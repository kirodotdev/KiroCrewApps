#!/usr/bin/env python3
"""Compile the authored catalog into the published, signed documents.

The chain is validate -> resolve -> bake -> stamp -> sign -> emit, and every
link exists to remove a human's ability to get it wrong:

*resolve* turns each curator-written branch or tag into an immutable commit,
because a signed index naming `main` signs nothing about the bytes anyone will
actually receive.

*bake* copies display fields out of each app's own ``app.json``. Curators cannot
author these (the authored schema forbids them), so the store's copy cannot
drift from the app or be inflated by whoever edits the catalog.

*stamp* records when the document was built and a revision id derived from its
content.

*sign* is the acceptance gate for Official trust, so it FAILS CLOSED: with no
key configured this exits non-zero and writes nothing. Publishing an unsigned
document would be worse than not publishing, because a client that accepts one
has no way to tell the catalog from an attacker's copy of it.

Nothing here reaches a CDN -- emitting the signed artifacts is where this stops
and distribution begins.

Usage:
    python tools/publish.py --out dist
    python tools/publish.py --out dist --dry-run   # skip resolve/fetch/sign
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = ROOT / "catalog"
SCHEMA_DIR = ROOT / "schema"
KEYS_DIR = ROOT / "keys"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate import Findings, check_schema, validate  # noqa: E402
from verify_dist import load_public_keys  # noqa: E402

SUMMARY_MAX = 200
TAGS_MAX = 16

# Author names that assert the catalog operator itself. A manifest may never
# carry one: it is a file we do not control, and no evidence inside it can
# support the claim (see bake_entry). Only the curator may state these, on the
# catalog entry. casefold()ed, because `KiroCrew` and `kirocrew` make the same
# claim to a reader.
RESERVED_AUTHORS = frozenset(
    {"kirocrew", "kiro crew", "kiro", "kirodotdev", "kiro.dev", "crew.kiro.dev"}
)
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{64}$")
HTTPS_RE = re.compile(r"^https://[^\s\x00]+$")

GIT_TIMEOUT = 120

# Star counts are display garnish, not publish substance: the fetch gets a short
# leash and any failure degrades to "unknown" rather than delaying or halting a
# release. Only canonical https://github.com/<owner>/<repo> URLs qualify --
# other git hosts have no GitHub star count to report.
STARS_TIMEOUT = 10
GITHUB_REPO_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)

#: Per-asset download budget for a `release` entry. Unlike a star count, the
#: asset digest is load-bearing (it is the install's trust anchor), so the
#: timeout is generous -- but still bounded, because build_registry() walks
#: entries serially and one stalled CDN must not outlive the CI job.
RELEASE_ASSET_TIMEOUT = 120
#: Hard cap on a release asset's size. A store app's built bundle is a few MB;
#: the cap exists so a hostile or misconfigured entry cannot make publish
#: stream gigabytes. Enforced on the BYTES ACTUALLY READ, never trusted from
#: Content-Length, which a server can omit or understate.
RELEASE_ASSET_MAX_BYTES = 100 * 1024 * 1024
#: Read granularity for the streaming digest. The asset is hashed as it
#: arrives and never held in memory whole.
_ASSET_CHUNK_BYTES = 1024 * 1024


def release_asset_url(repo_url: str, tag: str, asset: str) -> str:
    """The canonical GitHub download URL for one release asset.

    Derived, never authored: the curator states repo + tag + asset name, and
    this is the one place that turns those into a URL, so a published archive
    entry can never point anywhere except the stated repository's own releases.
    Raises for a non-GitHub repo URL -- other forges shape their release
    download URLs differently, and guessing would publish a dead link.

    Tag and asset are percent-encoded with NO safe characters: the schema
    already forbids whitespace and slashes, but encoding is what guarantees the
    two path segments cannot alter the URL's structure regardless of what a
    future schema revision admits.
    """
    match = GITHUB_REPO_RE.match(repo_url)
    if not match:
        raise PublishError(
            f"release entries require a github.com repository URL "
            f"(got {repo_url!r}); other forges are not supported yet"
        )
    owner, repo = match.group(1), match.group(2)
    quoted_tag = urllib.parse.quote(tag, safe="")
    quoted_asset = urllib.parse.quote(asset, safe="")
    return (
        f"https://github.com/{owner}/{repo}/releases/download/"
        f"{quoted_tag}/{quoted_asset}"
    )


def fetch_asset_sha256(url: str) -> str:
    """Download *url* and return its SHA-256, streaming with a hard size cap.

    This digest is what the catalog signs and what every client install
    verifies fail-closed, so unlike the star fetch this MUST raise on any
    failure -- publishing an archive entry whose digest could not be computed
    would be publishing an unpinned install. GitHub asset downloads redirect to
    a CDN host; the redirect is followed, and the size cap applies to the bytes
    actually received wherever they come from.
    """
    if not url.startswith("https://"):
        raise PublishError(f"release asset URL must be https: {url!r}")
    request = urllib.request.Request(
        url, headers={"User-Agent": "kirocrew-apps-publish"}
    )
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=RELEASE_ASSET_TIMEOUT) as response:
            while True:
                chunk = response.read(_ASSET_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > RELEASE_ASSET_MAX_BYTES:
                    raise PublishError(
                        f"release asset exceeds the "
                        f"{RELEASE_ASSET_MAX_BYTES // (1024 * 1024)} MB cap: {url}"
                    )
                digest.update(chunk)
    except PublishError:
        raise
    except Exception as exc:
        raise PublishError(f"failed to download release asset {url}: {exc}") from exc
    if total == 0:
        # A zero-byte asset is a broken upload, not a plausible app bundle.
        # Its digest is also a well-known constant, so signing it would pin
        # nothing anyone meant to ship.
        raise PublishError(f"release asset is empty: {url}")
    return digest.hexdigest()


# Hardening for git invocations against remotes we do not control. The schema
# already restricts `url` to https, but this is the layer that actually executes
# something, so it does not delegate its safety upward.
GIT_HARDENING = [
    # `ext::` hands a command line to the shell. Nothing else here matters if
    # this is reachable.
    "-c", "protocol.ext.allow=never",
    # No tier of the registry confers clone credentials, so a fetch that needs
    # them must fail rather than quietly succeed with the CI runner's identity.
    "-c", "credential.helper=",
    "-c", "core.askPass=",
    # Submodules are a second, attacker-controlled URL list. Never follow them.
    "-c", "submodule.recurse=false",
]

GIT_ENV = {
    **os.environ,
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_ALLOW_PROTOCOL": "https",
}


class PublishError(RuntimeError):
    """Anything that must stop the publish rather than degrade it."""


def run_git(args: list[str], cwd: Path | None = None) -> str:
    try:
        proc = subprocess.run(
            ["git", *GIT_HARDENING, *args],
            cwd=str(cwd) if cwd else None,
            env=GIT_ENV,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        # A timeout is attributable to ONE repository, so it must not be able to
        # end the run: raised bare it is not a `PublishError`, so it escapes the
        # per-image `except` in the ingest path, escapes `build_registry`, and
        # escapes `publish`'s own handler -- a slow or hostile repo would take
        # every other app's release down with a traceback. Converted here rather
        # than at each call site because `run_git` has seven of them (ls-remote,
        # init, remote, fetch, clone, rev-parse, cat-file) and patching only the
        # ingest ones would leave the rest able to do exactly that.
        #
        # Each caller's fatality is UNCHANGED, only its reporting: the ingest
        # path already degrades a `PublishError` to a warning and keeps going,
        # while `resolve_commit` and `fetch_manifest` already withhold the
        # catalog through `findings.error`. A missing git binary is deliberately
        # NOT folded in -- that is not attributable to any one entry, so it stays
        # loud.
        raise PublishError(
            f"git {' '.join(args[:2])} timed out after {GIT_TIMEOUT}s"
        ) from exc
    if proc.returncode != 0:
        raise PublishError(
            f"git {' '.join(args[:2])} failed ({proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    return proc.stdout


def require_https(url: str) -> None:
    """Re-check the scheme at the point of use.

    The schema enforces this too, but this function is what shells out, and a
    check that lives only in a validator one layer up is a check that a future
    caller can skip.
    """
    if not HTTPS_RE.match(url or ""):
        raise PublishError(f"refusing non-https git url: {url!r}")


@dataclass(frozen=True)
class ResolvedPin:
    """What a curator's ref resolved to.

    ``commit`` is the immutable pin the published document carries. ``tag`` is
    set only when the ref matched a tag: it is the human-readable release name
    the pin came from, published as ``sourceTag`` for display and provenance.
    The tag is NEVER a trust anchor -- a tag is a mutable pointer, so the commit
    remains the only coordinate anything downstream fetches or verifies.
    """

    commit: str
    tag: str | None = None


def resolve_commit(url: str, ref: str) -> str:
    """Resolve a branch/tag to the commit it points at.

    Kept alongside :func:`resolve_pin` because callers that only need the pin
    (and a body of existing tests) use the plain-string form.
    """
    return resolve_pin(url, ref).commit


def resolve_pin(url: str, ref: str) -> ResolvedPin:
    """Resolve a branch/tag to the commit it points at, remembering the tag.

    A ref that is already a commit passes through: re-resolving it would be a
    no-op at best and, for a server that does not advertise it, a spurious
    failure.
    """
    require_https(url)
    if COMMIT_RE.match(ref):
        return ResolvedPin(ref)

    # Ask for the peeled form alongside the ref itself. Without the explicit
    # `^{}` pattern, `ls-remote <url> v1` reports only `refs/tags/v1`, whose sha
    # is the TAG OBJECT -- not the commit. Pinning that would put a non-commit in
    # a field the schema documents as a commit id, and it is 40 hex characters so
    # nothing downstream could tell by shape.
    out = run_git(["ls-remote", url, ref, f"{ref}^{{}}"])
    # Prefer an exact tag/branch match; ls-remote can return several lines
    # (e.g. `v1` and `v1^{}` for an annotated tag).
    candidates: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            candidates[parts[1]] = parts[0]
    if not candidates:
        raise PublishError(f"ref {ref!r} not found at {url}")

    for name in (
        f"refs/tags/{ref}^{{}}",  # annotated tag -> the commit it wraps
        f"refs/tags/{ref}",
        f"refs/heads/{ref}",
        ref,
    ):
        if name not in candidates:
            continue
        # A fully qualified ref (`refs/tags/v1` written verbatim as the source
        # ref) matches its own RAW form here, so peel it the same way the short
        # forms above do: prefer the `^{}` candidate -- for an annotated tag the
        # raw ref names the TAG OBJECT, and pinning that halts publishing at the
        # object-type check. A ref with no peeled line (lightweight tag, branch)
        # already names the commit.
        sha = candidates.get(f"{name}^{{}}", candidates[name])
        # Tag-ness is decided by WHICH ref matched, not by what the ref looks
        # like -- and the published name comes from the matched ref too, so a
        # qualified spelling never leaks its `refs/tags/` namespace.
        is_tag = name.startswith("refs/tags/")
        return ResolvedPin(sha, _tag_name(name) if is_tag else None)

    # Collapse each annotated tag's pair of lines (`X` and `X^{}`) into one
    # entry pinned to the peeled commit, so a pattern matching a single
    # annotated tag is one candidate rather than a spurious ambiguity.
    peeled: dict[str, str] = {}
    for name, sha in candidates.items():
        if name.endswith("^{}"):
            continue
        peeled[name] = candidates.get(f"{name}^{{}}", sha)
    if not peeled:
        peeled = dict(candidates)
    if len(peeled) > 1:
        raise PublishError(
            f"ref {ref!r} is ambiguous at {url}: {sorted(peeled)}"
        )
    only_name, only_sha = next(iter(peeled.items()))
    if only_name.startswith("refs/tags/"):
        # Derive the tag from the REF THAT MATCHED, never from what the curator
        # typed: `ls-remote` accepts glob patterns, so a ref like `v1.*` can
        # reach this fallback by matching a single tag -- and publishing the
        # pattern itself would sign a release name that does not exist.
        return ResolvedPin(only_sha, _tag_name(only_name))
    return ResolvedPin(only_sha, None)


def _tag_name(ref_name: str) -> str:
    """The tag name inside a ``refs/tags/...`` ref, peel suffix stripped."""
    name = ref_name[len("refs/tags/"):]
    return name[:-3] if name.endswith("^{}") else name


#: Mirrors the published schema's `sourceTag` constraints (`^[^\u0000\s]+$`,
#: 1-255 chars). Kept in code so `bake_entry` can degrade ONE entry gracefully
#: instead of letting the final whole-document schema check refuse the catalog.
_SOURCE_TAG_RE = re.compile(r"^[^\u0000\s]{1,255}$")


def _publishable_source_tag(tag: str) -> bool:
    return bool(_SOURCE_TAG_RE.match(tag))


# Checkouts kept for the process, keyed by the exact bytes they contain. Every
# built-in app lives in one monorepo, so a per-call fetch would pull the same
# few hundred megabytes once per entry to read a few kilobytes of manifest.
# The TemporaryDirectory is stored WITH its path: two parallel structures let an
# eviction drop the only reachable path while leaving the handle referenced.
_REPO_CACHE: dict[tuple[str, str], tuple[Path, Any]] = {}


def reset_repo_cache() -> None:
    """Release every cached checkout.

    Total by construction: a ``cleanup()`` that refuses must not leave the rest
    of the cache populated, because a half-reset cache reintroduces exactly the
    cross-caller order dependence this function exists to remove.
    """
    while _REPO_CACHE:
        _, tmpdir = _REPO_CACHE.popitem()[1]
        with contextlib.suppress(Exception):
            tmpdir.cleanup()


def fetched_repo(url: str, commit: str) -> Path:
    """Fetch a repository at an exact commit. Cached per (url, commit).

    Fetches as a blobless partial clone (``--filter=blob:none``): only the commit
    and tree come down, and each file blob is fetched on demand by ``git show``
    and ``cat-file`` below. Reading a few manifests and icons out of a
    many-megabyte repository therefore costs a few hundred kilobytes instead of
    the whole working tree. A server without partial-clone support ignores the
    filter and serves a full shallow fetch, so the fallback behavior is
    unchanged.

    Either way the fetch verifies HEAD is the commit we resolved. That check is
    the point: resolve-then-fetch is two round trips, and without it a ref that
    moves in between would silently publish different bytes than the ones the
    commit id claims.
    """
    require_https(url)
    if hit := _REPO_CACHE.get((url, commit)):
        repo, _ = hit
        if repo.exists():
            return repo
        # Reaped underneath us. Evict rather than return a path whose absence
        # would surface downstream as "cannot read app.json" -- blaming the
        # manifest for an infrastructure loss.
        _, stale = _REPO_CACHE.pop((url, commit))
        with contextlib.suppress(Exception):
            stale.cleanup()

    # Held for the process rather than by a `with` block, because later entries
    # read from this same checkout. Released on eviction above, on any failure
    # below, or by reset_repo_cache().
    tmpdir = tempfile.TemporaryDirectory(prefix="kcapps-publish-")
    try:
        tmp = Path(tmpdir.name)
        repo = tmp / "fetched"
        try:
            # Fetching the commit directly is exact, but needs the server to
            # allow SHA1-in-want; fall back to a shallow clone below.
            run_git(["init", "--quiet", str(repo)])
            run_git(["remote", "add", "origin", url], cwd=repo)
            run_git(["fetch", "--depth", "1", "--filter=blob:none", "--quiet", "origin", commit], cwd=repo)
            head = run_git(["rev-parse", "FETCH_HEAD"], cwd=repo).strip()
        except PublishError:
            # A separate directory: `init` above already populated the first one,
            # and git refuses to clone into a non-empty destination.
            repo = tmp / "cloned"
            run_git(["clone", "--depth", "1", "--filter=blob:none", "--no-checkout", "--quiet", url, str(repo)])
            head = run_git(["rev-parse", "HEAD"], cwd=repo).strip()

        if head != commit:
            raise PublishError(
                f"{url}: expected commit {commit} but repository resolved to "
                f"{head}; the ref moved during publish"
            )

        # Belt and braces on the tag-peeling bug above: a tag object is also 40
        # hex characters, so only asking git what the object IS can rule it out.
        kind = run_git(["cat-file", "-t", head], cwd=repo).strip()
        if kind != "commit":
            raise PublishError(f"{url}: {commit} is a {kind}, not a commit")
    except BaseException:
        # A cleanup that raises here must not REPLACE the error that caused it:
        # "the ref moved during publish" is the diagnosis, an rmtree failure is
        # not. A leaked directory is worse-but-visible; a lost error is not.
        with contextlib.suppress(Exception):
            tmpdir.cleanup()
        raise

    _REPO_CACHE[(url, commit)] = (repo, tmpdir)
    return repo


def fetch_manifest(url: str, commit: str, subdir: str | None = None) -> dict[str, Any]:
    """Read ``app.json`` from a repository at an exact commit."""
    repo = fetched_repo(url, commit)
    rel = Path(subdir) / "app.json" if subdir else Path("app.json")
    try:
        raw = run_git(["show", f"{commit}:{rel.as_posix()}"], cwd=repo)
    except PublishError as exc:
        raise PublishError(f"{url}: cannot read {rel.as_posix()} at {commit}: {exc}")

    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PublishError(f"{url}: {rel.as_posix()} is not valid JSON: {exc}")
    if not isinstance(manifest, dict):
        raise PublishError(f"{url}: {rel.as_posix()} is not a JSON object")
    return manifest


def fetch_github_stars(url: str) -> int | None:
    """Read a GitHub repository's stargazer count, or ``None`` for "unknown".

    ``None`` covers every way the count can be unavailable -- a non-GitHub
    host, a missing or private repo, rate limiting, a timeout, or a malformed
    response. Callers must treat absence as "unknown", never as zero, and no
    failure here may raise: a star count is not worth failing a release over.

    ``GITHUB_TOKEN``, when present, is sent as a bearer token so CI runs get
    the authenticated rate limit instead of the anonymous one.
    """
    match = GITHUB_REPO_RE.match(url)
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)

    headers = {
        "Accept": "application/vnd.github+json",
        # api.github.com rejects requests without a User-Agent outright.
        "User-Agent": "kirocrew-apps-publish",
    }
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        f"https://api.github.com/repos/{owner}/{repo}", headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=STARS_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return None

    count = payload.get("stargazers_count") if isinstance(payload, dict) else None
    # `bool` is an `int` subclass; a hostile `true` must not publish as 1.
    # The upper bound mirrors the schema's `maximum` (JS safe-integer range):
    # a count above it is not a plausible count, and signing one would ship a
    # value JavaScript consumers cannot represent exactly.
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return None
    if count > 9_007_199_254_740_991:
        return None
    return count


#: Run-wide wall-clock budget for ALL star fetches in one publish. Each fetch
#: already has its own STARS_TIMEOUT, but build_registry() walks entries
#: serially, so per-fetch timeouts alone scale as 10s x entry count -- enough
#: stalled requests would outlive the CI job even though every individual
#: fetch "degraded gracefully". Stars are garnish: past this budget every
#: remaining entry publishes without the field rather than delaying a release.
STARS_TOTAL_BUDGET = 120.0


def budgeted_stars_fetcher() -> Callable[[str], int | None]:
    """A ``fetch_github_stars`` that stops fetching once the run budget is spent.

    The deadline starts at the first call (not at construction), so setup work
    between building the fetcher and reaching the first git entry does not eat
    the budget. After the deadline every call returns ``None`` immediately --
    the caller's absence-means-unknown contract already handles that.
    """
    deadline: list[float] = []

    def fetch(url: str) -> int | None:
        now = time.monotonic()
        if not deadline:
            deadline.append(now + STARS_TOTAL_BUDGET)
        if now >= deadline[0]:
            return None
        return fetch_github_stars(url)

    return fetch


def manifest_str(manifest: dict[str, Any], key: str) -> str:
    """Read a manifest field as a string, or "" for anything that is not one.

    Every display field comes from an ``app.json`` we do not control, so a
    hostile or merely sloppy value must DEGRADE that one field -- never raise.
    `(manifest.get(k) or "").strip()` looks total but is not: `None`/`0`/`""`
    are falsy and survive, while a truthy non-string (`5`, `[1]`, `{"a": 1}`)
    reaches `.strip()` and raises AttributeError, which halts the whole run and
    with it every OTHER app's release.
    """
    value = manifest.get(key)
    return value.strip() if isinstance(value, str) else ""


def derive_summary(description: Any, findings: Findings, app: str) -> str | None:
    """Reduce a manifest description to one list-safe line.

    `description` is detail-view body copy and routinely runs past 400
    characters, so it is not a summary. Taking the first sentence produces real
    list copy rather than a sentence severed mid-clause; only a first sentence
    that is itself over-long gets truncated, and that is reported.

    Takes `Any` deliberately: the value arrives from a manifest, so a non-string
    is input to handle, not a caller bug to raise on.
    """
    text = " ".join(description.split()) if isinstance(description, str) else ""
    if not text:
        return None

    match = re.match(r"^(.*?[.!?])(?:\s|$)", text, re.S)
    summary = match.group(1) if match else text

    if len(summary) > SUMMARY_MAX:
        summary = summary[: SUMMARY_MAX - 1].rstrip() + "\u2026"
        findings.warn(
            f"{app}: first sentence of description exceeds {SUMMARY_MAX} chars "
            f"and was truncated; consider a shorter opening sentence"
        )
    return summary


_AUTHOR_KINDS = frozenset({"person", "org"})
_AUTHOR_NAME_MAX = 80  # tracks author.name maxLength in BOTH schemas


def fold_author_name(name: str) -> str:
    """Fold a claimed author name to what a READER would take it to say.

    `casefold()` alone folds case and nothing else, so it compares bytes where
    the question is about appearance: `ＫｉｒｏＣｒｅｗ` (fullwidth) and
    `kiro\u200bcrew` (zero-width space) both read as ours and both miss a
    casefold-only membership test. NFKC maps the compatibility forms onto their
    ASCII equivalents, dropping format characters (category Cf, which is what
    ZWSP/ZWNJ/soft-hyphen are) removes the invisible separators NFKC keeps, and
    collapsing whitespace closes `kiro  crew`.
    """
    folded = unicodedata.normalize("NFKC", name)
    folded = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    return " ".join(folded.split()).casefold()


def normalize_author(value: Any) -> dict[str, Any] | None:
    """Widen a bare author string into the structured, schema-valid form.

    Manifests in the wild carry `"author": "kirocrew"`. The published shape is an
    object so it can carry a link and distinguish a person from an org, and the
    bare string stays valid input precisely so no manifest has to change first.

    Every field is dropped unless it is INDEPENDENTLY valid against the published
    schema, not merely a string. Type-safe is not schema-safe: `kind: "wizard"`,
    `url: "http://x"` and an 81-character name are all strings, so they survive a
    type filter, then fail validation on the ASSEMBLED document -- which returns
    errors for the whole run and halts every other app's release. An over-long
    name yields None rather than a truncation, because publishing a prefix would
    attribute the app to a different name than the one claimed.
    """
    if isinstance(value, str):
        name = value.strip()
        return {"name": name} if 0 < len(name) <= _AUTHOR_NAME_MAX else None
    if not isinstance(value, dict):
        return None

    name = value.get("name")
    if not isinstance(name, str) or not (0 < len(name.strip()) <= _AUTHOR_NAME_MAX):
        return None
    out: dict[str, Any] = {"name": name.strip()}

    url = value.get("url")
    if isinstance(url, str) and HTTPS_RE.match(url.strip()):
        out["url"] = url.strip()
    kind = value.get("kind")
    if isinstance(kind, str) and kind.strip().casefold() in _AUTHOR_KINDS:
        out["kind"] = kind.strip().casefold()
    return out


#: A published asset ref is a PATH, never a URL. Rejects a scheme (`https:`,
#: `data:`, `javascript:`), a protocol-relative `//host`, a `..` segment, a
#: backslash, and anything outside a conservative path charset. A leading `/` is
#: optional: a builtin's ref is an absolute client-local path, a fetched app's is
#: relative.
#:
#: MUST stay byte-identical to `entry.properties.iconRef.pattern` in
#: schema/official-registry.schema.json, and `ASSET_REF_MAX` to its `maxLength`.
#: `test_publish_and_schema_agree_on_the_asset_ref_rule` pins both. The divergence
#: is not cosmetic: a value this accepts and the schema rejects reaches
#: `check_schema` on the ASSEMBLED document, whose errors withhold the ENTIRE
#: catalog publish -- so one app's odd icon path would block every other app's
#: release, which is exactly what every other field here is careful to avoid.
ASSET_REF_PATTERN = (
    r"^(?![a-zA-Z][a-zA-Z0-9+.-]*:)(?!//)(?!.*(?:^|/)\.\.(?:/|$))/?[A-Za-z0-9_./-]+$"
)
ASSET_REF_MAX = 512
_ASSET_REF_RE = re.compile(ASSET_REF_PATTERN)


def bake_asset_ref(
    manifest: dict[str, Any],
    source_type: str,
    abs_key: str,
    rel_key: str,
    findings: Findings,
    app: str,
) -> str | None:
    """Read one display asset off a manifest, per what its source type may say.

    A built-in resolves from the client's OWN inventory, so its manifest names
    an absolute client-local path (`/app-assets/<app>/icon.svg`) that the client
    already ships the bytes for. Everything else is fetched from a repository we
    do not control, so only a REPO-RELATIVE path is read: the client rewrites it
    onto its own proxy, which is what keeps the extension allowlist and the
    trusted-host gate in the fetch path.

    The asymmetry is the point. Honouring an absolute value from a third-party
    manifest would let that publisher put any host it likes into a document WE
    sign, and the store would then load it — a tracking pixel at minimum, and a
    `javascript:`/`data:` ref at worst, depending on where a client interpolates
    it. So an absolute value from a non-builtin, or a relative value from a
    builtin, is DROPPED with a warning rather than published: half a display
    field costs a card its icon, while a signed bad ref costs more than that.
    """
    key = abs_key if source_type == "builtin" else rel_key
    other = rel_key if source_type == "builtin" else abs_key
    value = manifest_str(manifest, key)
    if not value:
        # The publisher named the asset under the key for the OTHER source type.
        # Silence here would ship a card with no icon and no diagnostic, which
        # reads as "the catalog dropped my icon" rather than "I used the wrong
        # key", so say which key this source type reads.
        if manifest_str(manifest, other):
            findings.warn(
                f"{app}: declares {other} but a {source_type or 'non-builtin'} source "
                f"reads {key}; publishing without it"
            )
        return None
    # One rule, applied to the value as it will be PUBLISHED. Checking a
    # transformed copy (an earlier revision matched `value.lstrip("/")`) let
    # `//app-assets/x.svg` through: it starts with `/` so it looked absolute, and
    # stripping the slashes made the remainder match -- but the published value
    # still began with `//`, which the schema refuses, and a schema error on the
    # assembled document withholds the whole catalog.
    if len(value) > ASSET_REF_MAX or not _ASSET_REF_RE.match(value):
        findings.warn(
            f"{app}: {key} {value!r} is not a publishable path; publishing "
            f"without it"
        )
        return None
    # Beyond being a valid path, it has to be the RIGHT KIND of path for this
    # source. A builtin's ref is resolved by the client against its own served
    # root, so a relative value would silently resolve somewhere else; a fetched
    # app may not name an absolute location at all, or a publisher could put a
    # host of their choosing into a document we sign.
    absolute = value.startswith("/")
    if source_type == "builtin" and not absolute:
        findings.warn(
            f"{app}: builtin {key} {value!r} is not an absolute client-local "
            f"path; publishing without it"
        )
        return None
    if source_type != "builtin" and absolute:
        findings.warn(
            f"{app}: {key} {value!r} is not a repo-relative path; publishing "
            f"without it. A fetched manifest may not name an absolute location."
        )
        return None
    return value


def bake_asset_ref_list(
    manifest: dict[str, Any],
    source_type: str,
    key: str,
    findings: Findings,
    app: str,
    limit: int,
) -> list[str]:
    """Read a LIST-valued display asset off a manifest, one rule per element.

    Same contract as `bake_asset_ref`, applied per element: a bad entry is
    dropped and the rest still publish, because one unusable screenshot should
    cost that screenshot and nothing else.

    A manifest field's TYPE is as untrusted as its content, and this is the shape
    where that bites. `screenshots` arrives from a file we do not control, so it
    may be a dict, a string, or a list holding dicts and numbers -- and a naive
    `for s in value: s.startswith(...)` raises on every one of those, taking the
    whole publish down over a field that is meant to be optional. So the
    container is type-checked before it is iterated and each element before it is
    read.

    A bare string is REFUSED rather than treated as a one-element list. Python
    would iterate it per character, and silently publishing an app's screenshot
    list as its filename's letters is worse than saying the field is wrong.
    """
    value = manifest.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        findings.warn(
            f"{app}: {key} is {type(value).__name__}, not a list; publishing "
            f"without it"
        )
        return []
    refs: list[str] = []
    # Bound the SCAN, not only what survives it. Capping accepted entries alone
    # left the loop unbounded on hostile input: `len(refs) >= limit` can only fire
    # once something has been ACCEPTED, so a list whose every element is invalid
    # never reaches the cap, runs to the end, and formats one warning per element
    # -- a million declared entries meant a million retained diagnostic strings.
    # The bound belongs on the read.
    #
    # Reading the first `limit` is not a lossy shortcut: they are the only ones
    # that could ever be published, so an entry past them was never going to be
    # shown whether it was valid or not.
    if len(value) > limit:
        findings.warn(
            f"{app}: {key} declares {len(value)} entries, over the {limit} the "
            f"catalog publishes; only the first {limit} are read"
        )
    for index, item in enumerate(value[:limit]):
        where = f"{key}[{index}]"
        if not isinstance(item, str) or not item.strip():
            findings.warn(
                f"{app}: {where} is not a non-empty string; publishing without it"
            )
            continue
        item = item.strip()
        if len(item) > ASSET_REF_MAX or not _ASSET_REF_RE.match(item):
            findings.warn(
                f"{app}: {where} {item!r} is not a publishable path; publishing "
                f"without it"
            )
            continue
        absolute = item.startswith("/")
        if source_type == "builtin" and not absolute:
            findings.warn(
                f"{app}: builtin {where} {item!r} is not an absolute client-local "
                f"path; publishing without it"
            )
            continue
        if source_type != "builtin" and absolute:
            findings.warn(
                f"{app}: {where} {item!r} is not a repo-relative path; publishing "
                f"without it. A fetched manifest may not name an absolute location."
            )
            continue
        if item in refs:
            # Deduplicated before ingest so the count against `limit` is a count
            # of distinct pictures, not of repeated lines in a manifest.
            continue
        refs.append(item)
    return refs


#: Icon bytes we are willing to host. RASTER ONLY, and that is a decision rather
#: than an omission.
#:
#: An SVG is a document, not pixels: it can carry `<script>`, event handlers,
#: external references and entity declarations, and we serve what we host from
#: our OWN origin with `image/svg+xml`, which makes a top-level navigation to it
#: an executing document on our domain. An earlier revision screened SVG text
#: with a regex; that screen was defeated three separate ways during review --
#: a namespace prefix (`<svg:script>`), a UTF-16 encoding (the ASCII pattern
#: never matches across interleaved NULs), and entity-encoded scheme names in an
#: href (`&#106;avascript:`). Each is individually fixable and the next one is
#: not, because a regex over untrusted XML is a losing position: the parser that
#: matters is the browser's, not ours.
#:
#: Re-admitting SVG therefore needs a real XML parse plus a serialisation we
#: control, not another pattern. Until then a third party ships raster, which is
#: what the publishing guide already asks for (512x512, opaque). First-party
#: built-ins keep their themeable inline SVGs -- those are never ingested here,
#: because the client already ships those bytes.
ICON_EXT_ALLOWED = frozenset({".png", ".webp", ".jpg", ".jpeg"})
#: Generous for a 512x512 icon and small enough that a repository cannot make
#: the catalog carry a payload. The blob-proxy path this replaces had NO cap.
ICON_MAX_BYTES = 256 * 1024
#: Below this an icon is visibly soft in the detail view; the store renders at
#: 28px in a list capsule, so this is about headroom, not the render size.
ICON_PX_MIN = 128
#: Where hosted icons land, relative to the catalog root. Content-addressed, so
#: the path is immutable and a client may cache it forever.
ICON_ASSET_DIR = "assets/icons"
#: Whether an entry that publishes no `iconRef` fails the run. Split by SOURCE
#: TYPE, because "whose defect is it" has two different answers.
#:
#: A missing icon is a real defect and not a cosmetic one: the store falls back
#: to a generated placeholder, and a placeholder is indistinguishable from an
#: icon this pipeline dropped, so an iconless listing reads as a store bug. A
#: store that gates on it makes the state unrepresentable instead -- Apple
#: refuses the UPLOAD of a build carrying no 1024px icon, before review is even
#: reachable -- which is where this is headed.
#:
#: For a THIRD PARTY it stays `False` while listed apps ship no icon of any kind:
#: erroring today would drop them from the catalog for a defect in THEIR
#: repository rather than in this pipeline, which is a worse outcome than a
#: placeholder. Flip it once every live entry publishes an `iconRef`;
#: `test_a_missing_icon_can_be_promoted_to_an_error` pins that to this one line.
ICON_MISSING_IS_ERROR = False
#: For a BUILT-IN there is nothing upstream to wait for, so the same leniency
#: buys nothing and costs the store a first-party card. The bytes ship in the
#: client we release, the manifest read here lives in our own repository, and the
#: only way to publish one iconless is for that manifest to omit `iconUrl` -- our
#: edit, our fix, before a document goes out. That is not hypothetical: `channels`,
#: `dev-fleet` and `workflows` each rendered a placeholder in the store for days
#: after their `icon.svg` shipped, because the ref pinned here still named a
#: manifest written before the icon was wired in, and a warning in a publish log
#: nobody reads was the only signal.
ICON_MISSING_IS_ERROR_BUILTIN = True


def run_git_bytes(args: list[str], cwd: Path | None = None) -> bytes:
    """``run_git`` for content that is not text.

    Image bytes decoded as UTF-8 are corrupt bytes, so reading a PNG through the
    text-mode helper would silently produce a different file than the repository
    holds -- and the digest we then publish would be a digest of the corruption.
    """
    try:
        proc = subprocess.run(
            ["git", *GIT_HARDENING, *args],
            cwd=str(cwd) if cwd else None,
            env=GIT_ENV,
            capture_output=True,
            timeout=GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        # Same reason as `run_git`: a bare `TimeoutExpired` is not a
        # `PublishError`, so it would escape the per-image handler that exists to
        # keep one slow repository from ending everyone's release.
        raise PublishError(
            f"git {' '.join(args[:2])} timed out after {GIT_TIMEOUT}s"
        ) from exc
    if proc.returncode != 0:
        raise PublishError(
            f"git {' '.join(args[:2])} failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()[:400]}"
        )
    return proc.stdout


def blob_size(url: str, commit: str, path: str) -> int:
    """Byte size of one file at a commit, WITHOUT reading its contents.

    `git cat-file -s` answers from the object header. Checking the cap before
    reading matters because the read buffers the whole object in memory: a
    repository could otherwise hand the publisher a multi-gigabyte file and kill
    the run before the size check it would have failed.
    """
    repo = fetched_repo(url, commit)
    out = run_git(["cat-file", "-s", f"{commit}:{path}"], cwd=repo).strip()
    try:
        return int(out)
    except ValueError as exc:
        raise PublishError(f"unexpected size for {path!r}: {out!r}") from exc


def fetch_blob(url: str, commit: str, path: str) -> bytes:
    """Read one file's bytes from a repository at an exact commit.

    Reuses the checkout ``fetch_manifest`` already made for this ``(url,
    commit)``, so hosting an icon costs no extra network round trip -- the file
    is sitting in a tree we have.
    """
    repo = fetched_repo(url, commit)
    return run_git_bytes(["show", f"{commit}:{path}"], cwd=repo)


def png_dimensions(data: bytes) -> tuple[int, int] | None:
    """Width and height from a PNG header, or None if it is not a PNG.

    Header-only, so it needs no image library: signature, then the IHDR chunk's
    two big-endian 32-bit fields. Anything else returns None and goes unchecked
    rather than blocking a format we cannot measure.
    """
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    return (
        int.from_bytes(data[16:20], "big"),
        int.from_bytes(data[20:24], "big"),
    )


class _FetchedImages:
    """Collects image bytes read out of a PUBLISHER'S repository, to publish.

    WHY THE CATALOG HOSTS THESE. Before this, a third-party image stayed in the
    publisher's repository and every client fetched it by cloning that repository
    through a proxy -- one shallow clone per uncached image, no byte cap, a cache
    keyed on a moving branch, and a store grid that broke when a repo was renamed
    or made private. Hosting the bytes removes the publisher's infrastructure
    from the render path entirely, which is the same move Apple makes: the icon
    is uploaded at submission and served from the store's own CDN, never from the
    developer's servers.

    HOW INTEGRITY WORKS WITHOUT SIGNING EACH FILE. The stored name is the
    sha256 of the bytes, and that name appears in the registry document, which IS
    signed. So a client that verifies the document signature and then checks the
    downloaded bytes against the digest in the path has end-to-end integrity for
    every image, with one signature over one document. Content addressing also
    makes the URL immutable (cache forever, no TTL question) and deduplicates two
    apps that ship the same file.

    A subclass supplies only the POLICY -- which extensions we are willing to
    host, the byte ceiling, the directory the bytes land in, and what dimensions
    render badly. This class owns the MECHANISM: read a blob at a pinned commit,
    screen it, and name it by the digest of its own bytes.

    That is the split `EditorialAssets` already documents from the other side. It
    stays a separate class because its SOURCE differs -- a file in THIS
    repository, resolved and contained against the repo root -- and not because
    its policy does. An icon and a hero image share the source, so they share
    this, and a second copy of the ingest body is how the two would drift.
    """

    #: What diagnostics call the thing. A publisher reads these warnings to find
    #: out why their card has no picture, so it has to name what they can fix.
    _NOUN = "image"
    #: Catalog-relative directory the bytes land in. Per-kind rather than one
    #: shared pool, so listing either kind is meaningful on its own.
    _DIR = ""
    _EXT_ALLOWED: frozenset[str] = frozenset()
    _MAX_BYTES = 0
    #: Aspect the store placement expects, or None for a kind with no fixed one.
    #: A mismatch is advice, never a refusal.
    _ASPECT: float | None = None
    _ASPECT_LABEL = ""

    def __init__(
        self,
        reader: Callable[[str, str, str], bytes],
        sizer: Callable[[str, str, str], int] | None = None,
    ) -> None:
        self._reader = reader
        # Defaults to reading then measuring, which is fine for an injected test
        # reader; the real pipeline passes `blob_size` so the cap is enforced
        # before anything is buffered.
        self._sizer = sizer
        self.files: dict[str, bytes] = {}

    def add(
        self,
        url: str,
        commit: str,
        rel_path: str,
        app: str,
        findings: Findings,
    ) -> str | None:
        """Ingest one image, returning its catalog-relative path.

        Every rejection is a WARNING, never an error: a bad image costs one card
        its picture, and halting would take every other app's release with it.
        """
        ext = Path(rel_path).suffix.lower()
        if ext not in self._EXT_ALLOWED:
            findings.warn(
                f"{app}: {self._NOUN} {rel_path!r} has type {ext or '(none)'!r}, which the "
                f"catalog does not host; publishing without it"
            )
            return None
        # Size BEFORE bytes. The read below buffers the whole object, so a cap
        # applied afterwards is a cap that never fires on the input it exists for.
        if self._sizer is not None:
            try:
                size = self._sizer(url, commit, rel_path)
            except PublishError as exc:
                findings.warn(f"{app}: cannot size {self._NOUN} {rel_path!r}: {exc}")
                return None
            if size > self._MAX_BYTES:
                findings.warn(
                    f"{app}: {self._NOUN} {rel_path!r} is {size} bytes, over the "
                    f"{self._MAX_BYTES}-byte limit; publishing without it"
                )
                return None
        try:
            data = self._reader(url, commit, rel_path)
        except PublishError as exc:
            findings.warn(f"{app}: cannot read {self._NOUN} {rel_path!r}: {exc}")
            return None
        if not data:
            findings.warn(
                f"{app}: {self._NOUN} {rel_path!r} is empty; publishing without it"
            )
            return None
        if len(data) > self._MAX_BYTES:
            findings.warn(
                f"{app}: {self._NOUN} {rel_path!r} is {len(data)} bytes, over the "
                f"{self._MAX_BYTES}-byte limit; publishing without it"
            )
            return None
        self._advise_dimensions(data, rel_path, app, findings)

        digest = hashlib.sha256(data).hexdigest()
        stored = f"{self._DIR}/{digest}{ext}"
        # Two apps shipping identical bytes converge on one file, and re-running
        # publish is idempotent for the same input.
        self.files[stored] = data
        return stored

    def _advise_dimensions(
        self, data: bytes, rel_path: str, app: str, findings: Findings
    ) -> None:
        """Warn about pixels that will render badly. Never a rejection.

        A shape that crops or looks soft is a curation nit, so it is reported and
        published; only the extension and byte checks above can withhold an
        image. Silent when the kind declares no `_ASPECT` (a screenshot has no
        fixed placement) and silent for a format `png_dimensions` cannot read --
        it parses PNG only, so a webp or jpg yields nothing to judge and
        "unmeasurable" must not be reported as a defect.
        """
        if self._ASPECT is None:
            return
        if dims := png_dimensions(data):
            width, height = dims
            if height and abs((width / height) - self._ASPECT) > ART_ASPECT_TOLERANCE:
                findings.warn(
                    f"{app}: {self._NOUN} {rel_path!r} is {width}x{height}; the store "
                    f"placement is {self._ASPECT_LABEL}, so it will letterbox or crop it"
                )


class IconAssets(_FetchedImages):
    """A 512px app tile, ingested from the publisher's repo at a pinned commit."""

    _NOUN = "icon"
    _DIR = ICON_ASSET_DIR
    _EXT_ALLOWED = ICON_EXT_ALLOWED
    _MAX_BYTES = ICON_MAX_BYTES

    def _advise_dimensions(
        self, data: bytes, rel_path: str, app: str, findings: Findings
    ) -> None:
        if dims := png_dimensions(data):
            width, height = dims
            if width != height:
                findings.warn(
                    f"{app}: icon {rel_path!r} is {width}x{height}, not square; "
                    f"the store renders it in a square box"
                )
            elif width < ICON_PX_MIN:
                findings.warn(
                    f"{app}: icon {rel_path!r} is {width}x{height}, below the "
                    f"{ICON_PX_MIN}px floor; it will look soft on the detail page"
                )


EDITORIAL_ASSET_DIR = "assets/editorial"
#: Editorial artwork is a wide hero image, not a 512px tile, so it gets its own
#: ceiling. Same raster whitelist as icons: SVG is a script host and a regex
#: screen over untrusted XML lost three separate ways.
ART_EXT_ALLOWED = frozenset({".png", ".webp", ".jpg", ".jpeg"})
ART_MAX_BYTES = 1024 * 1024
#: The placement this art fills. A mismatch is a WARNING, not a refusal: a
#: slightly-off crop is a curation nit, and refusing would take the whole
#: release with it.
ART_ASPECT = 1600 / 900
ART_ASPECT_TOLERANCE = 0.08

#: Where hosted app art lands. One directory per KIND rather than one shared
#: pool, so a listing of any kind is meaningful on its own, and separate from
#: `EDITORIAL_ASSET_DIR` because these belong to an APP (fetched from its
#: repository at a pinned commit) while editorial art belongs to a curated
#: SECTION of the store. Same content-addressed, immutable naming as both.
HERO_ASSET_DIR = "assets/heroes"
HERO_DETAIL_ASSET_DIR = "assets/hero-details"
SCREENSHOT_ASSET_DIR = "assets/screenshots"

#: The detail page's banner is far wider than the store card's, per the
#: publishing guide. Advice only, like every other aspect.
HERO_DETAIL_ASPECT = 25 / 6

#: How many screenshots one app may publish. A cap is not cosmetic: each one is
#: a blob read at publish time and a hosted file forever, so without it a single
#: manifest declaring hundreds would set the cost of everyone's release. Extras
#: are DROPPED with a diagnostic rather than failing the run, the same way every
#: other per-image rejection behaves.
SCREENSHOT_MAX_COUNT = 8


class HeroAssets(_FetchedImages):
    """An app's wide store hero, ingested from its repo at a pinned commit.

    Shares the ingest mechanism with `IconAssets` because the source is the same
    -- a blob in a repository we do not control -- and takes the WIDE-ART policy
    (`ART_*`) because a 16:9 banner is not a 512px tile: the icon ceiling would
    reject an ordinary hero, and the icon's squareness advice would fire on every
    correct one.

    Ingesting the bytes is what makes a hero render AT ALL for a fetched app.
    Published un-ingested, a `heroRef` stays repo-relative, and a relative ref is
    resolved by the client against the CATALOG root -- so it addressed a file
    that exists only in the app's repository and had never been uploaded here.
    Every third-party hero was a guaranteed 404/403 on a path that looked
    plausible, which reads as a broken store rather than a missing bake step.
    """

    _NOUN = "hero image"
    _DIR = HERO_ASSET_DIR
    _EXT_ALLOWED = ART_EXT_ALLOWED
    _MAX_BYTES = ART_MAX_BYTES
    _ASPECT = ART_ASPECT
    _ASPECT_LABEL = "16:9"


class HeroDetailAssets(_FetchedImages):
    """The detail page's banner. Same policy as the hero at a wider aspect."""

    _NOUN = "detail hero"
    _DIR = HERO_DETAIL_ASSET_DIR
    _EXT_ALLOWED = ART_EXT_ALLOWED
    _MAX_BYTES = ART_MAX_BYTES
    _ASPECT = HERO_DETAIL_ASPECT
    _ASPECT_LABEL = "25:6"


class ScreenshotAssets(_FetchedImages):
    """One of an app's store screenshots.

    No `_ASPECT`: a screenshot is whatever shape the app's own window is, and the
    store lays them out in a scroller rather than a fixed frame. Reporting a
    crop here would be advice about the app, not about the asset.
    """

    _NOUN = "screenshot"
    _DIR = SCREENSHOT_ASSET_DIR
    _EXT_ALLOWED = ART_EXT_ALLOWED
    _MAX_BYTES = ART_MAX_BYTES


class EditorialAssets:
    """Collects curator-authored artwork to publish alongside the documents.

    Separate from `IconAssets` because the SOURCE differs, not the mechanism: an
    app icon is a blob in the publisher's repository at a pinned commit, while
    editorial artwork is a file in THIS repository that a curator committed
    alongside the section that names it. The naming and integrity story is
    deliberately identical -- sha256 of the bytes as the filename, that name
    inside the signed document -- so `verify_dist` proves both with one pass and
    a client needs no second rule for artwork.

    Path containment is enforced here rather than trusted from the schema: the
    schema's pattern rejects the spellings it knows, and this rejects anything
    that resolves outside the repository root after symlinks.
    """

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self.files: dict[str, bytes] = {}

    def add(self, rel_path: str, where: str, findings: Findings) -> str | None:
        """Ingest one artwork file, returning its catalog-relative path.

        Every rejection is a WARNING: a bad image costs one section its picture,
        and halting would take every other section's release with it.
        """
        ext = Path(rel_path).suffix.lower()
        if ext not in ART_EXT_ALLOWED:
            findings.warn(
                f"{where}: artwork {rel_path!r} has type {ext or '(none)'!r}, which the "
                f"catalog does not host; publishing without it"
            )
            return None

        # Resolve THEN contain. A path that leaves the repository is refused even
        # if the schema's pattern happened to admit its spelling, and symlinks are
        # resolved first so a link inside the repo cannot point outside it.
        #
        # `RuntimeError` is in the tuple because `Path.resolve()` raises it -- NOT
        # an OSError -- on a symlink loop (`art/loop.png -> loop.png`, or a mutual
        # pair). Without it a single bad link aborts the whole publish, which
        # contradicts the warn-and-continue contract every other rejection here
        # keeps: one image loses its placement, never the release.
        try:
            resolved = (self._root / rel_path).resolve()
            resolved.relative_to(self._root)
        except (OSError, RuntimeError, ValueError):
            findings.warn(
                f"{where}: artwork {rel_path!r} resolves outside the repository; "
                f"publishing without it"
            )
            return None
        if not resolved.is_file():
            findings.warn(f"{where}: artwork {rel_path!r} is not a file in this repository")
            return None

        # Size before bytes: a cap applied after the read is a cap that never
        # fires on the input it exists for.
        try:
            size = resolved.stat().st_size
        except OSError as exc:
            findings.warn(f"{where}: cannot size artwork {rel_path!r}: {exc}")
            return None
        if size > ART_MAX_BYTES:
            findings.warn(
                f"{where}: artwork {rel_path!r} is {size} bytes, over the "
                f"{ART_MAX_BYTES}-byte limit; publishing without it"
            )
            return None
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            findings.warn(f"{where}: cannot read artwork {rel_path!r}: {exc}")
            return None
        if not data:
            findings.warn(f"{where}: artwork {rel_path!r} is empty; publishing without it")
            return None

        if dims := png_dimensions(data):
            width, height = dims
            if height and abs((width / height) - ART_ASPECT) > ART_ASPECT_TOLERANCE:
                findings.warn(
                    f"{where}: artwork {rel_path!r} is {width}x{height}; the placement is "
                    f"16:9, so the store will letterbox or crop it"
                )

        digest = hashlib.sha256(data).hexdigest()
        stored = f"{EDITORIAL_ASSET_DIR}/{digest}{ext}"
        # Two sections sharing one image converge on one file, and re-running
        # publish is idempotent for the same input.
        self.files[stored] = data
        return stored


def bake_entry(
    authored: dict[str, Any],
    manifest: dict[str, Any],
    commit: str,
    findings: Findings,
    assets: IconAssets | None = None,
    heroes: HeroAssets | None = None,
    hero_details: HeroDetailAssets | None = None,
    shots: ScreenshotAssets | None = None,
    stars_fetcher: Callable[[str], int | None] | None = None,
    *,
    tag: str | None = None,
    asset_url: str | None = None,
    asset_sha256: str | None = None,
) -> dict[str, Any]:
    """Produce a published entry: authored identity + generated display fields.

    The ingesters, when given, pull a fetched app's art into the catalog and the
    entry carries the hosted paths instead of the repo-relative ones. Omitted (as
    in a dry run, and in tests that only exercise field derivation) the entry
    keeps the repo-relative path, which is still a valid published ref -- but only
    `verify_dist` running on a REAL publish proves an un-ingested one never
    reaches the CDN.
    """
    name = authored["name"]
    if manifest.get("name") and manifest["name"] != name:
        # The catalog and the app disagree about what the app is called. Picking
        # one would make the store's identity depend on which file was read.
        raise PublishError(
            f"{name}: manifest declares name {manifest['name']!r}; "
            f"the catalog entry and the app must agree"
        )

    source = dict(authored["source"])
    if source.get("type") == "builtin":
        # A built-in resolves from the client's OWN inventory, so the published
        # entry carries no fetch coordinates at all: `manifestFrom` exists only
        # so publish can read display fields, and shipping it would hand clients
        # a clone target for code they already have. Same curator-only-then-
        # stripped pattern as `note`.
        source.pop("manifestFrom", None)
    elif source.get("type") == "release":
        # A release entry publishes as the ARCHIVE variant -- but the swap is
        # DEFERRED to the end of this function (see below): every ingester in
        # between (icon, hero, screenshots, stars) reads the REPOSITORY url
        # from `source["url"]`, and replacing it here would hand them the asset
        # download URL as a git remote, silently dropping the app's artwork
        # from the signed storefront. `asset_sha256` is validated up front
        # because there is no honest fallback: an archive entry without a
        # digest would tell clients to run whatever the URL serves tomorrow.
        if not asset_sha256 or not asset_url:
            raise PublishError(
                f"{name}: release entry reached bake without a resolved asset "
                f"digest -- refusing to publish an unpinned archive"
            )
    else:
        source["ref"] = commit
        if tag:
            # The release the pin came from, for display and provenance only.
            # The commit above stays the sole fetch/verify coordinate: a tag can
            # be force-moved after publish, so a client honouring it would trade
            # an immutable pin for a mutable pointer.
            #
            # Held to the published-schema constraints HERE, not just at the
            # final document check: that check refuses the whole catalog, so one
            # repository's freakish tag name (overlong, embedded whitespace)
            # would withhold every app. The pin is unaffected -- the entry just
            # publishes without a release name, and the run says why.
            if _publishable_source_tag(tag):
                source["sourceTag"] = tag
            else:
                findings.warn(
                    f"{name}: resolved tag {tag[:80]!r} is not publishable as "
                    f"sourceTag (must be 1-255 chars with no whitespace or NUL); "
                    f"publishing the commit pin without a release name"
                )

    entry: dict[str, Any] = {"name": name, "source": source}

    # Carried through verbatim, not derived: membership is ours to assign, and
    # reading it from the manifest would let an author place their own app.
    if categories := authored.get("categories"):
        entry["categories"] = list(categories)

    if display := manifest_str(manifest, "displayName"):
        entry["displayName"] = display[:60]
    if summary := derive_summary(manifest.get("description"), findings, name):
        entry["summary"] = summary
    # Attribution is the one display field the curator may state, because it is
    # the one that is an ASSERTION rather than a description. This document is
    # signed by us, so what it says about who made an app has to be what we
    # state -- not what the app's own file claims about itself.
    if curated := normalize_author(authored.get("author")):
        entry["author"] = curated
    elif authored.get("author") is not None:
        # Stated but unusable. Warn rather than silently falling through to the
        # manifest: a curator who wrote an author meant to override the file, and
        # degrading back to it would hand attribution to the untrusted side.
        findings.warn(
            f"{name}: catalog entry states an author that is not publishable "
            f"({authored['author']!r}); publishing it with no author"
        )
    elif author := normalize_author(manifest.get("author")):
        # Falling back to the publisher's self-claim, which is fine for an
        # ordinary name. A claim to OUR name is not a description but a trust
        # assertion, and no evidence inside a file we do not control can support
        # it -- not the source url (which normalizes: `.../kirodotdev/../x` passes
        # a prefix test and fetches something else), not the `type` field, not the
        # name itself (`ＫｉｒｏＣｒｅｗ` and `kiro\u200bcrew` read as ours and
        # fold to neither). So the file may never assert it, at all.
        if fold_author_name(author["name"]) in RESERVED_AUTHORS:
            # DROP the claim, do not fail the publish. Refusing the whole run
            # would let any publisher halt every release -- including other
            # apps' -- by writing our name in a file we do not control.
            findings.warn(
                f"{name}: manifest claims the reserved author {author['name']!r}; "
                f"a manifest cannot assert it, so this publishes with no author. "
                f"Set `author` on the catalog entry to state the attribution."
            )
        else:
            entry["author"] = author
    elif manifest.get("author") is not None:
        findings.warn(
            f"{name}: manifest author {manifest['author']!r} is not publishable; "
            f"publishing it with no author"
        )

    tags = [t.strip() for t in manifest.get("tags") or [] if isinstance(t, str) and t.strip()]
    if tags:
        entry["tags"] = tags[:TAGS_MAX]

    aliases = [
        a.strip()
        for a in manifest.get("searchAliases") or []
        if isinstance(a, str) and a.strip()
    ]
    if aliases:
        entry["searchAliases"] = aliases[:TAGS_MAX]

    if version := manifest_str(manifest, "version"):
        entry["version"] = version[:64]

    # Star counts are GENERATED, never authored, and only a source with a
    # repository has stars to count -- git and release entries both name one
    # (a release entry's `url` IS its GitHub repo); a builtin ships in the
    # client and never touches the network here. A missing count publishes NO
    # field: absence means "unknown", and writing 0 (or a stale prior value)
    # would state a popularity fact this run has no evidence for.
    if source.get("type") in ("git", "release") and stars_fetcher is not None:
        stars = stars_fetcher(source["url"])
        if stars is not None:
            entry["stargazersCount"] = stars
        else:
            findings.warn(
                f"{name}: no star count available for {source['url']} "
                f"(non-GitHub host, missing repo, rate limit, or timeout); "
                f"publishing without stargazersCount"
            )

    source_type = str(source.get("type") or "")
    # `iconPath` is the key a fetched app declares; `iconUrl` is the absolute
    # client-local path a builtin declares. Reading the wrong one per source type
    # is why third-party entries used to publish no icon at all.
    #
    # A builtin's ref is published as-is: the client already ships those bytes,
    # so hosting a second copy would add download weight and a second source of
    # truth. Every other source's icon is INGESTED -- the repo-relative path is
    # replaced by a content-addressed path under our own root, so the render path
    # no longer depends on the publisher's repository being reachable.
    for key_abs, key_rel, field in (
        ("iconUrl", "iconPath", "iconRef"),
        ("iconUrlDark", "iconPathDark", "iconRefDark"),
    ):
        ref = bake_asset_ref(manifest, source_type, key_abs, key_rel, findings, name)
        if not ref:
            continue
        if source_type != "builtin" and assets is not None:
            ref = assets.add(source["url"], commit, ref, name, findings)
            if not ref:
                continue
        entry[field] = ref
    # State the OUTCOME once per app, here, where it is finally known. Every
    # rejection above reports its own cause, but nothing reported the case where
    # a manifest names no icon at all: `bake_asset_ref` is deliberately silent
    # when NEITHER key is present, so such an app published a placeholder card
    # with no diagnostic anywhere. That is how a built-in came to ship iconless
    # while an `icon.svg` sat in the client's own asset directory, unread because
    # its manifest never named it.
    #
    # Keyed on the ABSENCE of `iconRef` rather than on what the manifest said, so
    # promoting the switch means "every live entry has an icon" -- an icon that
    # was declared and then dropped has to fail too, or the gate would only cover
    # the undeclared half. No dark-variant equivalent: that one is genuinely
    # optional, since the client falls back to the light icon.
    #
    # An EMPTY manifest says nothing either way and is not diagnosed: `--dry-run`
    # substitutes one on purpose, and "was never fetched" is a different claim
    # from "declares no icon". Every other field skips silently for that reason;
    # this one would otherwise print a finding per app on every dry run, which is
    # how a reader learns to skim past the whole block.
    if manifest and "iconRef" not in entry:
        fatal = (
            ICON_MISSING_IS_ERROR_BUILTIN
            if source_type == "builtin"
            else ICON_MISSING_IS_ERROR
        )
        report = findings.error if fatal else findings.warn
        if manifest_str(manifest, "iconUrl") or manifest_str(manifest, "iconPath"):
            # The specific cause is already reported above; do not repeat it, and
            # do not tell a publisher to declare a key they did declare.
            report(f"{name}: no icon published; the store renders a placeholder")
        elif source_type == "builtin":
            report(
                f"{name}: no icon declared; the store renders a placeholder. "
                f"Declare a top-level 'iconUrl' naming a path the client serves."
            )
        else:
            report(
                f"{name}: no icon declared; the store renders a placeholder. "
                f"Declare a top-level 'iconPath' naming a raster file in the "
                f"repository ({', '.join(sorted(ICON_EXT_ALLOWED))})."
            )
    # Every wide-art field goes through the SAME two stages as the icon above,
    # which `heroRef` did not: it was `entry["heroRef"] =
    # manifest_str(manifest, "heroImage")`, a raw read from an untrusted manifest
    # straight into a document we SIGN. `heroRef` also carried no `pattern` in the
    # published schema, so nothing downstream re-imposed the rule either, and the
    # field was relying on each client to re-validate what the publisher had
    # already signed. `heroDetailRef` and `screenshotRefs` were not published at
    # all, so an app's detail page had a banner and a gallery in its manifest that
    # the store could never learn about.
    #
    # Unlike the icon's `iconUrl`/`iconPath` pair, these use ONE manifest key for
    # both source types: a builtin declares an absolute client-local path and a
    # fetched app declares it repo-relative, under that same name. So the same key
    # is passed for both roles here. That makes `bake_asset_ref`'s "you used the
    # other source type's key" warning unreachable for them by construction -- it
    # fires only when this key is empty and the other is not, and they are the
    # same key -- while the checks they were missing still apply: the path
    # pattern, and absolute-only-for-a-builtin.
    for manifest_key, field, ingester in (
        ("heroImage", "heroRef", heroes),
        ("heroImageDetail", "heroDetailRef", hero_details),
    ):
        ref = bake_asset_ref(
            manifest, source_type, manifest_key, manifest_key, findings, name
        )
        if ref and source_type != "builtin" and ingester is not None:
            # Dropped rather than left repo-relative when ingest refuses the
            # bytes. Keeping the authored path would publish a ref that resolves
            # against the catalog root onto a file only the app's repository has
            # -- a guaranteed 404 that looks like a store bug, where no art at
            # all is merely a card without a picture.
            ref = ingester.add(source["url"], commit, ref, name, findings)
        if ref:
            entry[field] = ref

    declared_shots = bake_asset_ref_list(
        manifest, source_type, "screenshots", findings, name, SCREENSHOT_MAX_COUNT
    )
    if declared_shots:
        if source_type != "builtin" and shots is not None:
            hosted = [
                stored
                for shot in declared_shots
                if (stored := shots.add(source["url"], commit, shot, name, findings))
            ]
        else:
            hosted = declared_shots
        # Only when at least one survived: an empty array and an absent field read
        # the same to a client, and the absent one is honest about there being no
        # gallery rather than implying an empty one.
        if hosted:
            entry["screenshotRefs"] = hosted

    if authored["source"].get("type") == "release":
        # The deferred swap (see the release branch above): every ingester has
        # now read the repository URL it needed, so the published source can
        # become the archive coordinates -- the derived asset URL plus the
        # digest THIS run computed. The digest is the trust anchor: a GitHub
        # release asset can be deleted and re-uploaded with the same name, so
        # the URL alone pins nothing.
        archive: dict[str, Any] = {
            "type": "archive", "url": asset_url, "sha256": asset_sha256,
        }
        if tag and _publishable_source_tag(tag):
            archive["sourceTag"] = tag
        entry["source"] = archive

    return entry


def canonical_bytes(doc: dict[str, Any]) -> bytes:
    """The exact bytes that get written, hashed, and signed.

    One function so those three can never disagree: a signature over
    differently-serialized bytes than the file on disk verifies nothing.
    """
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def content_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def build_registry(
    authored: dict[str, Any],
    resolver: Callable[[str, str], "str | ResolvedPin"],
    fetcher: Callable[..., dict[str, Any]],
    now: datetime,
    findings: Findings,
    assets: IconAssets | None = None,
    heroes: HeroAssets | None = None,
    hero_details: HeroDetailAssets | None = None,
    shots: ScreenshotAssets | None = None,
    stars_fetcher: Callable[[str], int | None] | None = None,
    asset_digester: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    apps: list[dict[str, Any]] = []
    for authored_entry in authored.get("apps") or []:
        source = authored_entry["source"]
        # A built-in has no fetch coordinates of its own -- it resolves from the
        # client's inventory -- so the manifest is read from the repository the
        # curator names in `manifestFrom`, which never reaches the published doc.
        origin = source["manifestFrom"] if source.get("type") == "builtin" else source
        # A release entry's manifest and art come from the git repository AT THE
        # RELEASE TAG -- the same source tree the release was cut from -- so the
        # display fields cannot drift from the bytes the asset carries. Only the
        # install coordinates differ: the published source is the asset URL +
        # digest, not a clone target.
        is_release = source.get("type") == "release"
        ref = source["tag"] if is_release else origin["ref"]
        resolved = resolver(origin["url"], ref)
        # A plain-string resolver (the dry-run lambda, tests, and any older
        # caller) still works: a bare commit is a pin with no tag provenance.
        pin = resolved if isinstance(resolved, ResolvedPin) else ResolvedPin(resolved)
        manifest = fetcher(origin["url"], pin.commit, origin.get("subdir"))
        asset_url = asset_sha256 = None
        release_tag: str | None = None
        if is_release:
            # The asset URL must name the tag the resolver actually SELECTED:
            # an authored pattern like `v1.*` resolves to a concrete tag, and
            # deriving the URL from the authored spelling would percent-encode
            # the wildcard and request a nonexistent asset path. A plain-string
            # resolver carries no tag provenance, so the authored tag (already
            # an exact name in that offline path) stands in.
            release_tag = pin.tag if isinstance(resolved, ResolvedPin) else source["tag"]
            if not release_tag:
                raise PublishError(
                    f"release source for {origin['url']}: tag {source['tag']!r} "
                    "did not resolve to a concrete tag"
                )
            asset_url = release_asset_url(source["url"], release_tag, source["asset"])
            asset_sha256 = (asset_digester or fetch_asset_sha256)(asset_url)
        apps.append(
            bake_entry(
                authored_entry, manifest, pin.commit, findings,
                assets, heroes, hero_details, shots, stars_fetcher,
                # The RESOLVED tag is the release identity: it is the exact
                # name the asset URL was derived from, so the published
                # sourceTag can never disagree with the bytes the URL serves.
                tag=release_tag if is_release else pin.tag,
                asset_url=asset_url,
                asset_sha256=asset_sha256,
            )
        )

    stamped = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    content = {
        "apps": apps,
        "removed": authored.get("removed") or [],
        "reinstated": authored.get("reinstated") or [],
    }
    doc: dict[str, Any] = {
        "schemaVersion": 1,
        "generatedAt": stamped,
        "revision": f"{stamped}-{content_digest(content)[:7]}",
        "apps": apps,
    }
    # Omit empty history rather than shipping empty arrays: absence and "nothing
    # removed" read the same to a client, and the smaller document is honest.
    if content["removed"]:
        doc["removed"] = content["removed"]
    if content["reinstated"]:
        doc["reinstated"] = content["reinstated"]
    return doc


def bake_editorial_artwork(
    doc: dict[str, Any],
    assets: EditorialAssets | None,
    findings: Findings,
) -> dict[str, Any]:
    """Replace each section's authored artwork paths with hosted ones.

    Mutates a COPY: the authored file on disk keeps the curator's own paths, so a
    republish is deterministic from the same inputs rather than from whatever a
    previous run rewrote.

    A section whose artwork cannot be ingested keeps the section and loses the
    picture. Dropping the section instead would silently remove a curated
    placement because an image was a few bytes too large.
    """
    sections = doc.get("sections")
    if not isinstance(sections, list) or assets is None:
        return doc

    def bake_item(item: Any, where: str) -> Any:
        if not isinstance(item, dict) or "artwork" not in item:
            return item
        art = item.get("artwork")
        if not isinstance(art, dict):
            return item

        out = dict(art)
        for key in ("ref", "refDark"):
            rel = art.get(key)
            if not isinstance(rel, str) or not rel:
                continue
            hosted = assets.add(rel, f"{where}.{key}", findings)
            if hosted:
                out[key] = hosted
            else:
                out.pop(key, None)

        item_out = dict(item)
        # `ref` is required by the schema, so artwork that lost its light variant
        # is no longer valid artwork -- drop the whole block rather than emit a
        # dark-only object the published-schema check would then reject.
        if "ref" in out:
            item_out["artwork"] = out
        else:
            item_out.pop("artwork", None)
        return item_out

    baked: list[Any] = []
    for idx, section in enumerate(sections):
        # Artwork hangs off items, not the section: a section carries only its
        # `form` and the list. A section that is not a dict, or whose items are
        # not a list, rides through untouched for the schema check to reject.
        if not isinstance(section, dict) or not isinstance(section.get("items"), list):
            baked.append(section)
            continue
        section_out = dict(section)
        section_out["items"] = [
            bake_item(item, f"sections[{idx}].items[{jdx}]")
            for jdx, item in enumerate(section["items"])
        ]
        baked.append(section_out)

    return {**doc, "sections": baked}


#: Fields the publish step stamps, which an authored document therefore may not
#: supply. Stripped when the authored input is read rather than fought at the
#: spread: the two builders below finish with `**doc`, so a `generatedAt` that
#: survived into `doc` would override the stamped one and ride into a SIGNED
#: document -- and the digest deliberately excludes these fields, which is the
#: evidence they were always meant to be stamped rather than authored. The
#: registry builder is immune by construction: it enumerates its keys instead of
#: spreading authored input, which is why this only ever applied to these two.
#:
#: One schema validates both the authored and the published form of a document,
#: so the schema cannot forbid them -- it has to admit them for the published
#: side. That makes this the only place the authored side can be held.
GENERATED_FIELDS = ("generatedAt", "revision")


def build_editorial(
    authored: dict[str, Any],
    now: datetime,
    assets: EditorialAssets | None = None,
    findings: Findings | None = None,
) -> dict[str, Any]:
    stamped = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        k: v
        for k, v in authored.items()
        if k != "schemaVersion" and k not in GENERATED_FIELDS
    }
    if assets is not None and findings is not None:
        doc = bake_editorial_artwork(doc, assets, findings)
    return {
        "schemaVersion": 1,
        "generatedAt": stamped,
        "revision": f"{stamped}-{content_digest(doc)[:7]}",
        **doc,
    }


def build_category_order(authored: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Stamp the rail order for publication.

    Nothing is resolved, baked or fetched: the document is a list of ids the
    curator wrote, and its whole contract is the sequence they wrote them in. So
    this is the stamping half of `build_editorial` with no compile step -- which
    is also why it takes no `Findings`, having no field it could degrade.
    """
    stamped = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        k: v
        for k, v in authored.items()
        if k != "schemaVersion" and k not in GENERATED_FIELDS
    }
    return {
        "schemaVersion": 1,
        "generatedAt": stamped,
        "revision": f"{stamped}-{content_digest(doc)[:7]}",
        **doc,
    }


KMS_SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
KMS_KEY_SPEC = "RSA_3072"


def kms_signer(
    key_id: str, client: Any | None = None
) -> Callable[[bytes], dict[str, Any]]:
    """Resolve a KMS signing key, then return a callable that signs payloads.

    Detached signatures, because every document sets ``additionalProperties:
    false`` with no signature slot -- so the bytes verified are exactly the bytes
    parsed.

    The private half never leaves KMS. This asks for a signature over a digest we
    computed; it cannot obtain key material, so a compromised runner can borrow
    signing for the life of its session but cannot sign anything afterwards.

    The key is resolved and reconciled against the trust root in ``keys/`` BEFORE
    any document is signed, and the whole publish fails if that fails. A
    mistyped key id would otherwise mint signatures no published key can verify,
    and the damage would surface as an unverifiable catalog rather than as the
    configuration error it actually is.

    Returned as a closure so ``GetPublicKey`` runs once per publish rather than
    once per document -- two documents must not be able to disagree about which
    key signed them.
    """
    if client is None:  # pragma: no cover - exercised with an injected client
        try:
            import boto3
        except ImportError as exc:
            raise PublishError(
                "signing requires the `boto3` package "
                "(pip install -r tools/requirements.txt)"
            ) from exc
        client = boto3.client("kms")

    try:
        described = client.get_public_key(KeyId=key_id)
    except Exception as exc:  # noqa: BLE001 - boto3 raises service-specific types
        raise PublishError(f"could not read public key for {key_id!r}: {exc}") from exc

    spec, usage = described.get("KeySpec"), described.get("KeyUsage")
    if spec != KMS_KEY_SPEC or usage != "SIGN_VERIFY":
        raise PublishError(
            f"signing key {key_id!r} is {spec}/{usage}, "
            f"expected {KMS_KEY_SPEC}/SIGN_VERIFY"
        )

    der = described["PublicKey"]
    key_ref = hashlib.sha256(der).hexdigest()[:16]

    published = load_public_keys(KEYS_DIR)
    if key_ref not in published:
        raise PublishError(
            f"signing key {key_id!r} resolves to keyId {key_ref!r}, which is not "
            f"published in keys/ -- no reader could verify what it signs"
        )
    if not hmac.compare_digest(published[key_ref], der):
        raise PublishError(
            f"keys/ publishes {key_ref!r} but its material differs from the live "
            f"public key of {key_id!r}"
        )

    def sign(payload: bytes) -> dict[str, Any]:
        # DIGEST rather than RAW: KMS caps a RAW message at 4096 bytes, and the
        # registry outgrows that as apps are added. Hashing here keeps the
        # request a fixed size no matter how large the catalog gets, and the
        # digest is published in the sidecar either way.
        try:
            signed = client.sign(
                KeyId=key_id,
                Message=hashlib.sha256(payload).digest(),
                MessageType="DIGEST",
                SigningAlgorithm=KMS_SIGNING_ALGORITHM,
            )
        except Exception as exc:  # noqa: BLE001 - boto3 raises service-specific types
            raise PublishError(f"signing failed for {key_id!r}: {exc}") from exc
        return {
            "algorithm": KMS_SIGNING_ALGORITHM,
            "keyId": key_ref,
            "payloadSha256": hashlib.sha256(payload).hexdigest(),
            "signature": base64.b64encode(signed["Signature"]).decode("ascii"),
        }

    return sign


def publish(
    out_dir: Path,
    dry_run: bool,
    key_id: str | None,
    kms_client: Any | None = None,
) -> Findings:
    findings = Findings()

    registry_path = CATALOG_DIR / "official-registry.json"
    editorial_path = CATALOG_DIR / "editorial.json"
    order_path = CATALOG_DIR / "category-order.json"

    # Never publish something the gate would reject.
    pre = validate(registry_path, editorial_path, order_path)
    findings.errors.extend(pre.errors)
    findings.warnings.extend(pre.warnings)
    if pre.errors:
        return findings

    authored_registry = json.loads(registry_path.read_text(encoding="utf-8"))
    authored_editorial = json.loads(editorial_path.read_text(encoding="utf-8"))
    authored_order = json.loads(order_path.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)

    resolver: Callable[[str, str], "str | ResolvedPin"]
    fetcher: Callable[..., dict[str, Any]]
    stars_fetcher: Callable[[str], int | None] | None
    assets: IconAssets | None
    heroes: HeroAssets | None
    hero_details: HeroDetailAssets | None
    shots: ScreenshotAssets | None
    art: EditorialAssets | None
    if dry_run:
        # Enough to exercise stamping and schema conformance offline. Publishing
        # for real must never take this path, hence the separate flag.
        resolver = lambda url, ref: ref if COMMIT_RE.match(ref) else "0" * 40  # noqa: E731
        # Same offline stance as the resolver: a dry run must not touch the
        # network, so a release asset gets a placeholder digest.
        asset_digester = lambda url: "0" * 64  # noqa: E731
        fetcher = lambda url, commit, subdir=None: {}  # noqa: E731
        stars_fetcher = None
        assets = None
        heroes = None
        hero_details = None
        shots = None
        art = None
    else:
        resolver, fetcher = resolve_pin, fetch_manifest
        asset_digester = fetch_asset_sha256
        stars_fetcher = budgeted_stars_fetcher()
        assets = IconAssets(fetch_blob, blob_size)
        heroes = HeroAssets(fetch_blob, blob_size)
        hero_details = HeroDetailAssets(fetch_blob, blob_size)
        shots = ScreenshotAssets(fetch_blob, blob_size)
        art = EditorialAssets(ROOT)

    try:
        registry_doc = build_registry(
            authored_registry, resolver, fetcher, now, findings,
            assets, heroes, hero_details, shots, stars_fetcher,
            asset_digester=asset_digester,
        )
    except PublishError as exc:
        findings.error(str(exc))
        return findings

    editorial_doc = build_editorial(authored_editorial, now, art, findings)
    order_doc = build_category_order(authored_order, now)

    # The output is held to the PUBLISHED contract, which is stricter than the
    # authored one. This is what catches a resolver that returned a branch name
    # or a bake step that emitted an over-long field.
    check_schema(
        registry_doc, SCHEMA_DIR / "official-registry.schema.json", "published registry", findings
    )
    check_schema(
        editorial_doc, SCHEMA_DIR / "editorial.schema.json", "published editorial", findings
    )
    check_schema(
        order_doc,
        SCHEMA_DIR / "category-order.schema.json",
        "published category-order",
        findings,
    )
    if findings.errors:
        return findings

    artifacts = {
        "official-registry.json": canonical_bytes(registry_doc),
        "editorial.json": canonical_bytes(editorial_doc),
        "category-order.json": canonical_bytes(order_doc),
    }

    if dry_run:
        findings.warn("dry run: refs not resolved, fields not baked, nothing signed")
    else:
        if not key_id:
            # Fail closed. A signature is the acceptance gate for Official
            # trust, so an unsigned document is not a lesser product -- it is a
            # document a client cannot distinguish from an attacker's.
            findings.error(
                "no signing key configured: set KIROCREW_REGISTRY_KMS_KEY_ID to "
                "the KMS key id, ARN or alias. Refusing to emit an unsigned "
                "catalog."
            )
            return findings
        try:
            sign = kms_signer(key_id, kms_client)
            for filename, payload in list(artifacts.items()):
                artifacts[f"{filename}.sig"] = (
                    json.dumps(sign(payload), indent=2) + "\n"
                ).encode("utf-8")
        except PublishError as exc:
            findings.error(str(exc))
            return findings

    # Every hosted image is added AFTER signing on
    # purpose: they get no sidecar of their own. Their integrity rides on the
    # digest in the filename, which appears in a document that IS signed -- so
    # one signature covers every image, and a client checks a download by hashing
    # it against its own path.
    if assets is not None:
        artifacts.update(assets.files)
    for ingested in (heroes, hero_details, shots):
        if ingested is not None:
            artifacts.update(ingested.files)
    if art is not None:
        artifacts.update(art.files)

    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, payload in artifacts.items():
        path = out_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    print(f"revision {registry_doc['revision']}")
    for filename in sorted(artifacts):
        print(f"  {out_dir / filename} ({len(artifacts[filename])} bytes)")
    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="dist", help="output directory")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="skip ref resolution, manifest fetching and signing",
    )
    args = parser.parse_args(argv[1:])

    findings = publish(
        Path(args.out),
        args.dry_run,
        os.environ.get("KIROCREW_REGISTRY_KMS_KEY_ID"),
    )

    for warning in findings.warnings:
        print(f"warning: {warning}")
    for error in findings.errors:
        print(f"error: {error}")

    if findings.errors:
        print(f"PUBLISH FAILED: {len(findings.errors)} error(s)")
        return 1
    print("published")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
