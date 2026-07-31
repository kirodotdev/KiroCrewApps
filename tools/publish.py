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
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = ROOT / "catalog"
SCHEMA_DIR = ROOT / "schema"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate import Findings, check_schema, validate  # noqa: E402

SUMMARY_MAX = 200
TAGS_MAX = 16
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{64}$")
HTTPS_RE = re.compile(r"^https://[^\s\x00]+$")

GIT_TIMEOUT = 120

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
    proc = subprocess.run(
        ["git", *GIT_HARDENING, *args],
        cwd=str(cwd) if cwd else None,
        env=GIT_ENV,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
    )
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


def resolve_commit(url: str, ref: str) -> str:
    """Resolve a branch/tag to the commit it points at.

    A ref that is already a commit passes through: re-resolving it would be a
    no-op at best and, for a server that does not advertise it, a spurious
    failure.
    """
    require_https(url)
    if COMMIT_RE.match(ref):
        return ref

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
        if name in candidates:
            return candidates[name]

    if len(candidates) > 1:
        raise PublishError(
            f"ref {ref!r} is ambiguous at {url}: {sorted(candidates)}"
        )
    return next(iter(candidates.values()))


def fetch_manifest(url: str, commit: str, subdir: str | None = None) -> dict[str, Any]:
    """Read ``app.json`` from a repository at an exact commit.

    Clones shallowly and then verifies HEAD is the commit we resolved. That
    check is the point: resolve-then-clone is two round trips, and without it a
    ref that moves in between would silently publish different bytes than the
    ones the commit id claims.
    """
    require_https(url)
    with tempfile.TemporaryDirectory(prefix="kcapps-publish-") as tmp:
        repo = Path(tmp) / "fetched"
        try:
            # Fetching the commit directly is exact, but needs the server to
            # allow SHA1-in-want; fall back to a shallow clone below.
            run_git(["init", "--quiet", str(repo)])
            run_git(["remote", "add", "origin", url], cwd=repo)
            run_git(["fetch", "--depth", "1", "--quiet", "origin", commit], cwd=repo)
            head = run_git(["rev-parse", "FETCH_HEAD"], cwd=repo).strip()
        except PublishError:
            # A separate directory: `init` above already populated the first one,
            # and git refuses to clone into a non-empty destination.
            repo = Path(tmp) / "cloned"
            run_git(["clone", "--depth", "1", "--quiet", url, str(repo)])
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

        rel = Path(subdir) / "app.json" if subdir else Path("app.json")
        try:
            raw = run_git(["show", f"{head}:{rel.as_posix()}"], cwd=repo)
        except PublishError as exc:
            raise PublishError(f"{url}: cannot read {rel.as_posix()} at {commit}: {exc}")

    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PublishError(f"{url}: {rel.as_posix()} is not valid JSON: {exc}")
    if not isinstance(manifest, dict):
        raise PublishError(f"{url}: {rel.as_posix()} is not a JSON object")
    return manifest


def derive_summary(description: str, findings: Findings, app: str) -> str | None:
    """Reduce a manifest description to one list-safe line.

    `description` is detail-view body copy and routinely runs past 400
    characters, so it is not a summary. Taking the first sentence produces real
    list copy rather than a sentence severed mid-clause; only a first sentence
    that is itself over-long gets truncated, and that is reported.
    """
    text = " ".join((description or "").split())
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


def normalize_author(value: Any) -> dict[str, Any] | None:
    """Widen a bare author string into the structured form.

    Manifests in the wild carry `"author": "kirocrew"`. The published shape is an
    object so it can carry a link and distinguish a person from an org, and the
    bare string stays valid input precisely so no manifest has to change first.
    """
    if isinstance(value, str):
        name = value.strip()
        return {"name": name} if name else None
    if isinstance(value, dict):
        out = {k: v for k, v in value.items() if k in ("name", "url", "kind") and v}
        return out if out.get("name") else None
    return None


def bake_entry(
    authored: dict[str, Any],
    manifest: dict[str, Any],
    commit: str,
    findings: Findings,
) -> dict[str, Any]:
    """Produce a published entry: authored identity + generated display fields."""
    name = authored["name"]
    if manifest.get("name") and manifest["name"] != name:
        # The catalog and the app disagree about what the app is called. Picking
        # one would make the store's identity depend on which file was read.
        raise PublishError(
            f"{name}: manifest declares name {manifest['name']!r}; "
            f"the catalog entry and the app must agree"
        )

    source = dict(authored["source"])
    source["ref"] = commit

    entry: dict[str, Any] = {"name": name, "source": source}

    if display := (manifest.get("displayName") or "").strip():
        entry["displayName"] = display[:60]
    if summary := derive_summary(manifest.get("description", ""), findings, name):
        entry["summary"] = summary
    if author := normalize_author(manifest.get("author")):
        entry["author"] = author

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

    if version := (manifest.get("version") or "").strip():
        entry["version"] = version[:64]
    if icon := (manifest.get("iconUrl") or "").strip():
        entry["iconRef"] = icon
    if hero := (manifest.get("heroImage") or "").strip():
        entry["heroRef"] = hero

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
    resolver: Callable[[str, str], str],
    fetcher: Callable[..., dict[str, Any]],
    now: datetime,
    findings: Findings,
) -> dict[str, Any]:
    apps: list[dict[str, Any]] = []
    for authored_entry in authored.get("apps") or []:
        source = authored_entry["source"]
        commit = resolver(source["url"], source["ref"])
        manifest = fetcher(source["url"], commit, source.get("subdir"))
        apps.append(bake_entry(authored_entry, manifest, commit, findings))

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


def build_editorial(authored: dict[str, Any], now: datetime) -> dict[str, Any]:
    stamped = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {k: v for k, v in authored.items() if k != "schemaVersion"}
    content_only = {k: v for k, v in doc.items() if k not in ("generatedAt", "revision")}
    return {
        "schemaVersion": 1,
        "generatedAt": stamped,
        "revision": f"{stamped}-{content_digest(content_only)[:7]}",
        **doc,
    }


def sign_detached(payload: bytes, key_path: str) -> dict[str, Any]:
    """Produce a detached ed25519 signature sidecar.

    Detached because every document sets ``additionalProperties: false`` with no
    signature slot, so the bytes verified are exactly the bytes parsed.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:  # pragma: no cover
        raise PublishError(
            "signing requires the `cryptography` package "
            "(pip install -r tools/requirements.txt)"
        ) from exc

    path = Path(key_path)
    if not path.is_file():
        raise PublishError(f"signing key not found: {key_path}")

    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PublishError(
            f"signing key must be ed25519, got {type(key).__name__}"
        )

    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "algorithm": "ed25519",
        "keyId": hashlib.sha256(public).hexdigest()[:16],
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
    }


def publish(out_dir: Path, dry_run: bool, key_path: str | None) -> Findings:
    findings = Findings()

    registry_path = CATALOG_DIR / "official-registry.json"
    editorial_path = CATALOG_DIR / "editorial.json"

    # Never publish something the gate would reject.
    pre = validate(registry_path, editorial_path)
    findings.errors.extend(pre.errors)
    findings.warnings.extend(pre.warnings)
    if pre.errors:
        return findings

    authored_registry = json.loads(registry_path.read_text(encoding="utf-8"))
    authored_editorial = json.loads(editorial_path.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)

    resolver: Callable[[str, str], str]
    fetcher: Callable[..., dict[str, Any]]
    if dry_run:
        # Enough to exercise stamping and schema conformance offline. Publishing
        # for real must never take this path, hence the separate flag.
        resolver = lambda url, ref: ref if COMMIT_RE.match(ref) else "0" * 40  # noqa: E731
        fetcher = lambda url, commit, subdir=None: {}  # noqa: E731
    else:
        resolver, fetcher = resolve_commit, fetch_manifest

    try:
        registry_doc = build_registry(
            authored_registry, resolver, fetcher, now, findings
        )
    except PublishError as exc:
        findings.error(str(exc))
        return findings

    editorial_doc = build_editorial(authored_editorial, now)

    # The output is held to the PUBLISHED contract, which is stricter than the
    # authored one. This is what catches a resolver that returned a branch name
    # or a bake step that emitted an over-long field.
    check_schema(
        registry_doc, SCHEMA_DIR / "official-registry.schema.json", "published registry", findings
    )
    check_schema(
        editorial_doc, SCHEMA_DIR / "editorial.schema.json", "published editorial", findings
    )
    if findings.errors:
        return findings

    artifacts = {
        "official-registry.json": canonical_bytes(registry_doc),
        "editorial.json": canonical_bytes(editorial_doc),
    }

    if dry_run:
        findings.warn("dry run: refs not resolved, fields not baked, nothing signed")
    else:
        if not key_path:
            # Fail closed. A signature is the acceptance gate for Official
            # trust, so an unsigned document is not a lesser product -- it is a
            # document a client cannot distinguish from an attacker's.
            findings.error(
                "no signing key configured: set KIROCREW_REGISTRY_SIGNING_KEY "
                "to an ed25519 private key PEM. Refusing to emit an unsigned "
                "catalog."
            )
            return findings
        try:
            for filename, payload in list(artifacts.items()):
                sidecar = sign_detached(payload, key_path)
                artifacts[f"{filename}.sig"] = (
                    json.dumps(sidecar, indent=2) + "\n"
                ).encode("utf-8")
        except PublishError as exc:
            findings.error(str(exc))
            return findings

    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, payload in artifacts.items():
        (out_dir / filename).write_bytes(payload)

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
        os.environ.get("KIROCREW_REGISTRY_SIGNING_KEY"),
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
