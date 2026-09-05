"""Publish-pipeline tests, run against real git repositories.

The production catalog is empty, so resolve/bake/sign would otherwise ship
untested. These build actual repos in a temp dir and drive the real code paths
rather than mocking git, because the parts worth testing here ARE the git
interaction: which commit a ref resolves to, and whether a moved ref is caught.

`require_https` blocks local paths in production, which is the point of it. The
tests relax that recogniser rather than adding a production bypass flag -- a
`--allow-insecure-url` escape hatch would be exactly the kind of thing that ends
up set in CI.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import publish  # noqa: E402
from validate import Findings  # noqa: E402


@pytest.fixture
def allow_local_urls(monkeypatch):
    """Let the resolver reach local repositories, for tests only.

    Two independent gates have to be relaxed, which is itself the evidence that
    the hardening is real rather than decorative: `require_https` refuses the
    URL shape, and `GIT_ALLOW_PROTOCOL=https` makes git refuse the `file`
    transport even if the URL check were bypassed. Relaxed here rather than via
    a production flag -- an `--allow-insecure-url` option is exactly the kind of
    thing that ends up set in CI.
    """
    monkeypatch.setattr(publish, "HTTPS_RE", re.compile(r"^(https://|/)[^\s\x00]+$"))
    monkeypatch.setattr(
        publish, "GIT_ENV", {**publish.GIT_ENV, "GIT_ALLOW_PROTOCOL": "https:file"}
    )


def git(*args: str, cwd: Path) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True,
        env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e",
             "PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    return proc.stdout.strip()


def make_repo(
    path: Path,
    manifest: dict,
    subdir: str | None = None,
    extra: dict[str, bytes] | None = None,
) -> str:
    """Create a real one-commit repo containing app.json. Returns the commit.

    *extra* adds files by repo-relative path, so a test can commit real BINARY
    content (an icon) and exercise the byte-exact read path rather than stubbing
    it -- a text-mode `git show` would corrupt those bytes silently.
    """
    path.mkdir(parents=True, exist_ok=True)
    git("init", "--quiet", "-b", "main", ".", cwd=path)
    target = path / subdir if subdir else path
    target.mkdir(parents=True, exist_ok=True)
    (target / "app.json").write_text(json.dumps(manifest), encoding="utf-8")
    for rel, payload in (extra or {}).items():
        dest = path / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
    git("add", "-A", cwd=path)
    git("commit", "--quiet", "-m", "init", cwd=path)
    return git("rev-parse", "HEAD", cwd=path)


MANIFEST = {
    "name": "demo-app",
    "version": "1.2.3",
    "displayName": "Demo App",
    "description": "Does the demo thing. Then it does several other things that belong on a detail page rather than in a list, at considerable length.",
    # Deliberately NOT a reserved name: a manifest may no longer assert one at
    # all, so using "kirocrew" here would make every display-field test also a
    # test of the reserved-name drop. That contract has its own tests below.
    "author": "Demo Labs",
    "tags": ["dev", "demo"],
    "iconUrl": "/app-assets/demo-app/icon.svg",
    "heroImage": "/app-assets/demo-app/hero.svg",
}


# --------------------------------------------------------------------------
# Ref resolution
# --------------------------------------------------------------------------


class TestGitTimeoutsDoNotEndTheRun:
    """A git timeout must arrive as a `PublishError`, not a bare `TimeoutExpired`.

    Raised bare it is not a `PublishError`, so it escapes the per-image handler in
    the ingest path, escapes `build_registry`, and escapes `publish`'s own
    handler -- one slow or hostile repository would end every other app's release
    with a traceback, which is the opposite of the warn-and-continue contract
    every rejection in the ingest path documents.

    Converted inside the two git helpers rather than at the ingest call sites,
    because `run_git` has seven callers and patching only the ingest ones leaves
    ls-remote, fetch, clone and rev-parse able to do exactly that.
    """

    @pytest.mark.parametrize("helper", ["run_git", "run_git_bytes"])
    def test_a_timeout_becomes_a_publish_error(self, helper, monkeypatch):
        def times_out(*a, **kw):
            raise subprocess.TimeoutExpired(cmd=["git"], timeout=publish.GIT_TIMEOUT)

        monkeypatch.setattr(subprocess, "run", times_out)
        with pytest.raises(publish.PublishError, match="timed out"):
            getattr(publish, helper)(["show", "HEAD:x"])

    def test_an_ingest_timeout_degrades_to_a_warning(self, monkeypatch):
        """The contract: one repository's timeout costs one card its picture."""

        def times_out(*a, **kw):
            raise subprocess.TimeoutExpired(cmd=["git"], timeout=publish.GIT_TIMEOUT)

        monkeypatch.setattr(subprocess, "run", times_out)
        assets = publish.IconAssets(publish.fetch_blob, publish.blob_size)
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings) is None
        assert findings.errors == []
        assert any("timed out" in w for w in findings.warnings)


def test_resolves_branch_to_commit(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    assert publish.resolve_commit(str(repo), "main") == commit


def test_resolves_tag_to_commit(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "-a", "v1", "-m", "v1", cwd=repo)
    # An annotated tag resolves to the commit it wraps, not the tag object.
    assert publish.resolve_commit(str(repo), "v1") == commit


def test_commit_ref_passes_through(tmp_path, allow_local_urls):
    """Re-resolving a commit is a no-op at best and a spurious failure at worst."""
    sha = "a" * 40
    assert publish.resolve_commit("https://example.invalid/x.git", sha) == sha


def test_unknown_ref_fails(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    with pytest.raises(publish.PublishError):
        publish.resolve_commit(str(repo), "no-such-branch")


def test_resolve_pin_remembers_the_tag(tmp_path, allow_local_urls):
    """A tag ref resolves to (commit, tag): the pin stays immutable, the tag is
    kept as the release name the pin came from."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "-a", "v1.2.0", "-m", "v1.2.0", cwd=repo)
    pin = publish.resolve_pin(str(repo), "v1.2.0")
    assert pin.commit == commit
    assert pin.tag == "v1.2.0"


def test_resolve_pin_lightweight_tag_also_remembered(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "lw-tag", cwd=repo)
    pin = publish.resolve_pin(str(repo), "lw-tag")
    assert pin.commit == commit
    assert pin.tag == "lw-tag"


def test_resolve_pin_branch_has_no_tag(tmp_path, allow_local_urls):
    """Tag-ness comes from WHICH ref matched, not from what the name looks
    like: a branch named like a version is still a branch."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("branch", "v9.9.9", cwd=repo)
    assert publish.resolve_pin(str(repo), "main") == publish.ResolvedPin(commit, None)
    assert publish.resolve_pin(str(repo), "v9.9.9") == publish.ResolvedPin(commit, None)


def test_resolve_pin_commit_passthrough_has_no_tag():
    sha = "a" * 40
    assert publish.resolve_pin("https://example.invalid/x.git", sha) == publish.ResolvedPin(
        sha, None
    )


def test_resolve_pin_prefers_tag_over_same_named_branch(tmp_path, allow_local_urls):
    """When `v1` exists as both a tag and a branch, the existing resolution
    order picks the tag -- so the provenance must say tag as well."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "-a", "v1", "-m", "v1", cwd=repo)
    git("branch", "v1", cwd=repo)
    pin = publish.resolve_pin(str(repo), "v1")
    assert pin.commit == commit
    assert pin.tag == "v1"


def test_resolve_pin_wildcard_ref_publishes_the_matched_tag_not_the_pattern(
    tmp_path, allow_local_urls
):
    """`ls-remote` accepts glob patterns, so `v1.*` matching one lightweight tag
    reaches the single-candidate fallback. The published sourceTag must be the
    tag that MATCHED, never the pattern the curator typed -- a signed document
    naming release `v1.*` names a release that does not exist."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "v1.2.0", cwd=repo)
    pin = publish.resolve_pin(str(repo), "v1.*")
    assert pin.commit == commit
    assert pin.tag == "v1.2.0"


def test_resolve_pin_wildcard_matching_annotated_tag_peels_and_names_it(
    tmp_path, allow_local_urls
):
    """An annotated tag matched via glob returns two candidate lines (`v1.2.0`
    and `v1.2.0^{}`); the fallback collapses the pair onto the peeled commit
    and names the clean tag."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "-a", "v1.2.0", "-m", "v1.2.0", cwd=repo)
    pin = publish.resolve_pin(str(repo), "v1.*")
    assert pin.commit == commit
    assert pin.tag == "v1.2.0"


def test_resolve_pin_fully_qualified_annotated_tag_peels_and_strips_namespace(
    tmp_path, allow_local_urls
):
    """`refs/tags/v1` written verbatim matches its own RAW ref, which for an
    annotated tag names the TAG OBJECT -- the pin must still be the peeled
    commit (a tag-object pin halts publishing at the object-type check), and
    sourceTag must not leak the `refs/tags/` namespace."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "-a", "v1", "-m", "v1", cwd=repo)
    tag_object = git("rev-parse", "v1", cwd=repo)
    assert tag_object != commit, "fixture must use an annotated tag"

    pin = publish.resolve_pin(str(repo), "refs/tags/v1")
    assert pin.commit == commit, "must peel to the commit, not the tag object"
    assert pin.tag == "v1", "namespace must be stripped from the published name"


def test_resolve_pin_fully_qualified_lightweight_tag(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "lw", cwd=repo)
    pin = publish.resolve_pin(str(repo), "refs/tags/lw")
    assert pin.commit == commit
    assert pin.tag == "lw"


def test_resolve_pin_fully_qualified_branch_has_no_tag(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    pin = publish.resolve_pin(str(repo), "refs/heads/main")
    assert pin.commit == commit
    assert pin.tag is None


@pytest.mark.parametrize(
    "url", ["ext::sh -c id", "file:///etc/passwd", "--upload-pack=/bin/sh", "git@h:a/b.git"]
)
def test_require_https_refuses_execution_vectors(url):
    with pytest.raises(publish.PublishError):
        publish.require_https(url)


def test_git_hardening_disables_the_ext_transport():
    """`ext::` hands a command line to a shell; nothing else matters if reachable."""
    assert "protocol.ext.allow=never" in publish.GIT_HARDENING
    assert "credential.helper=" in publish.GIT_HARDENING
    assert publish.GIT_ENV["GIT_TERMINAL_PROMPT"] == "0"


# --------------------------------------------------------------------------
# Manifest fetch
# --------------------------------------------------------------------------


def test_fetches_manifest_at_commit(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    assert publish.fetch_manifest(str(repo), commit)["name"] == "demo-app"


def test_fetches_manifest_from_subdir(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST, subdir="apps/demo")
    assert publish.fetch_manifest(str(repo), commit, "apps/demo")["version"] == "1.2.3"


def test_missing_manifest_fails(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    with pytest.raises(publish.PublishError):
        publish.fetch_manifest(str(repo), commit, "nope")


def test_moved_ref_is_caught(tmp_path, allow_local_urls, monkeypatch):
    """resolve-then-clone is two round trips; a ref that moves between them must
    not publish bytes that disagree with the commit id."""
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    stale = "b" * 40  # a commit this repo does not contain

    # Force the shallow-clone fallback so HEAD is the branch tip, not `stale`.
    real = publish.run_git

    def fail_fetch(args, cwd=None):
        if args and args[0] == "fetch":
            raise publish.PublishError("no SHA1-in-want")
        return real(args, cwd=cwd)

    monkeypatch.setattr(publish, "run_git", fail_fetch)
    with pytest.raises(publish.PublishError, match="ref moved during publish"):
        publish.fetch_manifest(str(repo), stale)


# --------------------------------------------------------------------------
# Baking
# --------------------------------------------------------------------------


def authored(name="demo-app", url="https://example.com/a.git", ref="main"):
    return {"name": name, "source": {"type": "git", "url": url, "ref": ref}}


def test_bakes_generated_fields():
    findings = Findings()
    entry = publish.bake_entry(authored(), MANIFEST, "a" * 40, findings)

    assert entry["source"]["ref"] == "a" * 40, "the pin must be the resolved commit"
    assert "sourceTag" not in entry["source"], "a branch ref carries no release name"
    assert entry["displayName"] == "Demo App"
    assert entry["summary"] == "Does the demo thing."
    assert entry["author"] == {"name": "Demo Labs"}
    assert entry["tags"] == ["dev", "demo"]
    assert entry["version"] == "1.2.3"
    # MANIFEST names its icon with an ABSOLUTE `iconUrl`, which only a builtin
    # may do. This entry is a git source, so the icon is read from `iconPath`
    # (absent here) -- and because the publisher clearly meant to ship an icon,
    # the run says which key this source type reads instead of going quiet.
    # `heroImage` is absolute for the same reason and is now held to the same
    # rule: a fetched manifest may not name an absolute location, so the hero is
    # DROPPED with its own diagnostic rather than published. It used to be copied
    # through unchecked, into a document we sign.
    assert "iconRef" not in entry
    assert any("reads iconPath" in w for w in findings.warnings)
    assert "heroRef" not in entry
    assert any(
        "heroImage" in w and "not a repo-relative path" in w for w in findings.warnings
    )


class TestBakesIconRefs:
    """Which manifest key an icon is read from depends on the SOURCE TYPE.

    A builtin resolves from the client's own inventory, so it names an absolute
    client-local path whose bytes it already ships. Everything else is fetched
    from a repository we do not control, so only a repo-relative path is read --
    the client rewrites that onto its own proxy, which is what keeps the
    extension allowlist and the trusted-host gate in the fetch path.
    """

    def test_builtin_reads_the_absolute_icon_url(self):
        findings = Findings()
        entry = publish.bake_entry(BUILTIN, MANIFEST, "b" * 40, findings)
        assert entry["iconRef"] == "/app-assets/demo-app/icon.svg"
        assert findings.warnings == []

    def test_builtin_dark_variant_is_published(self):
        manifest = {**MANIFEST, "iconUrlDark": "/app-assets/demo-app/icon-dark.svg"}
        entry = publish.bake_entry(BUILTIN, manifest, "b" * 40, Findings())
        assert entry["iconRefDark"] == "/app-assets/demo-app/icon-dark.svg"

    def test_git_reads_the_repo_relative_icon_path(self):
        """The bug this closes: a fetched app declares `iconPath`, so reading
        only `iconUrl` published NO icon for every third-party entry."""
        findings = Findings()
        manifest = {**MANIFEST, "iconPath": "assets/icon.png"}
        del manifest["iconUrl"]
        # MANIFEST's `heroImage` is absolute, which a git source may not name, so
        # leaving it in would add a hero diagnostic to a test about icons and make
        # the empty-warnings assertion below fail for an unrelated reason.
        del manifest["heroImage"]
        entry = publish.bake_entry(authored(), manifest, "a" * 40, findings)
        assert entry["iconRef"] == "assets/icon.png"
        assert findings.warnings == []

    def test_git_dark_variant_is_published(self):
        manifest = {**MANIFEST, "iconPathDark": "assets/icon-dark.png"}
        del manifest["iconUrl"]
        entry = publish.bake_entry(authored(), manifest, "a" * 40, Findings())
        assert entry["iconRefDark"] == "assets/icon-dark.png"

    def test_absent_icon_publishes_no_key(self):
        """Absence must not publish an empty string: a falsy ref would still be
        a key the client has to special-case, and it widens every entry."""
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        entry = publish.bake_entry(authored(), manifest, "a" * 40, Findings())
        assert "iconRef" not in entry
        assert "iconRefDark" not in entry

    def test_truly_iconless_app_is_told_which_key_to_declare(self):
        """An app with no icon at all used to publish a placeholder card with no
        diagnostic anywhere, so the store looked broken rather than the manifest
        incomplete. The wrong-key warning must still not fire: nothing was
        declared under the other key either."""
        findings = Findings()
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        publish.bake_entry(authored(), manifest, "a" * 40, findings)
        assert any("no icon declared" in w for w in findings.warnings)
        assert any("'iconPath'" in w for w in findings.warnings)
        assert not any("reads" in w for w in findings.warnings)
        assert findings.errors == []

    def test_a_builtin_with_no_icon_is_told_to_declare_the_absolute_key(self):
        """The advice has to name the key THIS source type reads, or it sends the
        publisher to the one that would be dropped. Read off `errors` rather than
        `warnings` because a built-in's missing icon is fatal (see
        `ICON_MISSING_IS_ERROR_BUILTIN`) -- the ADVICE is what this pins, and it
        has to survive the finding changing severity."""
        findings = Findings()
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        publish.bake_entry(BUILTIN, manifest, "b" * 40, findings)
        assert any("'iconUrl'" in e for e in findings.errors)
        assert not any("'iconPath'" in e for e in findings.errors)

    def test_a_dropped_icon_is_not_told_to_declare_what_it_declared(self):
        """A rejected icon already reports its own cause. Repeating it as "no
        icon declared" would both duplicate the finding and give false advice."""
        findings = Findings()
        entry = publish.bake_entry(
            authored(), {**MANIFEST, "iconPath": "/etc/passwd"}, "a" * 40, findings
        )
        assert "iconRef" not in entry
        assert any("no icon published" in w for w in findings.warnings)
        assert not any("declared" in w and "Declare" in w for w in findings.warnings)

    def test_a_missing_icon_can_be_promoted_to_an_error(self, monkeypatch):
        """The gate is one switch. Two third-party entries ship no icon today, so
        erroring now would drop them for a defect upstream; this pins that
        flipping it later needs no other change."""
        monkeypatch.setattr(publish, "ICON_MISSING_IS_ERROR", True)
        findings = Findings()
        # `heroImage` out with `iconUrl`: it is absolute, which a git source may
        # not name, and its diagnostic would break the icon-only assertion below.
        manifest = {
            k: v for k, v in MANIFEST.items() if k not in ("iconUrl", "heroImage")
        }
        publish.bake_entry(authored(), manifest, "a" * 40, findings)
        assert findings.warnings == []
        assert any("no icon declared" in e for e in findings.errors)

    def test_a_builtin_with_no_icon_fails_the_run(self):
        """A first-party iconless card is not waiting on anyone: the manifest read
        here is in our own repository and the bytes ship in the client. So it fails
        the run instead of warning, which is the difference between "fix one line
        before the document goes out" and what actually happened -- three built-ins
        rendering placeholders in the live store while their `icon.svg` shipped in
        every client, diagnosed only in a publish log nobody reads."""
        findings = Findings()
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        publish.bake_entry(BUILTIN, manifest, "b" * 40, findings)
        assert findings.warnings == []
        assert any("no icon declared" in e for e in findings.errors)

    def test_a_third_party_with_no_icon_still_only_warns(self):
        """The asymmetry IS the gate, so it is pinned from both sides: erroring on
        a fetched app would withhold the whole catalog for a defect in a repository
        we do not control, which is worse than the placeholder it replaces."""
        findings = Findings()
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        publish.bake_entry(authored(), manifest, "a" * 40, findings)
        assert findings.errors == []
        assert any("no icon declared" in w for w in findings.warnings)

    def test_the_builtin_gate_is_also_one_switch(self, monkeypatch):
        """Mirrors the third-party switch: if a built-in ever has to ship iconless
        (an app whose icon is genuinely still in review), that is one line, not a
        rewrite of the reporting block."""
        monkeypatch.setattr(publish, "ICON_MISSING_IS_ERROR_BUILTIN", False)
        findings = Findings()
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        publish.bake_entry(BUILTIN, manifest, "b" * 40, findings)
        assert findings.errors == []
        assert any("no icon declared" in w for w in findings.warnings)

    def test_an_app_with_an_icon_is_not_warned_about_one(self):
        findings = Findings()
        publish.bake_entry(BUILTIN, MANIFEST, "b" * 40, findings)
        assert not any("no icon" in w for w in findings.warnings)

    def test_an_unfetched_manifest_is_not_diagnosed(self):
        """`--dry-run` substitutes an empty manifest for all 22 entries. Warning
        per app there would print more findings than a real publish does, none of
        them true, which is how a reader learns to skim the block."""
        findings = Findings()
        publish.bake_entry(authored(), {}, "a" * 40, findings)
        assert findings.warnings == []
        assert findings.errors == []

    def test_wrong_key_for_the_source_type_is_named(self):
        """A publisher who used the other source type's key gets told which key
        this one reads. Silence would read as "the catalog dropped my icon"."""
        findings = Findings()
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        manifest["iconPath"] = "assets/i.png"
        publish.bake_entry(BUILTIN, manifest, "b" * 40, findings)
        assert any("reads iconUrl" in w for w in findings.warnings)

    @pytest.mark.parametrize(
        "value",
        [
            "https://evil.example/track.png",
            "http://evil.example/track.png",
            "//evil.example/track.png",
            "javascript:alert(1)",
            "data:image/svg+xml;base64,AAAA",
            "/etc/passwd",
            "../../etc/passwd",
            "assets/../../etc/passwd",
            "assets/icon.png?ref=track",
            "assets/ icon.png",
        ],
    )
    def test_fetched_manifest_may_not_name_an_absolute_or_escaping_location(self, value):
        """A fetched manifest is untrusted content. Publishing an absolute value
        out of it would put a publisher-chosen host into a document WE sign, and
        the store would then load it."""
        findings = Findings()
        entry = publish.bake_entry(
            authored(), {**MANIFEST, "iconPath": value}, "a" * 40, findings
        )
        assert "iconRef" not in entry, value
        assert findings.errors == [], "one bad icon must not halt the release"
        assert any("iconPath" in w for w in findings.warnings)

    def test_builtin_relative_icon_is_refused(self):
        """The asymmetry runs both ways: a builtin's ref is resolved by the
        client against its own served root, so a relative value would silently
        resolve somewhere else entirely."""
        findings = Findings()
        manifest = {**MANIFEST, "iconUrl": "assets/icon.png"}
        entry = publish.bake_entry(BUILTIN, manifest, "b" * 40, findings)
        assert "iconRef" not in entry
        assert any("absolute client-local path" in w for w in findings.warnings)

    def test_non_string_icon_degrades_without_raising(self):
        """Same totality rule as every other display field: nothing read from an
        app.json may halt the run."""
        entry = publish.bake_entry(
            authored(), {**MANIFEST, "iconPath": {"nope": 1}}, "a" * 40, Findings()
        )
        assert "iconRef" not in entry



def test_bake_rejects_name_disagreement():
    """Picking a winner would make store identity depend on which file was read."""
    with pytest.raises(publish.PublishError, match="must agree"):
        publish.bake_entry(authored(), {**MANIFEST, "name": "other-app"}, "a" * 40, Findings())


def test_summary_is_the_first_sentence_not_a_truncation():
    """Every real description runs past the 200-char summary cap, so this is the
    normal path, not an edge case -- a mid-clause cut would be the norm."""
    findings = Findings()
    long_desc = "Short opener. " + "x" * 500
    assert publish.derive_summary(long_desc, findings, "a") == "Short opener."
    assert findings.warnings == []


def test_over_long_first_sentence_truncates_and_warns():
    findings = Findings()
    summary = publish.derive_summary("y" * 400 + ".", findings, "demo-app")
    assert len(summary) <= publish.SUMMARY_MAX
    assert summary.endswith("\u2026")
    assert any("truncated" in w for w in findings.warnings)


def test_description_with_no_sentence_end_still_yields_a_summary():
    assert publish.derive_summary("no full stop here", Findings(), "a") == "no full stop here"


def test_empty_description_yields_no_summary():
    assert publish.derive_summary("   ", Findings(), "a") is None


@pytest.mark.parametrize(
    "value,expected",
    [
        ("kirocrew", {"name": "kirocrew"}),
        ({"name": "acme", "url": "https://acme.example", "kind": "org"},
         {"name": "acme", "url": "https://acme.example", "kind": "org"}),
        ({"url": "https://acme.example"}, None),  # no name -> not a valid author
        ("", None),
        (42, None),
    ],
)
def test_normalize_author(value, expected):
    assert publish.normalize_author(value) == expected


# --------------------------------------------------------------------------
# Signing -- the acceptance gate
# --------------------------------------------------------------------------


class FakeKms:
    """Stands in for the KMS client.

    Backed by a real locally-generated RSA-3072 key that signs with the same
    algorithm KMS uses, so the signatures produced here are checked by the real
    verifier rather than by a mock that agrees with whatever it is given. The
    only thing faked is the network.
    """

    def __init__(self, key_spec="RSA_3072", key_usage="SIGN_VERIFY"):
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.key_spec = key_spec
        self.key_usage = key_usage
        self.get_public_key_calls = 0
        self.sign_calls = []

    def public_der(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_public_key(self, KeyId):  # noqa: N803 - boto3 parameter casing
        self.get_public_key_calls += 1
        return {
            "PublicKey": self.public_der(),
            "KeySpec": self.key_spec,
            "KeyUsage": self.key_usage,
        }

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):  # noqa: N803
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils

        self.sign_calls.append(
            {
                "Message": Message,
                "MessageType": MessageType,
                "SigningAlgorithm": SigningAlgorithm,
            }
        )
        if MessageType != "DIGEST":
            raise AssertionError(f"unexpected MessageType {MessageType!r}")
        return {
            "Signature": self.key.sign(
                Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
            )
        }


def publish_key(monkeypatch, keys_dir: Path, der: bytes, key_id=None) -> str:
    """Commit a public key to a stand-in `keys/`, the way the repo does."""
    keys_dir.mkdir(exist_ok=True)
    key_id = key_id or hashlib.sha256(der).hexdigest()[:16]
    (keys_dir / f"kms-{key_id}.pub").write_text(
        base64.b64encode(der).decode("ascii") + "\n"
    )
    monkeypatch.setattr(publish, "KEYS_DIR", keys_dir)
    return key_id


def verify_rsa(der: bytes, signature: bytes, payload: bytes) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    serialization.load_der_public_key(der).verify(
        signature, payload, padding.PKCS1v15(), hashes.SHA256()
    )


def test_signature_verifies_against_the_exact_payload(tmp_path, monkeypatch):
    kms = FakeKms()
    key_id = publish_key(monkeypatch, tmp_path / "keys", kms.public_der())
    payload = b'{"schemaVersion": 1}\n'

    sidecar = publish.kms_signer("alias/whatever", kms)(payload)

    assert sidecar["algorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"
    assert sidecar["keyId"] == key_id
    assert sidecar["payloadSha256"] == hashlib.sha256(payload).hexdigest()
    verify_rsa(kms.public_der(), base64.b64decode(sidecar["signature"]), payload)


def test_signature_does_not_verify_against_altered_payload(tmp_path, monkeypatch):
    from cryptography.exceptions import InvalidSignature

    kms = FakeKms()
    publish_key(monkeypatch, tmp_path / "keys", kms.public_der())

    sidecar = publish.kms_signer("alias/whatever", kms)(b"original")
    with pytest.raises(InvalidSignature):
        verify_rsa(
            kms.public_der(), base64.b64decode(sidecar["signature"]), b"tampered"
        )


def test_signing_asks_kms_for_a_digest_not_the_whole_document(tmp_path, monkeypatch):
    """KMS caps a RAW message at 4096 bytes, which the catalog will outgrow."""
    kms = FakeKms()
    publish_key(monkeypatch, tmp_path / "keys", kms.public_der())
    payload = b"x" * 9000

    publish.kms_signer("alias/whatever", kms)(payload)

    call = kms.sign_calls[0]
    assert call["MessageType"] == "DIGEST"
    assert call["Message"] == hashlib.sha256(payload).digest()
    assert call["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"


def test_public_key_is_resolved_once_not_once_per_document(tmp_path, monkeypatch):
    """Two documents must not be able to disagree about which key signed them."""
    kms = FakeKms()
    publish_key(monkeypatch, tmp_path / "keys", kms.public_der())

    sign = publish.kms_signer("alias/whatever", kms)
    sign(b"first")
    sign(b"second")

    assert kms.get_public_key_calls == 1
    assert len(kms.sign_calls) == 2


def test_key_absent_from_keys_dir_is_refused_before_signing(tmp_path, monkeypatch):
    """A mistyped key id must fail here, not mint unverifiable signatures."""
    kms = FakeKms()
    other = FakeKms()
    publish_key(monkeypatch, tmp_path / "keys", other.public_der())

    with pytest.raises(publish.PublishError, match="not published in keys/"):
        publish.kms_signer("alias/typo", kms)
    assert kms.sign_calls == []


def test_keys_entry_that_disagrees_with_the_live_key_is_refused(tmp_path, monkeypatch):
    """The filename claims the live key's id, but the material is another key."""
    kms = FakeKms()
    impostor = FakeKms()
    live_id = hashlib.sha256(kms.public_der()).hexdigest()[:16]
    publish_key(monkeypatch, tmp_path / "keys", impostor.public_der(), key_id=live_id)

    with pytest.raises(publish.PublishError, match="material differs"):
        publish.kms_signer("alias/whatever", kms)


def test_wrong_key_spec_is_refused(tmp_path, monkeypatch):
    kms = FakeKms(key_spec="RSA_2048")
    publish_key(monkeypatch, tmp_path / "keys", kms.public_der())

    with pytest.raises(publish.PublishError, match="expected RSA_3072/SIGN_VERIFY"):
        publish.kms_signer("alias/whatever", kms)


def test_encrypt_only_key_is_refused(tmp_path, monkeypatch):
    kms = FakeKms(key_usage="ENCRYPT_DECRYPT")
    publish_key(monkeypatch, tmp_path / "keys", kms.public_der())

    with pytest.raises(publish.PublishError, match="expected RSA_3072/SIGN_VERIFY"):
        publish.kms_signer("alias/whatever", kms)


def test_publish_fails_closed_without_a_key(tmp_path):
    """An unsigned catalog is not a lesser product: a client cannot tell it from
    an attacker's copy. So nothing may be written at all."""
    out = tmp_path / "dist"
    findings = publish.publish(out, dry_run=False, key_id=None)
    assert any("Refusing to emit an unsigned catalog" in e for e in findings.errors)
    assert not out.exists() or not list(out.iterdir())


# --------------------------------------------------------------------------
# Whole-document build
# --------------------------------------------------------------------------


def build(authored_doc, tmp_path, allow_local=True):
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    for entry in authored_doc.get("apps", []):
        entry["source"]["url"] = str(repo)
    findings = Findings()
    doc = publish.build_registry(
        authored_doc, publish.resolve_commit, publish.fetch_manifest,
        publish.datetime.now(publish.timezone.utc), findings,
    )
    return doc, findings, commit


def test_built_document_satisfies_the_published_schema(tmp_path, allow_local_urls):
    doc, findings, commit = build({"schemaVersion": 1, "apps": [authored()]}, tmp_path)
    assert findings.errors == []
    assert doc["apps"][0]["source"]["ref"] == commit

    # The published schema requires an https url, and these tests deliberately
    # build from a local repo. Swap the transport back before checking shape --
    # the schema rejecting the local path is correct behaviour, not a finding.
    doc["apps"][0]["source"]["url"] = "https://example.com/demo-app.git"

    from validate import check_schema
    out = Findings()
    check_schema(doc, publish.SCHEMA_DIR / "official-registry.schema.json", "pub", out)
    assert out.errors == [], out.errors


def test_publishing_from_a_tag_records_source_tag(tmp_path, allow_local_urls):
    """The release workflow end to end: a curator names a tag, the published
    entry pins the commit AND says which release the pin came from."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "-a", "v1.2.0", "-m", "v1.2.0", cwd=repo)

    authored_doc = {"schemaVersion": 1, "apps": [authored(url=str(repo), ref="v1.2.0")]}
    findings = Findings()
    doc = publish.build_registry(
        authored_doc, publish.resolve_pin, publish.fetch_manifest,
        publish.datetime.now(publish.timezone.utc), findings,
    )
    assert findings.errors == []
    source = doc["apps"][0]["source"]
    assert source["ref"] == commit, "the pin is still the immutable commit"
    assert source["sourceTag"] == "v1.2.0"

    # And the result is a legal published document (https swap as above).
    source["url"] = "https://example.com/demo-app.git"
    from validate import check_schema
    out = Findings()
    check_schema(doc, publish.SCHEMA_DIR / "official-registry.schema.json", "pub", out)
    assert out.errors == [], out.errors


def test_publishing_from_a_branch_emits_no_source_tag(tmp_path, allow_local_urls):
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    authored_doc = {"schemaVersion": 1, "apps": [authored(url=str(repo), ref="main")]}
    findings = Findings()
    doc = publish.build_registry(
        authored_doc, publish.resolve_pin, publish.fetch_manifest,
        publish.datetime.now(publish.timezone.utc), findings,
    )
    assert findings.errors == []
    assert "sourceTag" not in doc["apps"][0]["source"]


@pytest.mark.parametrize(
    "bad_tag",
    [
        5,  # non-string
        True,  # non-string (bool)
        "",  # empty -- omit the field instead
        "v1 2",  # whitespace
        "v1\t2",  # whitespace (tab)
        "v1\u0000",  # NUL
        "x" * 256,  # overlong (max 255)
    ],
)
def test_published_schema_rejects_malformed_source_tag(bad_tag, tmp_path, allow_local_urls):
    """Pin the published-schema constraints on sourceTag itself: this document
    is signed, so a field that renders in the store must not admit control
    characters, whitespace padding, or unbounded length."""
    doc, findings, commit = build({"schemaVersion": 1, "apps": [authored()]}, tmp_path)
    assert findings.errors == []
    source = doc["apps"][0]["source"]
    source["url"] = "https://example.com/demo-app.git"
    source["sourceTag"] = bad_tag

    from validate import check_schema
    out = Findings()
    check_schema(doc, publish.SCHEMA_DIR / "official-registry.schema.json", "pub", out)
    assert out.errors, f"schema must reject sourceTag {bad_tag!r}"


def test_published_schema_accepts_a_well_formed_source_tag(tmp_path, allow_local_urls):
    doc, findings, commit = build({"schemaVersion": 1, "apps": [authored()]}, tmp_path)
    source = doc["apps"][0]["source"]
    source["url"] = "https://example.com/demo-app.git"
    source["sourceTag"] = "v1.2.0"

    from validate import check_schema
    out = Findings()
    check_schema(doc, publish.SCHEMA_DIR / "official-registry.schema.json", "pub", out)
    assert out.errors == [], out.errors


def test_bake_entry_records_source_tag_for_git_only():
    findings = Findings()
    entry = publish.bake_entry(authored(), MANIFEST, "a" * 40, findings, tag="v2.0")
    assert entry["source"]["sourceTag"] == "v2.0"


@pytest.mark.parametrize("bad_tag", ["x" * 256, "v1 2", "v1\t2", "v1\u00002"])
def test_bake_entry_degrades_an_unpublishable_tag_to_a_warning(bad_tag):
    """One repository's freakish tag name must cost that entry its release
    label, never the whole catalog: the final schema check refuses the entire
    document, so an overlong/whitespace tag reaching it would withhold every
    app. The pin is unaffected."""
    findings = Findings()
    entry = publish.bake_entry(authored(), MANIFEST, "a" * 40, findings, tag=bad_tag)
    assert entry["source"]["ref"] == "a" * 40, "the pin must survive"
    assert "sourceTag" not in entry["source"]
    assert findings.errors == []
    assert any("not publishable as" in w for w in findings.warnings)


def test_bake_entry_accepts_a_255_char_tag_boundary():
    findings = Findings()
    entry = publish.bake_entry(authored(), MANIFEST, "a" * 40, findings, tag="x" * 255)
    assert entry["source"]["sourceTag"] == "x" * 255
    assert not any("not publishable" in w for w in findings.warnings)


def test_builtin_never_carries_a_source_tag():
    """A builtin publishes no fetch coordinates at all, so a tag on the
    manifestFrom repo has nothing to attach to."""
    findings = Findings()
    entry = publish.bake_entry(BUILTIN, MANIFEST, "b" * 40, findings, tag="v2.0")
    assert "sourceTag" not in entry["source"]


def test_authored_source_tag_is_rejected():
    """`sourceTag` is generated, never authored -- additionalProperties:false on
    the authored source is what machine-checks that, so pin the behaviour."""
    from validate import check_schema

    entry = authored()
    entry["source"]["sourceTag"] = "v1"
    out = Findings()
    check_schema(
        {"schemaVersion": 1, "apps": [entry]},
        publish.SCHEMA_DIR / "authored-registry.schema.json",
        "authored",
        out,
    )
    assert out.errors, "an authored sourceTag must fail validation"


def test_annotated_tag_resolves_to_a_commit_not_the_tag_object(tmp_path, allow_local_urls):
    """Regression: `ls-remote <url> v1` reports only `refs/tags/v1`, whose sha is
    the tag OBJECT. Pinning that put a non-commit in a commit field, undetectable
    by shape since both are 40 hex characters."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    git("tag", "-a", "v1", "-m", "v1", cwd=repo)

    tag_object = git("rev-parse", "v1", cwd=repo)
    assert tag_object != commit, "fixture must use an annotated tag"

    resolved = publish.resolve_commit(str(repo), "v1")
    assert resolved == commit, "must peel to the commit"
    assert resolved != tag_object


def test_tag_object_pin_is_rejected_at_fetch(tmp_path, allow_local_urls):
    """Second layer for the same bug: whatever produced the pin, the object must
    be a commit."""
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    git("tag", "-a", "v1", "-m", "v1", cwd=repo)
    tag_object = git("rev-parse", "v1", cwd=repo)

    with pytest.raises(publish.PublishError, match="not a commit"):
        publish.fetch_manifest(str(repo), tag_object)


def test_shallow_clone_fallback_works(tmp_path, allow_local_urls, monkeypatch):
    """Regression: the fallback cloned into the directory `git init` had already
    created, so git refused a non-empty destination and the path never worked."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)

    real = publish.run_git

    def no_sha_in_want(args, cwd=None):
        if args and args[0] == "fetch":
            raise publish.PublishError("simulated: server disallows SHA1-in-want")
        return real(args, cwd=cwd)

    monkeypatch.setattr(publish, "run_git", no_sha_in_want)
    # HEAD of the default branch IS the commit here, so the fallback must succeed.
    assert publish.fetch_manifest(str(repo), commit)["name"] == "demo-app"


def test_empty_history_is_omitted_not_emitted_empty(tmp_path, allow_local_urls):
    doc, _, _ = build({"schemaVersion": 1, "apps": [authored()]}, tmp_path)
    assert "removed" not in doc and "reinstated" not in doc


def test_revision_is_derived_from_content(tmp_path, allow_local_urls):
    """Same content must give the same revision digest; different content must not."""
    a, _, _ = build({"schemaVersion": 1, "apps": [authored()]}, tmp_path / "one")
    b, _, _ = build({"schemaVersion": 1, "apps": [authored()]}, tmp_path / "two")
    # Different repos -> different commit pins -> different content digest.
    assert a["revision"].split("-")[-1] != b["revision"].split("-")[-1]

    digest = publish.content_digest({"apps": [], "removed": [], "reinstated": []})
    assert digest == publish.content_digest({"apps": [], "removed": [], "reinstated": []})


def _bake(url: str, author, name: str = "some-app", curated=None):
    """Bake one entry, as build_registry would. Returns (entry, findings).

    The manifest carries an icon so these author assertions can keep demanding
    NO warnings at all: an entry with no icon earns one of its own, and a
    blanket-empty assertion is worth more than one narrowed to author findings.
    """
    findings = publish.Findings()
    authored = {"name": name, "source": {"type": "git", "url": url, "ref": "main"}}
    if curated is not None:
        authored["author"] = curated
    entry = publish.bake_entry(
        authored,
        {"name": name, "author": author, "iconPath": "assets/icon.png"},
        "0" * 40,
        findings,
    )
    return entry, findings


def test_curator_stated_author_overrides_the_manifest():
    """The catalog is signed by us, so what it asserts about provenance must be
    what we state -- not what the app's own file claims about itself."""
    entry, findings = _bake(
        "https://github.com/launchdarkly-labs/launchdarkly-kiro-crew-app",
        "kirocrew",
        name="launchdarkly",
        curated={
            "name": "LaunchDarkly Labs",
            "url": "https://github.com/launchdarkly-labs",
            "kind": "org",
        },
    )

    assert entry["author"] == {
        "name": "LaunchDarkly Labs",
        "url": "https://github.com/launchdarkly-labs",
        "kind": "org",
    }
    assert findings.warnings == [], "a stated author is not a fallback, so no warning"


def test_a_curator_may_state_the_first_party_author():
    """The reserved-name guard constrains the MANIFEST's self-claim, not us: the
    curator holds the signing key, so it can already assert anything -- there is
    no privilege to withhold here, only drift to avoid."""
    entry, _ = _bake(
        "https://github.com/acme-labs/white-labelled.git",
        "acme-labs",
        curated={"name": "kirocrew", "kind": "org"},
    )
    assert entry["author"] == {"name": "kirocrew", "kind": "org"}


def test_third_party_claiming_the_first_party_author_ships_unattributed():
    """`author` lives in the PUBLISHER's repo, so it is a self-claim. The claim is
    dropped rather than republished -- but the app still publishes, because
    failing the run would let any publisher halt every release by writing our
    name in a file we do not control."""
    entry, findings = _bake("https://github.com/acme-labs/their-app.git", "kirocrew")

    assert "author" not in entry, "the false claim must not reach a signed document"
    assert findings.errors == [], "one bad manifest field must not fail the publish"
    assert any("reserved author" in w for w in findings.warnings)


def test_the_reserved_author_check_is_case_insensitive():
    """`KiroCrew` and `kirocrew` make the same claim to a reader."""
    entry, findings = _bake("https://github.com/acme-labs/their-app.git", "KiroCrew")
    assert "author" not in entry
    assert findings.warnings


def test_even_a_first_party_source_cannot_let_a_manifest_claim_our_name():
    """The url is no longer consulted, and that is the point.

    Trusting it required the url we CHECK and the repository git FETCHES to be
    the same thing, and they are not: `https://github.com/kirodetdev/../x` style
    dot segments satisfy a first-party prefix test while git normalizes them away
    and fetches somewhere else. Rather than canonicalize a url in order to keep
    honouring a claim made inside a file we do not control, the claim is not
    honoured at all -- the curator states it on the entry instead.
    """
    entry, findings = _bake(
        "https://github.com/kirodotdev/KiroCrewApp-Thing.git", "kirocrew"
    )
    assert "author" not in entry
    assert any("reserved author" in w for w in findings.warnings)

    bypass, _ = _bake("https://github.com/kirodotdev/../attacker/x.git", "kirocrew")
    assert "author" not in bypass


@pytest.mark.parametrize(
    "claimed",
    [
        "\uff2b\uff49\uff52\uff4f\uff23\uff52\uff45\uff57",  # fullwidth KiroCrew
        "kiro\u200bcrew",  # zero-width space
        "kiro\u00adcrew",  # soft hyphen
        "kiro  crew",  # doubled separator
        "KiroCrew",
    ],
)
def test_reserved_name_folding_resists_look_alikes(claimed):
    """A name that READS as ours makes the claim, whatever bytes encode it.

    casefold() alone catches only the last of these, which is why the fold
    normalizes and strips format characters before the membership test.
    """
    entry, findings = _bake("https://github.com/acme-labs/their-app.git", claimed)
    assert "author" not in entry, f"{claimed!r} reads as the reserved name"
    assert findings.warnings


def test_a_third_party_author_passes_through_untouched():
    entry, findings = _bake("https://github.com/acme-labs/their-app.git", "acme-labs")
    assert entry["author"] == {"name": "acme-labs"}
    assert findings.warnings == []


# --------------------------------------------------------------------------
# Nothing in an app.json may halt another app's release
# --------------------------------------------------------------------------

BUILTIN = {
    "name": "demo-app",
    "source": {
        "type": "builtin",
        "manifestFrom": {
            "url": "https://github.com/kirodotdev/KiroCrew.git",
            "ref": "b" * 40,
            "subdir": "src/apps/builtins/demo_app",
        },
    },
}


@pytest.mark.parametrize("hostile", [5, [1], {"a": 1}, True])
@pytest.mark.parametrize(
    "field", ["displayName", "version", "description", "iconUrl", "heroImage"]
)
def test_a_non_string_display_field_degrades_instead_of_halting(field, hostile):
    """The contract's central promise, and it is about the WHOLE run.

    `bake_entry` raising means `publish()` propagates, so one hostile file in one
    app's repository stops EVERY app's release. `(x or "").strip()` looks total
    but is not: falsy values survive while a truthy non-string reaches `.strip()`
    and raises AttributeError. Five fields have that shape, not the three that
    are obvious -- iconUrl and heroImage are the easy ones to miss.
    """
    findings = Findings()
    entry = publish.bake_entry(
        authored(), {**MANIFEST, field: hostile}, "a" * 40, findings
    )
    # Still a publishable entry: identity survives, only the bad field is absent.
    assert entry["name"] == "demo-app"
    assert findings.errors == []


def test_a_hostile_manifest_still_produces_a_schema_valid_document():
    """End-to-end, because type-safety is not schema-safety.

    A `kind` outside the enum and an over-long name are STRINGS, so a type filter
    passes them through; they then fail validation on the assembled document,
    which returns errors for the whole run. Only checking the published schema
    catches that -- `bake_entry` alone cannot see it.
    """
    manifest = {
        **MANIFEST,
        "author": {"name": "x" * 200, "kind": "wizard", "url": "http://insecure"},
        "displayName": {"nope": 1},
        "version": ["1.0"],
    }
    findings = Findings()
    doc = publish.build_registry(
        {"schemaVersion": 1, "apps": [authored(url="https://example.com/a.git")]},
        lambda url, ref: "a" * 40,
        lambda url, c, subdir=None: manifest,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        findings,
    )
    schema_findings = Findings()
    publish.check_schema(
        doc,
        publish.SCHEMA_DIR / "official-registry.schema.json",
        "official-registry.json",
        schema_findings,
    )
    assert schema_findings.errors == [], (
        f"a manifest we do not control halted the publish: {schema_findings.errors}"
    )
    assert "author" not in doc["apps"][0], "schema-illegal author must be dropped"


@pytest.mark.parametrize(
    "value,expected",
    [
        # Dropped unless independently schema-valid, field by field.
        ({"name": "acme", "kind": "wizard"}, {"name": "acme"}),
        ({"name": "acme", "url": "http://x"}, {"name": "acme"}),
        ({"name": "acme", "url": 5}, {"name": "acme"}),
        ({"name": "acme", "kind": "ORG"}, {"name": "acme", "kind": "org"}),
        ({"name": " acme "}, {"name": "acme"}),
        # An over-long name yields nothing rather than a prefix: truncating would
        # publish an attribution to a DIFFERENT name than the one claimed.
        ({"name": "x" * 81}, None),
        ("x" * 81, None),
    ],
)
def test_normalize_author_is_schema_total(value, expected):
    assert publish.normalize_author(value) == expected


# --------------------------------------------------------------------------
# The builtin source type
# --------------------------------------------------------------------------


def test_builtin_publishes_no_fetch_coordinates():
    """`manifestFrom` is publish-time only, like `note`.

    Shipping it would hand a client a clone target for code it already has, which
    is the duplication the type exists to make unrepresentable.
    """
    entry = publish.bake_entry(BUILTIN, MANIFEST, "b" * 40, Findings())
    assert entry["source"] == {"type": "builtin"}
    assert "manifestFrom" not in entry["source"]
    assert "ref" not in entry["source"], "there is no commit to pin: nothing is fetched"
    assert "url" not in entry["source"]


def test_builtin_still_derives_display_fields_from_the_manifest():
    entry = publish.bake_entry(BUILTIN, MANIFEST, "b" * 40, Findings())
    assert entry["displayName"] == "Demo App"
    assert entry["version"] == "1.2.3"
    assert entry["summary"] == "Does the demo thing."


def test_builtin_keeps_minclientversion_but_a_bare_source_is_fine():
    pinned = {
        **BUILTIN,
        "source": {**BUILTIN["source"], "minClientVersion": "0.2.0-nightly.20260806"},
    }
    entry = publish.bake_entry(pinned, MANIFEST, "b" * 40, Findings())
    assert entry["source"] == {
        "type": "builtin",
        "minClientVersion": "0.2.0-nightly.20260806",
    }


def test_builtin_reads_its_manifest_from_manifest_from_not_from_source():
    """A builtin `source` has no url/ref at all, so a resolver reading `source`
    would raise KeyError rather than fetch."""
    seen: list[tuple[str, str, str | None]] = []

    publish.build_registry(
        {"schemaVersion": 1, "apps": [BUILTIN]},
        lambda url, ref: "b" * 40,
        lambda url, commit, subdir=None: seen.append((url, commit, subdir)) or MANIFEST,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        Findings(),
    )
    assert seen == [
        (
            "https://github.com/kirodotdev/KiroCrew.git",
            "b" * 40,
            "src/apps/builtins/demo_app",
        )
    ]


def test_a_builtin_manifest_cannot_claim_the_reserved_author_either():
    """The type is a string a curator types. It is not evidence of anything, and
    trusting it was the first version of this bug."""
    entry, findings = _bake_builtin("kirocrew")
    assert "author" not in entry
    assert any("reserved author" in w for w in findings.warnings)


def test_a_curator_stated_author_is_how_a_builtin_gets_attributed():
    entry, findings = _bake_builtin(
        "kirocrew", curated={"name": "Kiro Crew", "kind": "org"}
    )
    assert entry["author"] == {"name": "Kiro Crew", "kind": "org"}
    assert findings.warnings == []


def _bake_builtin(manifest_author, curated=None):
    """As `_bake`, for a builtin source; the icon is there for the same reason."""
    authored_entry = dict(BUILTIN)
    if curated is not None:
        authored_entry["author"] = curated
    findings = Findings()
    entry = publish.bake_entry(
        authored_entry,
        {
            "name": "demo-app",
            "author": manifest_author,
            "iconUrl": "/app-assets/demo-app/icon.svg",
        },
        "b" * 40,
        findings,
    )
    return entry, findings


# --------------------------------------------------------------------------
# The repo cache
# --------------------------------------------------------------------------


def test_one_fetch_serves_every_subdir_of_the_same_commit(tmp_path, allow_local_urls):
    """The reason the cache exists: 19 built-ins live in ONE monorepo, so a
    per-call fetch would pull it 19 times to read 19 small files."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "--quiet", "-b", "main", ".", cwd=repo)
    for app in ("one", "two"):
        d = repo / "apps" / app
        d.mkdir(parents=True)
        (d / "app.json").write_text(json.dumps({"name": f"app-{app}"}), encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "--quiet", "-m", "init", cwd=repo)
    commit = git("rev-parse", "HEAD", cwd=repo)

    first = publish.fetched_repo(str(repo), commit)
    assert publish.fetch_manifest(str(repo), commit, "apps/one")["name"] == "app-one"
    assert publish.fetch_manifest(str(repo), commit, "apps/two")["name"] == "app-two"
    assert publish.fetched_repo(str(repo), commit) is first, "refetched the same commit"


def test_reset_is_total_even_when_a_cleanup_refuses(tmp_path, allow_local_urls):
    """A cleanup that raises must not leave the cache half-emptied: a partial
    reset reintroduces exactly the cross-test order dependence this prevents."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    publish.fetched_repo(str(repo), commit)

    class Exploding:
        def cleanup(self):
            raise OSError("refuses")

    publish._REPO_CACHE[("x", "y")] = (Path("/nonexistent"), Exploding())
    publish.reset_repo_cache()
    assert publish._REPO_CACHE == {}


def test_a_reaped_checkout_is_evicted_rather_than_handed_back(tmp_path, allow_local_urls):
    """Returning a vanished path would surface as `cannot read app.json` --
    blaming the manifest for an infrastructure loss."""
    repo = tmp_path / "repo"
    commit = make_repo(repo, MANIFEST)
    checkout = publish.fetched_repo(str(repo), commit)
    shutil.rmtree(checkout)

    again = publish.fetched_repo(str(repo), commit)
    assert again.exists() and again != checkout


def test_the_original_error_survives_a_failing_cleanup(tmp_path, allow_local_urls, monkeypatch):
    """`the ref moved during publish` is the diagnosis; an rmtree failure is not.
    A cleanup that raises inside the handler would REPLACE it."""
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    with pytest.raises(publish.PublishError, match="ref moved during publish"):
        publish.fetched_repo(str(repo), "c" * 40)


def test_the_real_launchdarkly_app_is_publishable_but_unattributed():
    """The actual case: the published LaunchDarkly app declares
    `"author": "kirocrew"` while living in launchdarkly-labs. It is listable
    today -- it simply carries no author until its own app.json is corrected."""
    entry, findings = _bake(
        "https://github.com/launchdarkly-labs/launchdarkly-kiro-crew-app",
        "kirocrew",
        name="launchdarkly",
    )
    assert "author" not in entry
    assert findings.errors == []
    assert entry["source"]["ref"] == "0" * 40, "still pinned to the resolved commit"


def test_structured_author_objects_are_checked_too():
    """The dict form must not be a way around the check."""
    entry, _ = _bake(
        "https://github.com/acme-labs/their-app.git",
        {"name": "KiroCrew", "url": "https://crew.kiro.dev", "kind": "org"},
    )
    assert "author" not in entry


def test_canonical_bytes_are_what_gets_signed():
    """A signature over differently-serialized bytes than the file verifies nothing."""
    doc = {"schemaVersion": 1, "apps": []}
    assert publish.canonical_bytes(doc) == (json.dumps(doc, indent=2) + "\n").encode()


def test_canonical_bytes_keep_non_ascii_unescaped():
    """`ensure_ascii=False` is load-bearing, and the assertion above cannot see it.

    Escaping non-ASCII would change the bytes served while every signature is
    taken over the bytes served -- so dropping that argument would produce a
    catalog that fails verification only once an app carries a non-ASCII summary.
    """
    doc = {"schemaVersion": 1, "summary": "日本語"}
    assert publish.canonical_bytes(doc) == (
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    assert "日本語".encode("utf-8") in publish.canonical_bytes(doc)


# --------------------------------------------------------------------------
# End to end: a real repo, a real key, and a signature checked over the bytes
# actually written. The production catalog is empty, so without this the whole
# chain would only ever run in dry-run.
# --------------------------------------------------------------------------


def test_publish_end_to_end_emits_verifiable_signed_artifacts(
    tmp_path, allow_local_urls, monkeypatch
):
    repo = tmp_path / "repo"
    # A real icon committed as real bytes: this is the only place the byte-exact
    # read through `git show` runs for real. It deliberately contains every byte
    # value, which a text-mode read would mangle.
    icon = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (512).to_bytes(4, "big") * 2
    icon += bytes(range(256)) * 2
    manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
    manifest["iconPath"] = "assets/icon.png"
    commit = make_repo(repo, manifest, extra={"assets/icon.png": icon})

    catalog = tmp_path / "catalog"
    catalog.mkdir()
    (catalog / "official-registry.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "apps": [{"name": "demo-app",
                          "source": {"type": "git", "url": str(repo), "ref": "main"}}],
            },
            indent=2,
        )
        + "\n"
    )
    (catalog / "editorial.json").write_text(
        json.dumps({"schemaVersion": 1}, indent=2) + "\n"
    )
    (catalog / "category-order.json").write_text(
        json.dumps({"schemaVersion": 1, "categories": ["dev"]}, indent=2) + "\n"
    )
    monkeypatch.setattr(publish, "CATALOG_DIR", catalog)

    # The authored catalog points at a local repo, which BOTH registry schemas
    # reject (https only). Relax that one recogniser in throwaway copies so the
    # rest of the chain can be exercised for real; every other constraint --
    # including the commit-only `ref` -- still applies.
    relaxed = tmp_path / "schema"
    relaxed.mkdir()
    for name, defname in (
        ("authored-registry.schema.json", "authoredSourceGit"),
        ("official-registry.schema.json", "sourceGit"),
    ):
        schema = json.loads((publish.SCHEMA_DIR / name).read_text())
        url_def = schema["$defs"][defname]["properties"]["url"]
        url_def.pop("pattern", None)
        url_def["minLength"] = 1
        (relaxed / name).write_text(json.dumps(schema))
    # Copied verbatim, unlike the two above: neither carries a url pattern to
    # relax, and the publish step checks both the authored and the published
    # form against them.
    for name in ("editorial.schema.json", "category-order.schema.json"):
        (relaxed / name).write_text((publish.SCHEMA_DIR / name).read_text())

    import validate as validate_mod
    monkeypatch.setattr(validate_mod, "SCHEMA_DIR", relaxed)
    # The published-output check must ALSO use the relaxed copy here, since the
    # emitted url is still the local path.
    monkeypatch.setattr(publish, "SCHEMA_DIR", relaxed)

    kms = FakeKms()
    publish_key(monkeypatch, tmp_path / "keys", kms.public_der())
    out = tmp_path / "dist"
    findings = publish.publish(
        out, dry_run=False, key_id="alias/kirocrew-apps-registry", kms_client=kms
    )
    assert findings.errors == [], findings.errors

    registry = json.loads((out / "official-registry.json").read_text())
    entry = registry["apps"][0]
    assert entry["source"]["ref"] == commit, "must be pinned to the resolved commit"
    assert entry["displayName"] == "Demo App"
    assert entry["summary"] == "Does the demo thing."
    assert entry["author"] == {"name": "Demo Labs"}
    assert registry["revision"].endswith(
        publish.content_digest(
            {"apps": registry["apps"], "removed": [], "reinstated": []}
        )[:7]
    )

    # Verify each signature over the exact bytes on disk.
    for name in ("official-registry.json", "editorial.json"):
        payload = (out / name).read_bytes()
        sidecar = json.loads((out / f"{name}.sig").read_text())
        assert sidecar["payloadSha256"] == hashlib.sha256(payload).hexdigest()
        verify_rsa(kms.public_der(), base64.b64decode(sidecar["signature"]), payload)

    # The icon was INGESTED: the entry names a path under our own root, the file
    # is on disk byte-for-byte, and its name is the digest of those bytes.
    digest = hashlib.sha256(icon).hexdigest()
    assert entry["iconRef"] == f"assets/icons/{digest}.png"
    hosted = out / entry["iconRef"]
    assert hosted.read_bytes() == icon, "a text-mode read would corrupt these bytes"
    # No sidecar of its own: integrity rides on the digest in the filename, which
    # lives inside the registry document that IS signed. One signature, every
    # icon covered -- and a client checks an icon by hashing what it downloaded.
    assert not (out / f"{entry['iconRef']}.sig").exists()


# ---------------------------------------------------------------------------
# The catalog HOSTS icon bytes
# ---------------------------------------------------------------------------
#
# Before this, a third-party icon stayed in the publisher's repository and every
# client fetched it by cloning that repository through a proxy: one shallow clone
# per uncached image, no byte cap, a cache keyed on a moving branch, and a grid
# that broke when a repo was renamed or made private. Hosting the bytes takes the
# publisher's infrastructure out of the render path.


def png_bytes(width: int, height: int, filler: bytes = b"\x00" * 32) -> bytes:
    """A byte string with a REAL PNG header. Only the header is ever parsed."""
    ihdr = width.to_bytes(4, "big") + height.to_bytes(4, "big")
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\r" + b"IHDR" + ihdr + filler


def reader_for(files: dict[str, bytes]):
    def read(url: str, commit: str, path: str) -> bytes:
        if path not in files:
            raise publish.PublishError(f"cannot read {path}")
        return files[path]

    return read


class TestIconIngestion:
    def test_stores_bytes_under_their_own_digest(self):
        data = png_bytes(512, 512)
        assets = publish.IconAssets(reader_for({"a/i.png": data}))
        findings = Findings()
        ref = assets.add("https://x/y.git", "a" * 40, "a/i.png", "demo", findings)
        digest = hashlib.sha256(data).hexdigest()
        assert ref == f"assets/icons/{digest}.png"
        assert assets.files[ref] == data
        assert findings.warnings == []

    def test_the_digest_in_the_path_is_the_digest_of_the_bytes(self):
        """This is the whole integrity story: the path is inside the SIGNED
        document, so a client hashing the file it downloaded against its own path
        gets end-to-end integrity from one signature over one document."""
        data = png_bytes(512, 512, b"\x11" * 64)
        assets = publish.IconAssets(reader_for({"i.png": data}))
        ref = assets.add("https://x/y.git", "a" * 40, "i.png", "demo", Findings())
        assert Path(ref).stem == hashlib.sha256(assets.files[ref]).hexdigest()

    def test_identical_bytes_converge_on_one_file(self):
        data = png_bytes(512, 512)
        assets = publish.IconAssets(reader_for({"one.png": data, "two.png": data}))
        findings = Findings()
        first = assets.add("https://x/y.git", "a" * 40, "one.png", "app-one", findings)
        second = assets.add("https://x/y.git", "a" * 40, "two.png", "app-two", findings)
        assert first == second
        assert len(assets.files) == 1

    @pytest.mark.parametrize("path", ["i.exe", "i.html", "i.gif", "i", "i.PNG.txt"])
    def test_refuses_a_type_the_catalog_will_not_host(self, path):
        assets = publish.IconAssets(reader_for({path: png_bytes(512, 512)}))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, path, "demo", findings) is None
        assert assets.files == {}
        assert any("does not host" in w for w in findings.warnings)

    def test_refuses_an_oversized_icon(self):
        big = png_bytes(512, 512, b"\x00" * (publish.ICON_MAX_BYTES + 1))
        assets = publish.IconAssets(reader_for({"i.png": big}))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings) is None
        assert any("over the" in w for w in findings.warnings)

    def test_refuses_an_empty_icon(self):
        assets = publish.IconAssets(reader_for({"i.png": b""}))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings) is None
        assert any("is empty" in w for w in findings.warnings)

    def test_an_unreadable_icon_warns_rather_than_raising(self):
        """One missing file must not halt every other app's release."""
        assets = publish.IconAssets(reader_for({}))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings) is None
        assert findings.errors == []
        assert any("cannot read icon" in w for w in findings.warnings)

    @pytest.mark.parametrize(
        "svg",
        [
            b"<svg><script>alert(1)</script></svg>",
            b"<svg:svg><svg:script>alert(1)</svg:script></svg:svg>",  # namespace prefix
            "<svg><script>alert(1)</script></svg>".encode("utf-16-le"),  # NUL-interleaved
            b'<svg><a href="&#106;avascript:alert(1)">x</a></svg>',  # entity-encoded scheme
            b'<svg onload="alert(1)"></svg>',
            b"<svg><foreignObject><body/></foreignObject></svg>",
            b'<svg viewBox="0 0 24 24"><path d="M1 1h22v22H1z"/></svg>',  # entirely benign
        ],
    )
    def test_svg_is_not_hosted_at_all(self, svg):
        """Raster only, and that is a DECISION rather than an omission.

        An earlier revision screened SVG text with a regex. Review defeated it
        three separate ways -- a namespace prefix, a UTF-16 encoding whose ASCII
        pattern never matches across interleaved NULs, and an entity-encoded
        scheme in an href. Each is individually fixable and the next one is not:
        a regex over untrusted XML loses to the parser that actually matters,
        which is the browser's. So the capability is gone, not patched -- note
        the benign case is refused too, which is what makes this a rule rather
        than a filter.
        """
        assets = publish.IconAssets(reader_for({"i.svg": svg}))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.svg", "demo", findings) is None
        assert assets.files == {}
        assert any("does not host" in w for w in findings.warnings)

    def test_dimension_check_is_skipped_for_formats_it_cannot_measure(self):
        """`png_dimensions` reads a PNG header; a webp has none to read, so the
        shape advice is skipped rather than guessed at."""
        assets = publish.IconAssets(reader_for({"i.webp": b"RIFF....WEBPVP8 "}))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.webp", "demo", findings)
        assert findings.warnings == []

    def test_the_cap_is_checked_before_the_bytes_are_read(self):
        """The read buffers the whole object, so a cap applied afterwards never
        fires on the input it exists for: a repository could hand the publisher a
        multi-gigabyte file and kill the run before the check it would fail."""
        reads = []

        def reader(url, commit, path):
            reads.append(path)
            return b"never reached"

        assets = publish.IconAssets(reader, lambda u, c, p: publish.ICON_MAX_BYTES + 1)
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings) is None
        assert reads == [], "the oversized object must not be read"
        assert any("over the" in w for w in findings.warnings)

    def test_a_size_probe_failure_warns_rather_than_raising(self):
        def sizer(url, commit, path):
            raise publish.PublishError("no such object")

        assets = publish.IconAssets(reader_for({"i.png": png_bytes(512, 512)}), sizer)
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings) is None
        assert findings.errors == []
        assert any("cannot size icon" in w for w in findings.warnings)

    def test_a_within_cap_size_probe_lets_the_read_proceed(self):
        data = png_bytes(512, 512)
        assets = publish.IconAssets(reader_for({"i.png": data}), lambda u, c, p: len(data))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings)
        assert findings.warnings == []

    def test_a_non_square_png_is_published_with_a_warning(self):
        """Shape is advice, not a gate: a card with a slightly wrong aspect beats
        a card with no icon."""
        assets = publish.IconAssets(reader_for({"i.png": png_bytes(512, 256)}))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings)
        assert any("not square" in w for w in findings.warnings)

    def test_a_small_square_png_warns_about_the_floor(self):
        assets = publish.IconAssets(reader_for({"i.png": png_bytes(64, 64)}))
        findings = Findings()
        assert assets.add("https://x/y.git", "a" * 40, "i.png", "demo", findings)
        assert any("floor" in w for w in findings.warnings)

    def test_png_dimensions_returns_none_for_anything_else(self):
        assert publish.png_dimensions(b"not a png") is None
        assert publish.png_dimensions(b"") is None
        assert publish.png_dimensions(b"\x89PNG\r\n\x1a\n" + b"\x00" * 4) is None


class TestBakeEntryHostsFetchedIcons:
    def test_a_fetched_icon_becomes_a_hosted_path(self):
        data = png_bytes(512, 512)
        assets = publish.IconAssets(reader_for({"assets/icon.png": data}))
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        manifest["iconPath"] = "assets/icon.png"
        entry = publish.bake_entry(authored(), manifest, "a" * 40, Findings(), assets)
        assert entry["iconRef"] == f"assets/icons/{hashlib.sha256(data).hexdigest()}.png"
        assert assets.files

    def test_a_builtin_icon_is_not_ingested(self):
        """The client already ships those bytes. Hosting a second copy would add
        download weight and a second source of truth."""
        assets = publish.IconAssets(reader_for({}))
        entry = publish.bake_entry(BUILTIN, MANIFEST, "b" * 40, Findings(), assets)
        assert entry["iconRef"] == "/app-assets/demo-app/icon.svg"
        assert assets.files == {}

    def test_a_refused_icon_leaves_the_field_off_the_entry(self):
        """Not an empty string: a falsy ref is still a key every client has to
        special-case."""
        assets = publish.IconAssets(reader_for({}))
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        manifest["iconPath"] = "assets/missing.png"
        entry = publish.bake_entry(authored(), manifest, "a" * 40, Findings(), assets)
        assert "iconRef" not in entry

    def test_both_appearances_are_ingested(self):
        light = png_bytes(512, 512, b"\x01" * 32)
        dark = png_bytes(512, 512, b"\x02" * 32)
        assets = publish.IconAssets(reader_for({"i.png": light, "i-dark.png": dark}))
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        manifest["iconPath"] = "i.png"
        manifest["iconPathDark"] = "i-dark.png"
        entry = publish.bake_entry(authored(), manifest, "a" * 40, Findings(), assets)
        assert entry["iconRef"] != entry["iconRefDark"]
        assert len(assets.files) == 2


def hero_manifest(**over):
    """A git-source manifest naming a repo-relative hero and no absolute keys."""
    manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
    manifest["heroImage"] = "assets/hero.png"
    manifest.update(over)
    return manifest


class TestHeroIngestion:
    """A hero is ingested exactly like an icon, under the WIDE-ART policy.

    Same source (a blob in a repo we do not control) and same content-addressed
    naming, but a 16:9 banner is not a 512px tile: it gets the `ART_*` ceiling,
    because the icon ceiling rejects an ordinary hero, and it gets no squareness
    advice, because that would fire on every correct one.
    """

    def test_a_hero_becomes_a_content_addressed_path(self):
        data = png_bytes(1600, 900)
        heroes = publish.HeroAssets(reader_for({"assets/hero.png": data}))
        findings = Findings()
        ref = heroes.add("https://x/y.git", "a" * 40, "assets/hero.png", "demo", findings)
        assert ref == f"assets/heroes/{hashlib.sha256(data).hexdigest()}.png"
        assert heroes.files[ref] == data
        assert findings.warnings == []

    def test_heroes_land_in_their_own_directory(self):
        """Identical bytes published as both kinds must not collide. A shared pool
        would make `assets/icons/` a lie and defeat listing either kind alone."""
        data = png_bytes(512, 512)
        icon_ref = publish.IconAssets(reader_for({"i.png": data})).add(
            "https://x/y.git", "a" * 40, "i.png", "demo", Findings()
        )
        hero_ref = publish.HeroAssets(reader_for({"i.png": data})).add(
            "https://x/y.git", "a" * 40, "i.png", "demo", Findings()
        )
        assert icon_ref is not None and hero_ref is not None
        assert icon_ref.startswith("assets/icons/")
        assert hero_ref.startswith("assets/heroes/")
        assert Path(icon_ref).name == Path(hero_ref).name

    def test_refuses_an_svg_hero(self):
        """The live catalog shipped one: an SVG is a document, not pixels, and we
        serve what we host from our OWN origin. Raster only, same as icons."""
        heroes = publish.HeroAssets(reader_for({"h.svg": b"<svg/>"}))
        findings = Findings()
        assert heroes.add("https://x/y.git", "a" * 40, "h.svg", "demo", findings) is None
        assert heroes.files == {}
        assert any("does not host" in w for w in findings.warnings)

    def test_takes_the_wide_art_ceiling_not_the_icon_one(self):
        """A hero between the two limits must publish. Reusing `IconAssets` would
        have refused an ordinary banner for being over a 512px tile's budget."""
        assert publish.ICON_MAX_BYTES < publish.ART_MAX_BYTES
        data = png_bytes(1600, 900, b"\x00" * (publish.ICON_MAX_BYTES + 1))
        assert publish.ICON_MAX_BYTES < len(data) <= publish.ART_MAX_BYTES
        heroes = publish.HeroAssets(reader_for({"h.png": data}))
        findings = Findings()
        assert heroes.add("https://x/y.git", "a" * 40, "h.png", "demo", findings) is not None
        assert findings.warnings == []

    def test_refuses_a_hero_over_the_wide_art_ceiling(self):
        big = png_bytes(1600, 900, b"\x00" * (publish.ART_MAX_BYTES + 1))
        heroes = publish.HeroAssets(reader_for({"h.png": big}))
        findings = Findings()
        assert heroes.add("https://x/y.git", "a" * 40, "h.png", "demo", findings) is None
        assert any("over the" in w for w in findings.warnings)

    def test_an_off_aspect_hero_is_advised_but_still_published(self):
        """A crop is a curation nit; only type and bytes may withhold an image."""
        heroes = publish.HeroAssets(reader_for({"h.png": png_bytes(900, 900)}))
        findings = Findings()
        ref = heroes.add("https://x/y.git", "a" * 40, "h.png", "demo", findings)
        assert ref is not None
        assert any("16:9" in w for w in findings.warnings)

    def test_a_square_hero_is_not_judged_by_the_icon_rules(self):
        """`IconAssets` would call 1600x900 "not square". Wrong advice for a hero."""
        heroes = publish.HeroAssets(reader_for({"h.png": png_bytes(1600, 900)}))
        findings = Findings()
        heroes.add("https://x/y.git", "a" * 40, "h.png", "demo", findings)
        assert not any("square" in w for w in findings.warnings)


class TestBakeEntryHostsFetchedHeroes:
    """`heroRef` goes through validate-then-ingest, which it did not before.

    It used to be a bare `manifest_str(manifest, "heroImage")` copied straight
    into a document we SIGN -- unscreened, un-ingested, and with no `pattern` on
    the field in the published schema to catch it downstream either.
    """

    def test_a_fetched_hero_becomes_a_hosted_path(self):
        """The defect this closes. Published repo-relative, a hero resolved
        against the CATALOG root onto a file only the app's repo had, so every
        third-party hero was a guaranteed miss on a plausible-looking path."""
        data = png_bytes(1600, 900)
        heroes = publish.HeroAssets(reader_for({"assets/hero.png": data}))
        entry = publish.bake_entry(
            authored(), hero_manifest(), "a" * 40, Findings(), None, heroes
        )
        assert entry["heroRef"] == f"assets/heroes/{hashlib.sha256(data).hexdigest()}.png"
        assert heroes.files

    def test_a_builtin_hero_is_published_as_is(self):
        """Absolute is correct for a builtin, and the client ships those bytes."""
        heroes = publish.HeroAssets(reader_for({}))
        entry = publish.bake_entry(BUILTIN, MANIFEST, "b" * 40, Findings(), None, heroes)
        assert entry["heroRef"] == "/app-assets/demo-app/hero.svg"
        assert heroes.files == {}

    def test_a_git_source_may_not_name_an_absolute_hero(self):
        """The rule icons already had: honouring an absolute value from a manifest
        we do not control would let a publisher put a host of their choosing into
        a document we sign."""
        findings = Findings()
        entry = publish.bake_entry(
            authored(),
            hero_manifest(heroImage="/app-assets/demo-app/hero.svg"),
            "a" * 40,
            findings,
        )
        assert "heroRef" not in entry
        assert any("not a repo-relative path" in w for w in findings.warnings)

    @pytest.mark.parametrize(
        "value",
        [
            "https://evil.example/pixel.png",
            "//evil.example/pixel.png",
            "javascript:alert(1)",
            "data:image/svg+xml,<svg/>",
            "../../etc/passwd",
            "assets/../../secret.png",
        ],
    )
    def test_a_hero_that_is_not_a_path_is_dropped(self, value):
        """Every one of these used to reach the signed document verbatim."""
        findings = Findings()
        entry = publish.bake_entry(
            authored(), hero_manifest(heroImage=value), "a" * 40, findings
        )
        assert "heroRef" not in entry
        assert findings.warnings

    def test_a_refused_hero_leaves_the_field_off_the_entry(self):
        """Dropped, NOT left repo-relative. Keeping the authored path would
        publish a ref that cannot load; no hero is just a card with no banner."""
        heroes = publish.HeroAssets(reader_for({}))
        entry = publish.bake_entry(
            authored(), hero_manifest(), "a" * 40, Findings(), None, heroes
        )
        assert "heroRef" not in entry

    def test_an_over_long_hero_ref_is_dropped(self):
        findings = Findings()
        entry = publish.bake_entry(
            authored(),
            hero_manifest(heroImage="a/" + "b" * publish.ASSET_REF_MAX + ".png"),
            "a" * 40,
            findings,
        )
        assert "heroRef" not in entry
        assert any("not a publishable path" in w for w in findings.warnings)


class TestBakeEntryHostsDetailHeroes:
    """`heroDetailRef` was published by NOTHING before, so an app's detail banner
    could never reach the store however correctly its manifest declared one."""

    def test_a_detail_hero_becomes_a_hosted_path(self):
        data = png_bytes(2500, 600)
        details = publish.HeroDetailAssets(reader_for({"assets/detail.png": data}))
        entry = publish.bake_entry(
            authored(),
            hero_manifest(heroImageDetail="assets/detail.png"),
            "a" * 40,
            Findings(),
            None,
            None,
            details,
        )
        digest = hashlib.sha256(data).hexdigest()
        assert entry["heroDetailRef"] == f"assets/hero-details/{digest}.png"

    def test_the_detail_hero_is_judged_at_25_by_6(self):
        """Not 16:9. The two are different crops, so the hero's advice would be
        wrong here and would fire on every correct detail banner."""
        details = publish.HeroDetailAssets(reader_for({"d.png": png_bytes(2500, 600)}))
        findings = Findings()
        details.add("https://x/y.git", "a" * 40, "d.png", "demo", findings)
        assert findings.warnings == []

        off = publish.HeroDetailAssets(reader_for({"d.png": png_bytes(1600, 900)}))
        findings = Findings()
        off.add("https://x/y.git", "a" * 40, "d.png", "demo", findings)
        assert any("25:6" in w for w in findings.warnings)

    def test_a_detail_hero_does_not_share_the_hero_directory(self):
        """Different aspect, so one is not a substitute for the other and a shared
        pool would make either directory's name a lie."""
        data = png_bytes(1600, 900)
        hero = publish.HeroAssets(reader_for({"x.png": data})).add(
            "https://x/y.git", "a" * 40, "x.png", "demo", Findings()
        )
        detail = publish.HeroDetailAssets(reader_for({"x.png": data})).add(
            "https://x/y.git", "a" * 40, "x.png", "demo", Findings()
        )
        assert hero is not None and detail is not None
        assert hero.startswith("assets/heroes/")
        assert detail.startswith("assets/hero-details/")


class TestBakeEntryHostsScreenshots:
    """`screenshotRefs` was published by nothing either, and it is the one field
    whose declared TYPE is a list -- which is where an untrusted manifest bites.
    """

    def shots_for(self, files):
        return publish.ScreenshotAssets(reader_for(files))

    def test_screenshots_become_hosted_paths_in_order(self):
        one, two = png_bytes(1200, 800, b"\x01" * 32), png_bytes(1200, 800, b"\x02" * 32)
        shots = self.shots_for({"a.png": one, "b.png": two})
        entry = publish.bake_entry(
            authored(),
            hero_manifest(screenshots=["a.png", "b.png"]),
            "a" * 40,
            Findings(),
            None,
            None,
            None,
            shots,
        )
        assert entry["screenshotRefs"] == [
            f"assets/screenshots/{hashlib.sha256(one).hexdigest()}.png",
            f"assets/screenshots/{hashlib.sha256(two).hexdigest()}.png",
        ], "the detail page shows them in the order the manifest declared"

    def test_a_screenshot_has_no_aspect_advice(self):
        """A screenshot is whatever shape the app's window is; the store scrolls
        them rather than seating them in a fixed frame."""
        shots = self.shots_for({"s.png": png_bytes(700, 1500)})
        findings = Findings()
        assert shots.add("https://x/y.git", "a" * 40, "s.png", "demo", findings)
        assert findings.warnings == []

    @pytest.mark.parametrize("value", [{}, "one.png", 7, True])
    def test_a_screenshots_field_that_is_not_a_list_is_refused(self, value):
        """Every one of these used to be impossible to publish at all; now the
        container's TYPE is checked before it is iterated. A bare string matters
        most: Python would iterate it per CHARACTER and publish an app's gallery
        as the letters of a filename."""
        findings = Findings()
        entry = publish.bake_entry(
            authored(), hero_manifest(screenshots=value), "a" * 40, findings
        )
        assert "screenshotRefs" not in entry
        assert any("not a list" in w for w in findings.warnings)

    @pytest.mark.parametrize("bad", [{}, None, 7, "", "   ", []])
    def test_one_unusable_element_does_not_take_the_others(self, bad):
        """A naive `for s in value: s.startswith(...)` raises on a dict or an int
        and ends the whole publish over an optional field."""
        data = png_bytes(1200, 800)
        shots = self.shots_for({"ok.png": data})
        findings = Findings()
        entry = publish.bake_entry(
            authored(),
            hero_manifest(screenshots=[bad, "ok.png"]),
            "a" * 40,
            findings,
            None,
            None,
            None,
            shots,
        )
        assert entry["screenshotRefs"] == [
            f"assets/screenshots/{hashlib.sha256(data).hexdigest()}.png"
        ]
        assert findings.warnings

    @pytest.mark.parametrize(
        "value",
        [
            "https://evil.example/shot.png",
            "//evil.example/shot.png",
            "javascript:alert(1)",
            "../../etc/passwd",
            "/app-assets/demo-app/shot.png",
        ],
    )
    def test_an_element_that_is_not_a_repo_relative_path_is_dropped(self, value):
        findings = Findings()
        entry = publish.bake_entry(
            authored(), hero_manifest(screenshots=[value]), "a" * 40, findings
        )
        assert "screenshotRefs" not in entry
        assert findings.warnings

    def test_the_count_is_capped(self):
        """Each entry is a blob read now and a hosted file forever, so an uncapped
        list lets one manifest set the cost of everyone's release."""
        limit = publish.SCREENSHOT_MAX_COUNT
        names = [f"s{i}.png" for i in range(limit + 4)]
        files = {n: png_bytes(1200, 800, bytes([i % 251]) * 32) for i, n in enumerate(names)}
        findings = Findings()
        entry = publish.bake_entry(
            authored(),
            hero_manifest(screenshots=names),
            "a" * 40,
            findings,
            None,
            None,
            None,
            self.shots_for(files),
        )
        assert len(entry["screenshotRefs"]) == limit
        assert any("over the" in w for w in findings.warnings)

    def test_the_cap_bounds_the_SCAN_not_only_what_survives_it(self):
        """The bound has to hold when NOTHING is accepted. Capping accepted entries
        alone left the loop running to the end of a hostile list and formatting one
        warning per element, so a million declared entries meant a million retained
        strings -- the cap could not fire, because nothing was ever accepted."""
        limit = publish.SCREENSHOT_MAX_COUNT
        findings = Findings()
        entry = publish.bake_entry(
            authored(),
            # Every element invalid, so `refs` never grows.
            hero_manifest(screenshots=[{} for _ in range(5000)]),
            "a" * 40,
            findings,
        )
        assert "screenshotRefs" not in entry
        # Count only the diagnostics THIS field produced: the fixture declares no
        # icon, so an unfiltered count folds in an unrelated warning and stops
        # discriminating. One per element READ plus the one over-limit notice --
        # bounded by the cap, not by how long the manifest is.
        mine = [w for w in findings.warnings if "screenshots[" in w or "screenshots " in w]
        assert len(mine) <= limit + 1, mine[:3]
        assert any("only the first" in w for w in findings.warnings)

    def test_duplicate_declarations_collapse(self):
        """So the count against the cap is a count of distinct pictures."""
        findings = Findings()
        entry = publish.bake_entry(
            authored(),
            hero_manifest(screenshots=["a.png", "a.png", "a.png"]),
            "a" * 40,
            findings,
            None,
            None,
            None,
            self.shots_for({"a.png": png_bytes(1200, 800)}),
        )
        assert len(entry["screenshotRefs"]) == 1

    def test_no_surviving_screenshot_leaves_the_field_off(self):
        """Not an empty array: absent and empty read the same to a client, and the
        absent one is honest about there being no gallery."""
        entry = publish.bake_entry(
            authored(),
            hero_manifest(screenshots=["gone.png"]),
            "a" * 40,
            Findings(),
            None,
            None,
            None,
            self.shots_for({}),
        )
        assert "screenshotRefs" not in entry

    def test_an_svg_screenshot_is_refused(self):
        findings = Findings()
        entry = publish.bake_entry(
            authored(),
            hero_manifest(screenshots=["s.svg"]),
            "a" * 40,
            findings,
            None,
            None,
            None,
            self.shots_for({"s.svg": b"<svg/>"}),
        )
        assert "screenshotRefs" not in entry
        assert any("does not host" in w for w in findings.warnings)

    def test_screenshots_do_not_share_a_directory_with_the_heroes(self):
        data = png_bytes(1200, 800)
        shot = self.shots_for({"x.png": data}).add(
            "https://x/y.git", "a" * 40, "x.png", "demo", Findings()
        )
        assert shot is not None and shot.startswith("assets/screenshots/")


# ---------------------------------------------------------------------------
# verify_dist closes the last link of the integrity chain
# ---------------------------------------------------------------------------
#
# An icon carries no signature. Its integrity rides on being content-addressed:
# the filename IS the sha256 of the bytes, and that filename lives in the signed
# registry document. So the chain is signature -> document -> path -> bytes, and
# verify_dist is both the pre-upload gate for the last link and the reference
# implementation of what a client must do after downloading an icon.


def dist_with_icon(tmp_path, ref: str, data: bytes, on_disk: bytes | None = None):
    """A dist dir holding one entry naming *ref*, with *on_disk* bytes stored."""
    dist = tmp_path / "dist"
    (dist / "assets" / "icons").mkdir(parents=True)
    (dist / "official-registry.json").write_text(
        json.dumps({"schemaVersion": 1, "apps": [{"name": "demo-app", "iconRef": ref}]})
    )
    if on_disk is not None:
        (dist / ref).write_bytes(on_disk)
    return dist


def test_verify_dist_accepts_a_matching_icon_digest(tmp_path):
    from verify_dist import verify_hosted_entry_images

    data = b"\x89PNG\r\n\x1a\nwhatever"
    ref = f"assets/icons/{hashlib.sha256(data).hexdigest()}.png"
    assert verify_hosted_entry_images(dist_with_icon(tmp_path, ref, data, data)) == []


def test_verify_dist_catches_bytes_that_do_not_match_their_digest(tmp_path):
    """The case the whole scheme exists to catch: a document naming one digest
    while the served bytes are something else. Undetectable to a client that
    skips this check, which is why it is code and not a sentence in the schema."""
    from verify_dist import verify_hosted_entry_images

    honest = b"\x89PNG\r\n\x1a\nhonest"
    ref = f"assets/icons/{hashlib.sha256(honest).hexdigest()}.png"
    problems = verify_hosted_entry_images(dist_with_icon(tmp_path, ref, honest, b"swapped"))
    assert len(problems) == 1
    assert "bytes hash to" in problems[0]


def test_verify_dist_catches_a_missing_icon(tmp_path):
    from verify_dist import verify_hosted_entry_images

    data = b"\x89PNG\r\n\x1a\ngone"
    ref = f"assets/icons/{hashlib.sha256(data).hexdigest()}.png"
    problems = verify_hosted_entry_images(dist_with_icon(tmp_path, ref, data, None))
    assert len(problems) == 1
    assert "is not in" in problems[0]


def test_verify_dist_ignores_a_builtin_client_local_ref(tmp_path):
    """Those bytes ship with the client, so there is nothing in dist to check."""
    from verify_dist import verify_hosted_entry_images

    dist = dist_with_icon(tmp_path, "/app-assets/demo-app/icon.svg", b"", None)
    assert verify_hosted_entry_images(dist) == []


def test_verify_dist_is_quiet_when_there_is_no_registry(tmp_path):
    from verify_dist import verify_hosted_entry_images

    (tmp_path / "empty").mkdir()
    assert verify_hosted_entry_images(tmp_path / "empty") == []


def dist_with_hero(tmp_path, ref: str, on_disk: bytes | None = None):
    """A dist dir holding one entry whose `heroRef` is *ref*."""
    dist = tmp_path / "dist"
    (dist / "assets" / "heroes").mkdir(parents=True)
    (dist / "official-registry.json").write_text(
        json.dumps({"schemaVersion": 1, "apps": [{"name": "demo-app", "heroRef": ref}]})
    )
    if on_disk is not None:
        (dist / ref).write_bytes(on_disk)
    return dist


def test_verify_dist_checks_a_hero_digest_too(tmp_path):
    """A hero's integrity story is the icon's, so it gets the icon's check. It was
    outside this pass entirely while the field went un-ingested."""
    from verify_dist import verify_hosted_entry_images

    data = b"\x89PNG\r\n\x1a\nhero"
    ref = f"assets/heroes/{hashlib.sha256(data).hexdigest()}.png"
    assert verify_hosted_entry_images(dist_with_hero(tmp_path, ref, data)) == []
    problems = verify_hosted_entry_images(dist_with_hero(tmp_path / "b", ref, b"swapped"))
    assert len(problems) == 1 and "bytes hash to" in problems[0]


def test_verify_dist_catches_a_hero_the_ingest_step_skipped(tmp_path):
    """A repo-relative ref in the OUTPUT means the bake ran without an ingester.
    Such a ref resolves against the catalog root onto a file only the app's
    repository has, so it can never load -- exactly what shipped, and nothing
    downstream said so. Same rule the editorial pass already applies."""
    from verify_dist import verify_hosted_entry_images

    problems = verify_hosted_entry_images(dist_with_hero(tmp_path, "assets/hero.webp"))
    assert len(problems) == 1
    assert "the ingest step did not run" in problems[0]


def test_verify_dist_catches_an_icon_the_ingest_step_skipped(tmp_path):
    """The same hole existed for icons: a non-hosted relative ref was skipped
    silently rather than reported."""
    from verify_dist import verify_hosted_entry_images

    problems = verify_hosted_entry_images(dist_with_icon(tmp_path, "assets/icon.png", b""))
    assert len(problems) == 1
    assert "the ingest step did not run" in problems[0]


def dist_with_detail_hero(tmp_path, ref: str, on_disk: bytes | None = None):
    """A dist dir holding one entry whose `heroDetailRef` is *ref*."""
    dist = tmp_path / "dist"
    (dist / "assets" / "hero-details").mkdir(parents=True)
    (dist / "official-registry.json").write_text(
        json.dumps(
            {"schemaVersion": 1, "apps": [{"name": "demo-app", "heroDetailRef": ref}]}
        )
    )
    if on_disk is not None:
        (dist / ref).write_bytes(on_disk)
    return dist


def test_verify_dist_checks_the_detail_hero_digest(tmp_path):
    """Its own field and its own directory, so it needs its own row in the table --
    a hero that is verified says nothing about a detail hero that is not."""
    from verify_dist import verify_hosted_entry_images

    data = b"\x89PNGdetail"
    ref = f"assets/hero-details/{hashlib.sha256(data).hexdigest()}.png"
    assert verify_hosted_entry_images(dist_with_detail_hero(tmp_path, ref, data)) == []
    problems = verify_hosted_entry_images(
        dist_with_detail_hero(tmp_path / "b", ref, b"swapped")
    )
    assert len(problems) == 1 and "bytes hash to" in problems[0]


def test_verify_dist_catches_a_detail_hero_the_ingest_step_skipped(tmp_path):
    from verify_dist import verify_hosted_entry_images

    problems = verify_hosted_entry_images(
        dist_with_detail_hero(tmp_path, "assets/detail.png")
    )
    assert len(problems) == 1
    assert "the ingest step did not run" in problems[0]


def dist_with_screenshots(tmp_path, refs, files=()):
    """A dist dir holding one entry whose `screenshotRefs` is *refs*."""
    dist = tmp_path / "dist"
    (dist / "assets" / "screenshots").mkdir(parents=True)
    (dist / "official-registry.json").write_text(
        json.dumps(
            {"schemaVersion": 1, "apps": [{"name": "demo-app", "screenshotRefs": refs}]}
        )
    )
    for ref, data in files:
        (dist / ref).write_bytes(data)
    return dist


def test_verify_dist_checks_every_screenshot(tmp_path):
    """Element by element: one bad entry in an otherwise good gallery has to be
    named, and its INDEX has to be in the message or nobody can find it."""
    from verify_dist import verify_hosted_entry_images

    good, bad = b"\x89PNGgood", b"\x89PNGbad"
    good_ref = f"assets/screenshots/{hashlib.sha256(good).hexdigest()}.png"
    bad_ref = f"assets/screenshots/{hashlib.sha256(bad).hexdigest()}.png"
    dist = dist_with_screenshots(
        tmp_path, [good_ref, bad_ref], [(good_ref, good), (bad_ref, b"swapped")]
    )
    problems = verify_hosted_entry_images(dist)
    assert len(problems) == 1
    assert "screenshotRefs[1]" in problems[0] and "bytes hash to" in problems[0]


def test_verify_dist_catches_a_screenshot_the_ingest_step_skipped(tmp_path):
    from verify_dist import verify_hosted_entry_images

    problems = verify_hosted_entry_images(
        dist_with_screenshots(tmp_path, ["assets/shots/one.png"])
    )
    assert len(problems) == 1
    assert "the ingest step did not run" in problems[0]


def test_verify_dist_reports_a_screenshot_field_that_is_not_a_list(tmp_path):
    """Reported rather than crashing the verifier on `.  __iter__`: this runs as
    the last gate before upload, so it must survive a malformed document."""
    from verify_dist import verify_hosted_entry_images

    problems = verify_hosted_entry_images(
        dist_with_screenshots(tmp_path, {"a": "assets/screenshots/x.png"})
    )
    assert len(problems) == 1
    assert "not a list" in problems[0]


# ---------------------------------------------------------------------------
# publish and the schema must enforce the SAME asset-ref rule
# ---------------------------------------------------------------------------
#
# A value publish accepts and the schema rejects does not degrade one field: it
# reaches check_schema on the ASSEMBLED document, and those errors withhold the
# ENTIRE catalog publish. So one app's odd icon path would block every other
# app's release -- the opposite of the totality rule every other baked field
# follows. Pinning the two together is the fix; patching individual cases is not.


def test_publish_and_schema_agree_on_the_asset_ref_rule():
    schema = json.loads(
        (publish.SCHEMA_DIR / "official-registry.schema.json").read_text(encoding="utf-8")
    )
    props = schema["$defs"]["entry"]["properties"]
    # `heroRef` is in this list now. It used to be a bare `{"type": "string"}`,
    # so the ONLY thing standing between an untrusted manifest and a signed
    # document naming any host was each client re-validating what we had already
    # signed. Tightening the schema is only safe because `bake_entry` now drops a
    # value this pattern would reject: a value publish emits and the schema
    # refuses fails `check_schema` on the ASSEMBLED document, which withholds the
    # whole catalog -- one app's odd path blocking every other app's release.
    for field in ("iconRef", "iconRefDark", "heroRef", "heroDetailRef"):
        assert props[field]["pattern"] == publish.ASSET_REF_PATTERN, field
        assert props[field]["maxLength"] == publish.ASSET_REF_MAX, field
    # The list-valued field carries the rule on its ITEMS, and its cap has to be
    # the one publish enforces -- a schema that allowed more than publish emits
    # would be dead slack, and one that allowed fewer would fail `check_schema` on
    # the assembled document and withhold the whole catalog.
    shots = props["screenshotRefs"]
    assert shots["items"]["pattern"] == publish.ASSET_REF_PATTERN
    assert shots["items"]["maxLength"] == publish.ASSET_REF_MAX
    assert shots["maxItems"] == publish.SCREENSHOT_MAX_COUNT


class TestAssetRefRuleMatchesTheSchema:
    """Values that pass publish must also pass the published schema."""

    @pytest.mark.parametrize(
        "value",
        [
            "//app-assets/x.svg",  # looks absolute, is protocol-relative
            "///app-assets/x.svg",
            "/" + "a" * publish.ASSET_REF_MAX + ".svg",  # over maxLength
        ],
    )
    def test_builtin_refs_the_schema_would_reject_are_refused(self, value):
        findings = Findings()
        entry = publish.bake_entry(
            BUILTIN, {**MANIFEST, "iconUrl": value}, "b" * 40, findings
        )
        assert "iconRef" not in entry, value
        assert any("iconUrl" in w for w in findings.warnings)
        # Refused rather than published is what this class pins. That a BUILT-IN
        # then fails the run is the first-party icon gate
        # (`ICON_MISSING_IS_ERROR_BUILTIN`) doing its job on an unpublishable
        # first-party path; the "one odd path must not halt the release" rule this
        # line used to assert still holds for a FETCHED app, where the defect is
        # upstream -- see `test_over_long_fetched_refs_are_refused`.
        assert findings.errors == [
            "demo-app: no icon published; the store renders a placeholder"
        ]

    @pytest.mark.parametrize(
        "value",
        ["a" * (publish.ASSET_REF_MAX + 1) + ".png", "assets/" + "b" * 600 + ".png"],
    )
    def test_over_long_fetched_refs_are_refused(self, value):
        findings = Findings()
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        manifest["iconPath"] = value
        entry = publish.bake_entry(authored(), manifest, "a" * 40, findings)
        assert "iconRef" not in entry
        assert findings.errors == []

    def test_every_accepted_ref_validates_against_the_published_schema(self):
        """The property that matters, checked end to end rather than by eye: bake
        a builtin and a fetched entry with the longest legal refs and run the real
        published-schema validator over the assembled document."""
        from validate import Findings as VFindings
        from validate import check_schema

        longest_abs = "/" + "a" * (publish.ASSET_REF_MAX - 1)
        longest_rel = "a" * publish.ASSET_REF_MAX
        builtin = publish.bake_entry(
            BUILTIN, {**MANIFEST, "iconUrl": longest_abs}, "b" * 40, Findings()
        )
        manifest = {k: v for k, v in MANIFEST.items() if k != "iconUrl"}
        manifest["iconPath"] = longest_rel
        fetched = publish.bake_entry(authored(), manifest, "a" * 40, Findings())
        assert builtin["iconRef"] == longest_abs
        assert fetched["iconRef"] == longest_rel

        vf = VFindings()
        check_schema(
            {
                "schemaVersion": 1,
                "generatedAt": "2026-01-01T00:00:00Z",
                "revision": "2026-01-01T00:00:00Z-abcdef1",
                "apps": [builtin, {**fetched, "source": {"type": "builtin"}}],
            },
            publish.SCHEMA_DIR / "official-registry.schema.json",
            "official-registry.json",
            vf,
        )
        assert vf.errors == [], vf.errors


# ---------------------------------------------------------------------------
# Hosted icons must be uploaded with an image content type
# ---------------------------------------------------------------------------
#
# `aws s3 sync --content-type` applies ONE value to every object a call uploads.
# The document sync forces application/json, so an icon riding along in that call
# reaches clients as JSON and an <img> refuses to render it. The fix is a
# separate pass per extension, which only holds while the two lists agree.


def test_asset_upload_covers_every_extension_publish_will_host():
    script = (
        publish.ROOT / ".github" / "scripts" / "upload-assets.sh"
    ).read_text(encoding="utf-8")
    for ext in publish.ICON_EXT_ALLOWED:
        assert f'upload "*{ext}"' in script, ext


def test_document_syncs_exclude_the_asset_directory():
    """Without the exclude, icons are uploaded twice and the JSON-typed pass may
    be the one that wins."""
    workflow = (
        publish.ROOT / ".github" / "workflows" / "s3-publish.yml"
    ).read_text(encoding="utf-8")
    json_syncs = [
        line for line in workflow.splitlines() if "--content-type \"application/json\"" in line
    ]
    assert len(json_syncs) == 2, "expected the revision and pointer syncs"
    assert workflow.count('--exclude "assets/*"') == len(json_syncs)


def test_assets_are_uploaded_before_the_document_that_names_them():
    """The document is the only thing that makes an icon reachable.

    Publishing it first opens a window where a client resolves a path whose
    bytes are not there yet, and if the asset step then fails the signed
    document is already live pointing at a 404. Uploading first is safe in a way
    the reverse is not: the filename is the sha256 of the contents, so an asset
    nothing references yet is inert and re-uploading is idempotent.

    Both destinations are checked -- the immutable revision and the rolling
    pointer -- because they publish the same document to two prefixes.
    """
    workflow = (
        publish.ROOT / ".github" / "workflows" / "s3-publish.yml"
    ).read_text(encoding="utf-8")
    lines = workflow.splitlines()
    assets = [i for i, ln in enumerate(lines) if "upload-assets.sh" in ln]
    documents = [
        i for i, ln in enumerate(lines) if 'aws s3 sync dist "s3://' in ln
    ]
    assert len(assets) == 2, "expected the revision and pointer asset uploads"
    assert len(documents) == 2, "expected the revision and pointer document syncs"
    for asset_line, document_line in zip(assets, documents):
        assert asset_line < document_line, (
            "upload-assets.sh must run BEFORE the document sync that references "
            f"the icons (asset upload at line {asset_line + 1}, document sync at "
            f"line {document_line + 1})"
        )


class TestAuthoredCannotForgeGeneratedFields:
    """An authored document may not supply `generatedAt` or `revision`.

    Both builders finish with `**doc`, so a generated field that survived the
    authored read would land AFTER the stamped one and win -- riding into a
    signed document as the publisher's own claim about when it was built and
    which revision it is. The digest deliberately excludes these fields, which
    is the evidence they were always meant to be stamped.

    One schema validates both the authored and the published form, so it cannot
    forbid them; it has to admit them for the published side. That leaves the
    builder as the only place the authored side can be held, and these tests as
    the only thing that pins it.

    The registry builder is absent here on purpose: it enumerates its keys
    rather than spreading authored input, so the shape is unreachable there.
    """

    FORGED = {"generatedAt": "1999-01-01T00:00:00Z", "revision": "1999-forged"}

    def test_editorial_stamps_over_authored_values(self):
        now = datetime(2026, 8, 19, 6, 0, 0, tzinfo=timezone.utc)
        doc = publish.build_editorial(
            {"schemaVersion": 1, "sections": [], **self.FORGED}, now
        )
        assert doc["generatedAt"] == "2026-08-19T06:00:00Z"
        assert doc["revision"].startswith("2026-08-19T06:00:00Z-")
        assert "forged" not in doc["revision"]

    def test_category_order_stamps_over_authored_values(self):
        now = datetime(2026, 8, 19, 6, 0, 0, tzinfo=timezone.utc)
        doc = publish.build_category_order(
            {"schemaVersion": 1, "categories": ["dev"], **self.FORGED}, now
        )
        assert doc["generatedAt"] == "2026-08-19T06:00:00Z"
        assert doc["revision"].startswith("2026-08-19T06:00:00Z-")
        assert "forged" not in doc["revision"]

    def test_a_forged_timestamp_does_not_change_the_revision(self):
        """The digest covers content, so two documents differing only in a forged
        timestamp must publish to the SAME revision.

        Pins the half a naive fix misses: stripping the field from the spread
        while leaving it in the digest input would make the revision depend on a
        value the curator controls, so an unchanged catalog would republish under
        a new revision on every edit to that field.
        """
        now = datetime(2026, 8, 19, 6, 0, 0, tzinfo=timezone.utc)
        clean = publish.build_category_order(
            {"schemaVersion": 1, "categories": ["dev"]}, now
        )
        forged = publish.build_category_order(
            {"schemaVersion": 1, "categories": ["dev"], **self.FORGED}, now
        )
        assert clean["revision"] == forged["revision"]


# --------------------------------------------------------------------------
# Star counts
# --------------------------------------------------------------------------


class TestBakesStarCounts:
    """`stargazersCount` is GENERATED at publish via an injected fetcher.

    Absence means UNKNOWN, never zero: a run that could not read the count
    publishes NO field rather than a number it has no evidence for, and only
    warns -- a star count is never worth failing a release over.
    """

    def test_git_entry_bakes_the_fetched_count(self):
        entry = publish.bake_entry(
            authored(), MANIFEST, "a" * 40, Findings(),
            stars_fetcher=lambda url: 42,
        )
        assert entry["stargazersCount"] == 42

    def test_fetcher_sees_the_source_url(self):
        seen: list[str] = []

        def fetcher(url: str) -> int | None:
            seen.append(url)
            return 1

        publish.bake_entry(
            authored(url="https://github.com/o/r"), MANIFEST, "a" * 40,
            Findings(), stars_fetcher=fetcher,
        )
        assert seen == ["https://github.com/o/r"]

    def test_unknown_count_omits_the_field_and_warns(self):
        findings = Findings()
        entry = publish.bake_entry(
            authored(), MANIFEST, "a" * 40, findings,
            stars_fetcher=lambda url: None,
        )
        assert "stargazersCount" not in entry, "absent means unknown, never 0"
        assert findings.errors == []
        assert any("star count" in w for w in findings.warnings)

    def test_no_fetcher_means_no_field_and_no_warning(self):
        """A dry run injects no fetcher; that is silence, not a degraded fetch."""
        findings = Findings()
        entry = publish.bake_entry(authored(), MANIFEST, "a" * 40, findings)
        assert "stargazersCount" not in entry
        assert not any("star count" in w for w in findings.warnings)

    def test_builtin_never_calls_the_fetcher(self):
        def explode(url: str) -> int | None:
            raise AssertionError("a builtin has no repository to count stars on")

        entry = publish.bake_entry(
            BUILTIN, MANIFEST, "b" * 40, Findings(), stars_fetcher=explode
        )
        assert "stargazersCount" not in entry

    def test_published_schema_accepts_the_field(self):
        findings = Findings()
        doc = publish.build_registry(
            {"schemaVersion": 1, "apps": [authored(url="https://github.com/o/r.git")]},
            lambda url, ref: "a" * 40,
            lambda url, commit, subdir=None: MANIFEST,
            datetime.now(timezone.utc),
            findings,
            stars_fetcher=lambda url: 5,
        )
        assert doc["apps"][0]["stargazersCount"] == 5

        from validate import check_schema
        out = Findings()
        check_schema(
            doc, publish.SCHEMA_DIR / "official-registry.schema.json", "pub", out
        )
        assert out.errors == [], out.errors


class TestFetchGithubStars:
    """URL gating and response hygiene; no test may reach api.github.com."""

    @pytest.fixture(autouse=True)
    def no_network(self, monkeypatch):
        def refuse(*args, **kwargs):
            raise AssertionError("test must not perform a real HTTP request")

        monkeypatch.setattr(publish.urllib.request, "urlopen", refuse)

    @pytest.mark.parametrize(
        "url",
        [
            "https://gitlab.com/o/r",
            "https://example.com/o/r.git",
            "https://github.com/only-owner",
            "https://github.com/o/r/extra/path",
            "http://github.com/o/r",
        ],
    )
    def test_non_github_repo_urls_skip_without_a_request(self, url):
        assert publish.fetch_github_stars(url) is None

    def test_fetch_failure_returns_none(self, monkeypatch):
        def boom(*args, **kwargs):
            raise OSError("timed out")

        monkeypatch.setattr(publish.urllib.request, "urlopen", boom)
        assert publish.fetch_github_stars("https://github.com/o/r") is None

    @pytest.mark.parametrize("hostile", [None, "9", -1, True, [3], {"n": 1}, 9_007_199_254_740_992])
    def test_non_count_payload_returns_none(self, monkeypatch, hostile):
        """The response body is a file we do not control; a hostile
        `stargazers_count` must degrade to unknown, not publish. The upper
        bound mirrors the schema's `maximum` (JS safe-integer range)."""
        import contextlib as _ctx
        import io

        class FakeResponse(io.BytesIO):
            pass

        body = json.dumps({"stargazers_count": hostile}).encode("utf-8")

        @_ctx.contextmanager
        def fake_urlopen(request, timeout=None):
            yield FakeResponse(body)

        monkeypatch.setattr(publish.urllib.request, "urlopen", fake_urlopen)
        assert publish.fetch_github_stars("https://github.com/o/r") is None


class TestBudgetedStarsFetcher:
    """A run-wide budget bounds TOTAL star-fetch time across all entries.

    Each fetch has its own timeout, but build_registry() walks entries
    serially — enough stalled requests would outlive the CI job even though
    every individual fetch "degraded gracefully". Past the budget, remaining
    entries publish without the field instead of delaying the release.
    """

    def test_fetches_normally_within_the_budget(self, monkeypatch):
        monkeypatch.setattr(publish, "fetch_github_stars", lambda url: 42)
        fetch = publish.budgeted_stars_fetcher()
        assert fetch("https://github.com/o/r") == 42

    def test_stops_fetching_once_the_budget_is_spent(self, monkeypatch):
        calls: list[str] = []

        def fake_fetch(url):
            calls.append(url)
            return 42

        monkeypatch.setattr(publish, "fetch_github_stars", fake_fetch)
        # fetch() reads the clock ONCE per call: first call pins the deadline
        # at 0.0 + budget, second call observes a time past it.
        clock = iter([0.0, publish.STARS_TOTAL_BUDGET + 1.0])
        monkeypatch.setattr(publish.time, "monotonic", lambda: next(clock))
        fetch = publish.budgeted_stars_fetcher()
        assert fetch("https://github.com/o/first") == 42, "within budget: fetched"
        assert fetch("https://github.com/o/late") is None, "past budget: skipped"
        assert calls == ["https://github.com/o/first"], "no request after the deadline"

    def test_the_deadline_starts_at_the_first_call_not_construction(self, monkeypatch):
        monkeypatch.setattr(publish, "fetch_github_stars", lambda url: 7)
        # Construction time is irrelevant: the first call starts the clock.
        clock = iter([100.0, 100.0])
        monkeypatch.setattr(publish.time, "monotonic", lambda: next(clock))
        fetch = publish.budgeted_stars_fetcher()
        assert fetch("https://github.com/o/r") == 7


# --------------------------------------------------------------------------
# release entries: publish a prebuilt asset pinned by digest (#44 phase 1)
# --------------------------------------------------------------------------


def authored_release(name="demo-app", url="https://github.com/octo/demo-app",
                     tag="v1.2.0", asset="demo-app-dist.tar.gz"):
    return {
        "name": name,
        "source": {"type": "release", "url": url, "tag": tag, "asset": asset},
    }


def test_authored_schema_accepts_a_release_entry():
    from validate import check_schema
    out = Findings()
    check_schema(
        {"schemaVersion": 1, "apps": [authored_release()]},
        publish.SCHEMA_DIR / "authored-registry.schema.json",
        "authored",
        out,
    )
    assert out.errors == [], out.errors


@pytest.mark.parametrize(
    "patch",
    [
        {"url": "https://gitlab.com/o/r"},  # non-GitHub forge
        {"tag": "v1/2"},  # slash would add a URL path segment
        {"tag": "v1 2"},  # whitespace
        {"tag": ""},  # empty
        {"tag": "x" * 256},  # over the 255 bound
        {"asset": "dist/app.tar.gz"},  # path separator
        {"asset": "..\u002e"},  # dot-dot spelling
        {"asset": ".."},
        {"asset": ""},  # empty
        {"asset": "x" * 256},  # over the 255 bound
        {"sha256": "a" * 64},  # digest is generated, never authored
    ],
)
def test_authored_schema_rejects_malformed_release_entries(patch):
    from validate import check_schema
    entry = authored_release()
    entry["source"].update(patch)
    out = Findings()
    check_schema(
        {"schemaVersion": 1, "apps": [entry]},
        publish.SCHEMA_DIR / "authored-registry.schema.json",
        "authored",
        out,
    )
    assert out.errors, f"schema must reject {patch!r}"


def test_release_asset_url_is_derived_and_percent_encoded():
    url = publish.release_asset_url(
        "https://github.com/octo/demo-app.git", "v1.2.0", "demo app%.tar.gz"
    )
    assert url == (
        "https://github.com/octo/demo-app/releases/download/"
        "v1.2.0/demo%20app%25.tar.gz"
    )


def test_release_asset_url_refuses_non_github():
    with pytest.raises(publish.PublishError, match="github.com"):
        publish.release_asset_url("https://example.com/o/r.git", "v1", "a.tar.gz")


def test_release_entry_publishes_as_a_digest_pinned_archive(
    tmp_path, allow_local_urls, monkeypatch
):
    """End to end: the published source is the ARCHIVE variant carrying the
    derived URL, the digest THIS run computed, and the release tag -- and the
    document satisfies the published schema."""
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    git("tag", "-a", "v1.2.0", "-m", "v1.2.0", cwd=repo)

    entry = authored_release(url=str(repo))
    # The fixture repo is local, so stand in for GitHub URL derivation; the
    # real deriver's GitHub-only refusal is pinned by its own tests below.
    canned = "https://github.com/octo/demo-app/releases/download/v1.2.0/demo-app-dist.tar.gz"
    monkeypatch.setattr(publish, "release_asset_url", lambda u, t, a: canned)
    digested: list[str] = []

    def digester(url: str) -> str:
        digested.append(url)
        return "ab" * 32

    findings = Findings()
    doc = publish.build_registry(
        {"schemaVersion": 1, "apps": [entry]},
        publish.resolve_pin, publish.fetch_manifest,
        publish.datetime.now(publish.timezone.utc), findings,
        asset_digester=digester,
    )
    assert findings.errors == []
    source = doc["apps"][0]["source"]
    assert source["type"] == "archive"
    assert source["url"] == canned
    assert source["sha256"] == "ab" * 32
    assert source["sourceTag"] == "v1.2.0"
    assert "ref" not in source, "an archive entry has no git pin"
    assert digested == [canned], "the digest must be computed over the derived URL"
    # Display fields still came from the git repo at the tag.
    assert doc["apps"][0]["displayName"] == "Demo App"

    from validate import check_schema
    out = Findings()
    check_schema(doc, publish.SCHEMA_DIR / "official-registry.schema.json", "pub", out)
    assert out.errors == [], out.errors


def test_release_entry_with_non_github_url_fails_url_derivation(
    tmp_path, allow_local_urls
):
    """A release entry's url must be a GitHub repo: a non-GitHub url fails at
    URL derivation with a clear error rather than publishing a guessed link."""
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    git("tag", "v1.2.0", cwd=repo)
    with pytest.raises(publish.PublishError, match="github.com"):
        publish.build_registry(
            {"schemaVersion": 1, "apps": [authored_release(url=str(repo))]},
            publish.resolve_pin, publish.fetch_manifest,
            publish.datetime.now(publish.timezone.utc), Findings(),
            asset_digester=lambda url: "ab" * 32,
        )


def test_bake_entry_refuses_a_release_without_a_digest():
    """The fail-closed invariant: no digest, no archive entry -- never an
    unpinned URL in a signed document."""
    findings = Findings()
    with pytest.raises(publish.PublishError, match="unpinned"):
        publish.bake_entry(
            authored_release(), MANIFEST, "a" * 40, findings,
            tag="v1.2.0", asset_url="https://github.com/o/r/releases/download/v1.2.0/a.tar.gz",
            asset_sha256=None,
        )


def test_release_asset_url_uses_the_resolved_tag_not_the_authored_pattern(
    tmp_path, allow_local_urls, monkeypatch
):
    """An authored wildcard like `v1.*` resolves to a concrete tag; the asset
    URL and sourceTag must carry THAT tag -- deriving from the authored
    spelling would percent-encode the wildcard and request a dead path."""
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    git("tag", "-a", "v1.2.0", "-m", "v1.2.0", cwd=repo)

    entry = authored_release(url=str(repo))
    entry["source"]["tag"] = "v1.*"
    derived: list[tuple[str, str]] = []

    def fake_url(u: str, t: str, a: str) -> str:
        derived.append((t, a))
        return f"https://github.com/octo/demo-app/releases/download/{t}/{a}"

    monkeypatch.setattr(publish, "release_asset_url", fake_url)
    findings = Findings()
    doc = publish.build_registry(
        {"schemaVersion": 1, "apps": [entry]},
        publish.resolve_pin, publish.fetch_manifest,
        publish.datetime.now(publish.timezone.utc), findings,
        asset_digester=lambda url: "ab" * 32,
    )
    assert findings.errors == []
    assert derived == [("v1.2.0", "demo-app-dist.tar.gz")], (
        "the URL must be derived from the RESOLVED tag, never the pattern"
    )
    source = doc["apps"][0]["source"]
    assert "v1.2.0" in source["url"] and "*" not in source["url"]
    assert source["sourceTag"] == "v1.2.0"


def test_release_entry_refuses_a_ref_with_no_tag_provenance(
    tmp_path, allow_local_urls
):
    """A release ref that resolves without tag provenance (e.g. a branch name)
    fails closed: there is no tag to derive the asset URL from."""
    repo = tmp_path / "repo"
    make_repo(repo, MANIFEST)
    git("tag", "-a", "v1.2.0", "-m", "v1.2.0", cwd=repo)

    entry = authored_release(url=str(repo))

    def resolver(url: str, ref: str) -> publish.ResolvedPin:
        return publish.ResolvedPin("a" * 40)  # commit found, no tag matched

    with pytest.raises(publish.PublishError, match="concrete tag"):
        publish.build_registry(
            {"schemaVersion": 1, "apps": [entry]},
            resolver, lambda url, commit, subdir=None: dict(MANIFEST),
            publish.datetime.now(publish.timezone.utc), Findings(),
            asset_digester=lambda url: "ab" * 32,
        )


def test_release_entry_ingests_art_from_the_repository_not_the_asset_url():
    """Regression pin: the release->archive swap is deferred past every
    ingester, so icon ingestion and the star fetch read the REPOSITORY url --
    handing them the asset download URL as a git remote silently dropped the
    app's artwork from the signed storefront."""
    seen_urls: list[str] = []

    class SpyAssets:
        def add(self, url, commit, ref, name, findings):
            seen_urls.append(url)
            return "assets/icons/" + "c" * 64 + ".png"

    manifest = dict(MANIFEST)
    manifest.pop("iconUrl", None)
    manifest["iconPath"] = "ui/icon.png"

    star_urls: list[str] = []

    def stars(url):
        star_urls.append(url)
        return 5

    repo_url = "https://github.com/octo/demo-app"
    findings = Findings()
    entry = publish.bake_entry(
        authored_release(url=repo_url), manifest, "a" * 40, findings,
        assets=SpyAssets(), stars_fetcher=stars,
        tag="v1.2.0",
        asset_url="https://github.com/octo/demo-app/releases/download/v1.2.0/a.tar.gz",
        asset_sha256="ab" * 32,
    )
    assert seen_urls == [repo_url], "icon ingestion must see the git repo, not the asset"
    assert star_urls == [repo_url]
    assert entry["iconRef"].startswith("assets/icons/")
    assert entry["stargazersCount"] == 5
    # And the swap still happened -- the published source is the archive.
    assert entry["source"] == {
        "type": "archive",
        "url": "https://github.com/octo/demo-app/releases/download/v1.2.0/a.tar.gz",
        "sha256": "ab" * 32,
        "sourceTag": "v1.2.0",
    }


@pytest.mark.parametrize(
    "bad_source",
    [
        {"type": "archive", "url": "http://x/a.tar.gz", "sha256": "ab" * 32},  # http
        {"type": "archive", "url": "https://x/" + "a" * 2048, "sha256": "ab" * 32},  # over 2048
        {"type": "archive", "url": "https://x/a.tar.gz", "sha256": "ab" * 31},  # short digest
        {"type": "archive", "url": "https://x/a.tar.gz", "sha256": "ab" * 32,
         "sourceTag": "v1 2"},  # whitespace tag
        {"type": "archive", "url": "https://x/a.tar.gz", "sha256": "ab" * 32,
         "sourceTag": ""},  # empty tag -- omit the field instead
        {"type": "archive", "url": "https://x/a.tar.gz", "sha256": "ab" * 32,
         "sourceTag": "x" * 256},  # overlong tag
        {"type": "archive", "url": "https://x/a.tar.gz"},  # digest missing entirely
    ],
)
def test_published_schema_rejects_malformed_archive_sources(
    bad_source, tmp_path, allow_local_urls
):
    """Pin the published-schema constraints on the archive variant itself:
    https-only url, exact 64-hex digest required, sourceTag held to the same
    shape as the git variant's."""
    doc, findings, commit = build({"schemaVersion": 1, "apps": [authored()]}, tmp_path)
    assert findings.errors == []
    doc["apps"][0]["source"] = bad_source

    from validate import check_schema
    out = Findings()
    check_schema(doc, publish.SCHEMA_DIR / "official-registry.schema.json", "pub", out)
    assert out.errors, f"schema must reject {bad_source!r}"


def test_fetch_asset_sha256_refuses_http():
    with pytest.raises(publish.PublishError, match="https"):
        publish.fetch_asset_sha256("http://example.com/a.tar.gz")


class TestFetchAssetSha256:
    def _serve(self, monkeypatch, chunks, exc=None):
        class FakeResponse:
            def __init__(self):
                self._chunks = list(chunks)

            def read(self, n):
                return self._chunks.pop(0) if self._chunks else b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(request, timeout=None):
            if exc:
                raise exc
            return FakeResponse()

        monkeypatch.setattr(publish.urllib.request, "urlopen", fake_urlopen)

    def test_digest_matches_hashlib(self, monkeypatch):
        self._serve(monkeypatch, [b"hello ", b"world"])
        expected = publish.hashlib.sha256(b"hello world").hexdigest()
        assert publish.fetch_asset_sha256("https://x/a.tar.gz") == expected

    def test_size_cap_is_enforced_on_bytes_read(self, monkeypatch):
        big = b"x" * publish._ASSET_CHUNK_BYTES
        count = publish.RELEASE_ASSET_MAX_BYTES // len(big) + 2
        self._serve(monkeypatch, [big] * count)
        with pytest.raises(publish.PublishError, match="cap"):
            publish.fetch_asset_sha256("https://x/a.tar.gz")

    def test_empty_asset_is_refused(self, monkeypatch):
        self._serve(monkeypatch, [])
        with pytest.raises(publish.PublishError, match="empty"):
            publish.fetch_asset_sha256("https://x/a.tar.gz")

    def test_network_failure_raises_not_degrades(self, monkeypatch):
        self._serve(monkeypatch, [], exc=OSError("boom"))
        with pytest.raises(publish.PublishError, match="failed to download"):
            publish.fetch_asset_sha256("https://x/a.tar.gz")
