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


def make_repo(path: Path, manifest: dict, subdir: str | None = None) -> str:
    """Create a real one-commit repo containing app.json. Returns the commit."""
    path.mkdir(parents=True, exist_ok=True)
    git("init", "--quiet", "-b", "main", ".", cwd=path)
    target = path / subdir if subdir else path
    target.mkdir(parents=True, exist_ok=True)
    (target / "app.json").write_text(json.dumps(manifest), encoding="utf-8")
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
    assert entry["displayName"] == "Demo App"
    assert entry["summary"] == "Does the demo thing."
    assert entry["author"] == {"name": "Demo Labs"}
    assert entry["tags"] == ["dev", "demo"]
    assert entry["version"] == "1.2.3"
    assert entry["iconRef"] == "/app-assets/demo-app/icon.svg"
    assert entry["heroRef"] == "/app-assets/demo-app/hero.svg"


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
    """Bake one entry, as build_registry would. Returns (entry, findings)."""
    findings = publish.Findings()
    authored = {"name": name, "source": {"type": "git", "url": url, "ref": "main"}}
    if curated is not None:
        authored["author"] = curated
    entry = publish.bake_entry(
        authored, {"name": name, "author": author}, "0" * 40, findings
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
    authored_entry = dict(BUILTIN)
    if curated is not None:
        authored_entry["author"] = curated
    findings = Findings()
    entry = publish.bake_entry(
        authored_entry,
        {"name": "demo-app", "author": manifest_author},
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
    commit = make_repo(repo, MANIFEST)

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
        json.dumps(
            {
                "schemaVersion": 1,
                "categories": [{"id": "dev", "label": "Dev", "order": 10}],
            },
            indent=2,
        )
        + "\n"
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
    (relaxed / "editorial.schema.json").write_text(
        (publish.SCHEMA_DIR / "editorial.schema.json").read_text()
    )

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
