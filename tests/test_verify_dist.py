"""Tests for the pre-upload verifier.

The point of this tool is refusal, so most of these assert that something is
rejected. A verifier that only ever sees good input is indistinguishable from
one that returns success unconditionally.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import publish  # noqa: E402
import verify_dist  # noqa: E402


@pytest.fixture
def signed(tmp_path):
    """A dist/ directory with one correctly signed document, plus its key set."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "k.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    key_id = hashlib.sha256(raw).hexdigest()[:16]

    dist = tmp_path / "dist"
    dist.mkdir()
    payload = publish.canonical_bytes({"schemaVersion": 1, "apps": []})
    (dist / "official-registry.json").write_bytes(payload)
    (dist / "official-registry.json.sig").write_text(
        json.dumps(publish.sign_detached(payload, str(key_path))) + "\n"
    )
    return dist, {key_id: raw}, key_path


def test_accepts_a_correctly_signed_document(signed):
    dist, keys, _ = signed
    assert verify_dist.verify_dir(dist, keys) == []


def test_rejects_a_tampered_document(signed):
    dist, keys, _ = signed
    doc = dist / "official-registry.json"
    doc.write_bytes(doc.read_bytes().replace(b'"apps": []', b'"apps": [ ]'))
    problems = verify_dist.verify_dir(dist, keys)
    # The digest check catches it first; either way it must not pass.
    assert problems and any("digest" in p or "does not verify" in p for p in problems)


def test_rejects_a_missing_sidecar(signed):
    dist, keys, _ = signed
    (dist / "official-registry.json.sig").unlink()
    assert any("no signature sidecar" in p for p in verify_dist.verify_dir(dist, keys))


def test_rejects_a_key_nobody_can_verify_with(signed):
    """Signed by a key that is not published: readers would be stuck."""
    dist, _, _ = signed
    problems = verify_dist.verify_dir(dist, {})
    assert any("not published" in p for p in problems)


def test_rejects_an_empty_directory(tmp_path):
    """"Nothing to check" must not read as success."""
    empty = tmp_path / "dist"
    empty.mkdir()
    assert any("no documents" in p for p in verify_dist.verify_dir(empty, {}))


def test_rejects_a_mislabelled_key_file(signed):
    """A filename claiming one keyId while holding another key would let a
    published-looking id authorize unpublished material."""
    dist, keys, _ = signed
    raw = next(iter(keys.values()))
    problems = verify_dist.verify_dir(dist, {"0" * 16: raw})
    assert any("material is" in p for p in problems)


def test_rejects_a_corrupt_sidecar(signed):
    dist, keys, _ = signed
    (dist / "official-registry.json.sig").write_text("{not json")
    assert any("invalid JSON" in p for p in verify_dist.verify_dir(dist, keys))


def test_rejects_an_unexpected_algorithm(signed):
    dist, keys, _ = signed
    path = dist / "official-registry.json.sig"
    sidecar = json.loads(path.read_text())
    sidecar["algorithm"] = "rsa-pkcs1"
    path.write_text(json.dumps(sidecar))
    assert any("unexpected algorithm" in p for p in verify_dist.verify_dir(dist, keys))


def test_the_committed_bootstrap_key_is_self_consistent():
    """Guards the real keys/ directory: every filename must match its material."""
    keys = verify_dist.load_public_keys()
    assert keys, "no public keys committed"
    for key_id, raw in keys.items():
        assert hashlib.sha256(raw).hexdigest()[:16] == key_id, key_id


def test_signature_is_over_the_bytes_as_served_not_a_reserialization(signed):
    """Re-serializing before verifying is the classic mistake: JSON that parses
    identically can differ byte for byte."""
    dist, keys, _ = signed
    doc = dist / "official-registry.json"
    reserialized = json.dumps(json.loads(doc.read_text()))  # different bytes, same data
    doc.write_text(reserialized)
    assert verify_dist.verify_dir(dist, keys) != []
