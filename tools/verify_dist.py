#!/usr/bin/env python3
"""Verify published artifacts against the public keys committed to this repo.

Deliberately verifies against `keys/*.pub` rather than against whatever the
signer just produced. Checking a signature with the key that made it proves only
that the signer is self-consistent; checking it with the key readers will use is
what catches a signature minted over different bytes than the file being shipped.

Refuses, in every case, to let something unverifiable through:

- a document with no sidecar
- a document signed by a key that is not published here, so no reader could
  verify it
- a payload digest that disagrees with the file
- a signature that does not verify
- an empty directory, because "nothing to check" must not read as success

Usage:
    python tools/verify_dist.py dist
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = ROOT / "keys"


def load_public_keys(keys_dir: Path = KEYS_DIR) -> dict[str, bytes]:
    """Map keyId -> raw public key bytes, from `keys/*.pub`.

    The keyId is taken from the filename, then checked against the key material
    itself in `verify_dir` -- a mislabelled file must not silently authorize the
    wrong key.
    """
    keys: dict[str, bytes] = {}
    for path in sorted(keys_dir.glob("*.pub")):
        stem = path.stem
        key_id = stem.split("-", 1)[1] if "-" in stem else stem
        keys[key_id] = base64.b64decode(path.read_text().strip())
    return keys


def _verify_ed25519(raw: bytes, signature: bytes, payload: bytes) -> None:
    """The bootstrap algorithm. Retained so revisions published before the move
    to KMS stay verifiable -- immutable revisions are immutable, including their
    signatures."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    Ed25519PublicKey.from_public_bytes(raw).verify(signature, payload)


def _verify_rsa_pkcs1_sha256(raw: bytes, signature: bytes, payload: bytes) -> None:
    """Verify a signature from the KMS RSA_3072 key.

    ``raw`` is a DER SPKI blob rather than bare key bytes -- RSA has no raw
    encoding, which is also why keyId is a hash over the SPKI DER.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = serialization.load_der_public_key(raw)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError(f"key material is {type(key).__name__}, not RSA")
    key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())


# An allowlist, not a lookup with a fallback: an algorithm this verifier does not
# implement must be a refusal, never a skipped check.
SIGNATURE_ALGORITHMS = {
    "ed25519": _verify_ed25519,
    "RSASSA_PKCS1_V1_5_SHA_256": _verify_rsa_pkcs1_sha256,
}


def verify_dir(dist: Path, keys: dict[str, bytes] | None = None) -> list[str]:
    """Return a list of problems; empty means everything verified."""
    from cryptography.exceptions import InvalidSignature

    if keys is None:
        keys = load_public_keys()

    problems: list[str] = []

    # A filename claiming one keyId while holding another key would let a
    # published-looking id authorize unpublished material.
    for key_id, raw in keys.items():
        actual = hashlib.sha256(raw).hexdigest()[:16]
        if actual != key_id:
            problems.append(
                f"keys/: file names key {key_id!r} but the material is {actual!r}"
            )

    documents = sorted(p for p in dist.glob("*.json") if not p.name.endswith(".sig"))
    if not documents:
        return problems + [f"{dist}: no documents to verify"]

    for doc in documents:
        sidecar_path = doc.with_name(f"{doc.name}.sig")
        if not sidecar_path.is_file():
            problems.append(f"{doc.name}: no signature sidecar")
            continue

        payload = doc.read_bytes()
        try:
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"{sidecar_path.name}: invalid JSON: {exc}")
            continue

        key_id = sidecar.get("keyId")
        if key_id not in keys:
            problems.append(
                f"{doc.name}: signed by key {key_id!r}, which is not published in "
                f"keys/ -- no reader could verify this"
            )
            continue

        algorithm = sidecar.get("algorithm")
        if algorithm not in SIGNATURE_ALGORITHMS:
            problems.append(f"{doc.name}: unexpected algorithm {algorithm!r}")
            continue

        digest = hashlib.sha256(payload).hexdigest()
        if sidecar.get("payloadSha256") != digest:
            problems.append(
                f"{doc.name}: sidecar digest {sidecar.get('payloadSha256')!r} != "
                f"file digest {digest!r}"
            )
            continue

        # A sidecar missing this field, or carrying something that is not base64,
        # is a verification failure like any other -- not a crash. This runs as a
        # pre-upload gate, where a traceback would be a far less useful answer
        # than a named problem.
        encoded = sidecar.get("signature")
        if not isinstance(encoded, str):
            problems.append(f"{doc.name}: sidecar has no signature")
            continue
        try:
            signature = base64.b64decode(encoded, validate=True)
        except ValueError as exc:  # binascii.Error subclasses ValueError
            problems.append(f"{doc.name}: signature is not valid base64 ({exc})")
            continue

        try:
            SIGNATURE_ALGORITHMS[algorithm](keys[key_id], signature, payload)
        except (InvalidSignature, ValueError, TypeError) as exc:
            problems.append(f"{doc.name}: signature does not verify ({exc})")
            continue

        print(f"verified {doc.name} ({len(payload)} bytes, {algorithm}, key {key_id})")

    problems.extend(verify_hosted_icons(dist))
    problems.extend(verify_hosted_artwork(dist))
    return problems


def verify_hosted_icons(dist: Path) -> list[str]:
    """Check every hosted icon against the digest in its own filename.

    Icons carry no signature of their own. Their integrity rides on being
    content-addressed: the filename IS the sha256 of the bytes, and the filename
    appears in the registry document, which is signed and verified above. So the
    chain is signature -> document -> path -> bytes, and this closes the last
    link for the artifacts we are about to upload.

    It is also the reference implementation of what a CLIENT must do after
    downloading an icon. Publishing a document that names a digest and then
    serving bytes that do not match it would be undetectable to anyone who
    skipped this step, which is exactly why the step is written down as code
    rather than as a sentence in the schema.
    """
    problems: list[str] = []
    registry = dist / "official-registry.json"
    if not registry.is_file():
        return problems
    try:
        doc = json.loads(registry.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return problems  # already reported by the signature pass above

    checked = 0
    for entry in doc.get("apps") or []:
        if not isinstance(entry, dict):
            continue
        for field in ("iconRef", "iconRefDark"):
            ref = entry.get(field)
            # An absolute ref is a builtin's client-local path: those bytes ship
            # with the client, so there is nothing here to check.
            if not isinstance(ref, str) or not ref or ref.startswith("/"):
                continue
            path = dist / ref
            if not path.is_file():
                problems.append(
                    f"{entry.get('name')}: {field} names {ref!r}, which is not in {dist}"
                )
                continue
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != path.stem:
                problems.append(
                    f"{entry.get('name')}: {field} {ref!r} is addressed by digest "
                    f"{path.stem!r} but its bytes hash to {actual!r}"
                )
                continue
            checked += 1
    if checked:
        print(f"verified {checked} hosted icon(s) against their content digests")
    return problems


def verify_hosted_artwork(dist: Path) -> list[str]:
    """Check every hosted editorial image against the digest in its own filename.

    Same chain as the icons above -- signature -> document -> path -> bytes --
    applied to the editorial document instead of the registry. Written as a
    second pass over a second document rather than folded into the first,
    because the two documents are signed separately and a client that reads only
    one must still get a complete story for the images that document names.
    """
    problems: list[str] = []
    editorial = dist / "editorial.json"
    if not editorial.is_file():
        return problems
    try:
        doc = json.loads(editorial.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return problems  # already reported by the signature pass

    checked = 0
    for idx, section in enumerate(doc.get("sections") or []):
        if not isinstance(section, dict):
            continue
        # Artwork hangs off items. Reading `sections[].artwork` would find
        # nothing and report a clean chain for a document full of images.
        for jdx, entry in enumerate(section.get("items") or []):
            if not isinstance(entry, dict):
                continue
            art = entry.get("artwork")
            if not isinstance(art, dict):
                continue
            for field in ("ref", "refDark"):
                ref = art.get(field)
                if not isinstance(ref, str) or not ref:
                    continue
                where = f"sections[{idx}].items[{jdx}].artwork.{field}"
                # A published ref MUST be the content-addressed form. An authored
                # path that reached the output means the bake step was skipped,
                # and that is a hole in the integrity chain, not a cosmetic slip.
                if not ref.startswith("assets/editorial/"):
                    problems.append(
                        f"{where} names {ref!r}, which is not a hosted asset path -- "
                        f"the artwork bake step did not run"
                    )
                    continue
                path = dist / ref
                if not path.is_file():
                    problems.append(f"{where} names {ref!r}, which is not in {dist}")
                    continue
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != path.stem:
                    problems.append(
                        f"{where} {ref!r} is addressed by digest {path.stem!r} but its "
                        f"bytes hash to {actual!r}"
                    )
                    continue
                checked += 1
    if checked:
        print(f"verified {checked} hosted editorial image(s) against their content digests")
    return problems


def main(argv: list[str]) -> int:
    dist = Path(argv[1]) if len(argv) > 1 else Path("dist")
    problems = verify_dir(dist)
    for problem in problems:
        print(f"error: {problem}")
    if problems:
        print(f"VERIFICATION FAILED: {len(problems)} problem(s)")
        return 1
    print("all artifacts verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
