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


def verify_dir(dist: Path, keys: dict[str, bytes] | None = None) -> list[str]:
    """Return a list of problems; empty means everything verified."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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

        if sidecar.get("algorithm") != "ed25519":
            problems.append(f"{doc.name}: unexpected algorithm {sidecar.get('algorithm')!r}")
            continue

        digest = hashlib.sha256(payload).hexdigest()
        if sidecar.get("payloadSha256") != digest:
            problems.append(
                f"{doc.name}: sidecar digest {sidecar.get('payloadSha256')!r} != "
                f"file digest {digest!r}"
            )
            continue

        try:
            Ed25519PublicKey.from_public_bytes(keys[key_id]).verify(
                base64.b64decode(sidecar["signature"]), payload
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            problems.append(f"{doc.name}: signature does not verify ({exc})")
            continue

        print(f"verified {doc.name} ({len(payload)} bytes, key {key_id})")

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
