# Verification keys

Public halves only. Private keys never appear in this repository.

| File | keyId | Algorithm | Status |
|---|---|---|---|
| `kms-899025c9e92fe39f.pub` | `899025c9e92fe39f` | `RSASSA_PKCS1_V1_5_SHA_256` | **Active** — signs every new revision |
| `bootstrap-adb8f178f20a6c90.pub` | `adb8f178f20a6c90` | `ed25519` | Superseded — retained only to verify revisions published before the switch |

Each file holds the base64 of the public key's DER (`SubjectPublicKeyInfo` for
RSA, raw bytes for ed25519), and the filename's keyId is `sha256(that
material)[:16]`. `tools/verify_dist.py` recomputes it and refuses a file whose
name disagrees with its contents, so a published-looking id cannot authorize
unpublished material.

## The active key

`kms-899025c9e92fe39f.pub` is the public half of an AWS KMS key
(`RSA_3072`/`SIGN_VERIFY`, alias `alias/kirocrew-apps-registry`) declared in
CDK. The private half has no exportable form: it is generated inside KMS and
cannot be read out by anyone, including the account's administrators. Signing is
an API call authorized by an OIDC role that only the publish workflow on `main`
can assume, and every use is recorded in CloudTrail.

That is a materially different custody story from the bootstrap key it replaces —
there is no file to leak, and revocation is disabling one key rather than
chasing copies. It is **not** the full ceremony the RFC describes for an Official
root: there is no split custody or documented recovery drill, and one compromised
push to `main` still reaches the signing role.

## What is still missing before a client should trust this

**`keys/` ships from the same origin as the documents it authenticates.** Anyone
who can write the catalog bucket can replace both the documents and the key used
to check them, which makes this directory a convenience for verification, not a
root of trust. Closing that requires the verification key to be **bundled with
the client**, offline and not fetchable — listed in the RFC as a prerequisite for
granting Official trust, and not yet done.

So: a client may verify against a *bundled copy* of this key, but must not fetch
it from the network at verification time.

## Rotation

Add the new public key as another file here and publish it before switching the
signer. The verifier is a keyId → key map, so a revision signed by either key
verifies while both files are present; the superseded file is removed only once
no reachable revision was signed with it. Immutable revisions keep their original
signatures forever, which is why the ed25519 entry above stays.

## Verifying a signature

Each published document has a detached `.sig` sidecar:

```json
{
  "algorithm": "RSASSA_PKCS1_V1_5_SHA_256",
  "keyId": "899025c9e92fe39f",
  "payloadSha256": "…",
  "signature": "…base64…"
}
```

The signature covers the **exact bytes** of the document, so verify the file as
downloaded — do not re-serialize it first.

```python
import base64, hashlib, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

payload = open("official-registry.json", "rb").read()
sidecar = json.load(open("official-registry.json.sig"))
der = base64.b64decode(open("keys/kms-899025c9e92fe39f.pub").read().strip())

assert sidecar["payloadSha256"] == hashlib.sha256(payload).hexdigest()
serialization.load_der_public_key(der).verify(
    base64.b64decode(sidecar["signature"]),
    payload,
    padding.PKCS1v15(),
    hashes.SHA256(),
)
```

Dispatch on `algorithm` rather than assuming it: a verifier that ignores the
field will accept whatever it happens to implement. Treat an algorithm you do not
implement as a refusal, never as a skipped check.

`payloadSha256` is a convenience for spotting a truncated download; it is **not**
the security check. The signature is. A hash the attacker can recompute proves
nothing on its own.
