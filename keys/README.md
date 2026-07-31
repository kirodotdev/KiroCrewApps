# Verification keys

Public halves only. Private keys never appear in this repository.

| File | keyId | Status |
|---|---|---|
| `bootstrap-adb8f178f20a6c90.pub` | `adb8f178f20a6c90` | **Bootstrap — not a production root of trust** |

## What "bootstrap" means

This key exists so the publish chain can be exercised end to end at a real URL
while signing-key custody is still unassigned. It is generated and held without
the ceremony a production root requires: no hardware backing, no split custody,
no documented recovery procedure.

Concretely, that means:

- **Do not ship a client that trusts this key.** It proves the transport and the
  signature format work, not that the catalog is authoritative.
- Treat anything it signs as a preview artifact.
- It will be **replaced**, not promoted. The RFC specifies a root-signed
  active-key model, so rotation is a designed operation rather than a migration —
  publishing a new active key under proper custody supersedes this one.

## Verifying a signature

Each published document has a detached `.sig` sidecar:

```json
{
  "algorithm": "ed25519",
  "keyId": "adb8f178f20a6c90",
  "payloadSha256": "…",
  "signature": "…base64…"
}
```

The signature covers the **exact bytes** of the document, so verify the file as
downloaded — do not re-serialize it first.

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

payload = open("official-registry.json", "rb").read()
sidecar = json.load(open("official-registry.json.sig"))
pub = base64.b64decode(open("keys/bootstrap-adb8f178f20a6c90.pub").read().strip())

assert sidecar["payloadSha256"] == hashlib.sha256(payload).hexdigest()
Ed25519PublicKey.from_public_bytes(pub).verify(
    base64.b64decode(sidecar["signature"]), payload
)
```

`payloadSha256` is a convenience for spotting a truncated download; it is **not**
the security check. The signature is. A hash the attacker can recompute proves
nothing on its own.
