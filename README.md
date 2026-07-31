# KiroCrewApps

The official app catalog for the KiroCrew App Store, plus the editorial feed
that decides how the store presents it.

This repository holds **data and its contract**, not code. Clients fetch the
published output at runtime, which is the point: the storefront changes when
this repository changes, with no client release.

Design rationale lives in `docs/request-for-change/rfc-appstore-official-registry.md`
in the KiroCrew repository. This README covers the mechanics.

## Layout

| Path | What it is |
|---|---|
| `catalog/official-registry.json` | **Authored** app catalog — the file curators edit |
| `catalog/editorial.json` | **Authored** taxonomy, category membership, and Discover layout |
| `schema/authored-registry.schema.json` | Contract for authored input (what a human may write) |
| `schema/official-registry.schema.json` | Contract for the **published** document (the wire format) |
| `schema/editorial.schema.json` | Contract for the editorial feed |
| `tools/validate.py` | The gate: schema + cross-document invariants, offline |
| `tools/format.py` | Normalizes authored files so diffs stay semantic |
| `tests/` | Proves the gate still rejects what it should |

## Two documents, deliberately

Splitting the catalog from the editorial feed keeps each answerable to one
question. The registry answers *what an app is and where its bytes come from*.
Editorial answers *how the store presents apps*. Consequences worth knowing:

- Editorial only ever **references** apps by name. App data always resolves
  through the registry, so a curated feed cannot introduce a phantom app or
  spoof an existing one.
- The registry carries **no presentation at all** — no categories, no ordering,
  no copy. Re-theming the store never touches the catalog.
- Category **membership** is curator-assigned in editorial, not derived from an
  app's own tags. Otherwise an author could self-promote into a curated
  category by editing their own `app.json`.

## Two registry schemas, deliberately

Authored input and published output are not the same shape, and conflating them
would break one of them:

|  | Authored | Published |
|---|---|---|
| `source.ref` | commit, **branch, or tag** | immutable commit only |
| Display fields (`displayName`, `summary`, `author`, `tags`, …) | **forbidden** | present, generated |
| `generatedAt` / `revision` | forbidden | stamped by CI |

A curator writes a branch because pinning is the pipeline's job, not a human's.
Display fields are forbidden in authored input so *generated, never authored* is
machine-checked rather than a convention someone remembers — they are baked from
each app's own `app.json` at publish time, and therefore cannot drift from the
app or be inflated by whoever edits the catalog.

The published schema is the stricter one, because it is what clients validate.

## Authoring a change

```bash
pip install -r tools/requirements.txt

# edit catalog/official-registry.json and/or catalog/editorial.json
python tools/format.py      # normalize
python tools/validate.py    # same verdict CI will give
```

Adding an app is two fields:

```json
{ "name": "my-app", "source": { "type": "git", "url": "https://github.com/org/my-app.git", "ref": "main" } }
```

Then add `"my-app"` to exactly one category's `appRefs` in `catalog/editorial.json`.
An app in no category still appears — it lands in the default bucket rather than
being hidden — but the validator will say so, since the usual cause is a
forgotten edit.

## What the gate enforces

Beyond per-document schema validation, `tools/validate.py` checks the
invariants that span both files — the ones that validate fine in isolation and
then render wrong in the store:

- Every `appRefs` entry resolves to a declared, non-tombstoned app.
- An app is in **at most one** category. A partitioned rail is the whole point
  of the taxonomy; use a `rail` section for cross-cutting collections like
  "Staff picks", which is how an app appears in two places without
  multi-category membership.
- `categories[].order` values are unique, so the rail sequence does not depend
  on array position.
- No duplicate app names or category ids.
- A reinstatement has a matching tombstone. A reinstatement is the only thing
  that clears a persisted tombstone, so one with a typo'd name would otherwise
  be a silent no-op.

## Removing an app

Omitting an entry is **not** a removal: a client with a warm cache keeps serving
what it already has. Removal is positive data, so add a tombstone to `removed`:

```json
{ "name": "my-app", "reason": "withdrawn", "since": "2026-08-01", "advice": "keep" }
```

`advice` says what to do about an already-installed copy. It defaults to `keep`;
only a yank escalates to `uninstall`.

### `advice` is a remote instruction — two rules for whoever writes the client

`advice: "uninstall"` is a fetched document telling a client to remove software
the user already has installed. That is a kill switch, and it is worth writing
the constraints down here because the client read path does not exist yet and
this contract is what its author will read as the spec:

1. **A client must not act on `advice` from an unsigned document.** A signature
   is the acceptance gate for Official trust. Until signing exists, `advice`
   carries no authority and a client should ignore it rather than honor it.
2. **`uninstall` prompts, it does not execute silently.** Removing an installed
   app is the user's decision; the catalog's role is to surface the reason.

Ignoring a tombstone's *listing* is not on the table — a tombstone still hides a
withdrawn app from the store. These rules are only about acting on an installed
copy.

## Signatures are detached, necessarily

Every document here sets `additionalProperties: false` and defines no signature
field, so a signature cannot be inlined later without a breaking schema change.
That is intentional: the signature travels alongside the payload as a detached
sidecar, which also means the bytes a client verifies are exactly the bytes it
parses. Nobody should later "add a `signature` field" — the slot is absent by
design, not by omission.

## Not yet implemented

The publish pipeline (resolve refs to commits → bake generated fields from each
app's `app.json` → stamp → **sign** → publish) is not in this repository yet.
Until it lands there is no published output, and nothing here reaches a client.

Signing is a release blocker rather than a nicety: a signature is the acceptance
gate for Official trust, so the pipeline must fail closed without a key rather
than publish an unsigned document. Key custody is still unassigned.
