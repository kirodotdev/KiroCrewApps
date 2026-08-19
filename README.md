# KiroCrewApps

The official app catalog for the KiroCrew App Store, plus the editorial feed
that decides how the store presents it.

This repository holds **data and its contract**, not code. Clients fetch the
published output at runtime, which is the point: the storefront changes when
this repository changes, with no client release.

The published catalog is the store's **inventory, not just its copy**: a
KiroCrew client installs a `git`-source entry by fetching exactly the commit the
published document pins (`source.ref`), and reads update availability from the
entry's `version` field rather than any branch tip. Publishing a new entry here
is what makes a third-party app installable — previously that required shipping
a KiroCrew release with an updated bundled seed.

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
| `tools/publish.py` | Resolve → bake → stamp → sign the published documents |
| `tools/verify_dist.py` | Verifies published artifacts against `keys/*.pub` |
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
The pin is load-bearing on the client side: an install fetches that exact commit
and hard-fails on any mismatch (there is no branch fallback), so "revision N of
the catalog" delivers the same bytes to every user, with the published `version`
field — not a branch tip — carrying the update signal.
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

Then set `"categories": ["my-category"]` on the app's own entry in
`catalog/official-registry.json`, naming exactly one id that `catalog/editorial.json`
declares. Membership lives on the app rather than in a list somewhere else, so an
app and its placement are one edit and a reference to an app that does not exist
cannot be written down.
An app in no category still appears — it lands in the default bucket rather than
being hidden — but the validator will say so, since the usual cause is a
forgotten edit.

## What the gate enforces

Beyond per-document schema validation, `tools/validate.py` checks the
invariants that span both files — the ones that validate fine in isolation and
then render wrong in the store:

- Every section reference resolves to a declared, non-tombstoned app -- `appRef`
  on an `app` section, each `appRefs` entry on a `collection`.
- An app is in **at most one** category. A partitioned rail is the whole point
  of the taxonomy; an app that belongs in more than one place is served by a
  `collection` section or by search keywords, neither of which changes where
  the taxonomy files it.
- `categories[].order` values are unique, so the rail sequence does not depend
  on array position.
- No duplicate app names or category ids.
- A reinstatement has a matching tombstone. A reinstatement is the only thing
  that clears a persisted tombstone, so one with a typo'd name would otherwise
  be a silent no-op.

## Two section types, and the one place they differ on artwork

Discover's layout is a list of sections, each either an `app` (one app, headed by
its own name) or a `collection` (two to six apps under a curator's `title`).

`artwork` is **required on an `app` section and optional on a `collection`**. The
asymmetry is not an oversight:

- The client draws **editorial art or nothing**. It deliberately does not fall
  back to the app's own hero image — that art argues for one app, and borrowing
  it would illustrate a curator's placement with the author's claim. On a
  collection it would be worse still, since the art would come from whichever
  member happens to be first and would silently promote it.
- So an `app` section with no artwork renders as a **text-only card in the
  loudest slot on the page**, which serves the app worse than not featuring it at
  all. Requiring the picture keeps that state unreachable by omission rather than
  merely discouraged.
- A collection reads fine without one: it already shows several named apps under
  a stated theme.

Artwork is raster only (`png` / `webp` / `jpg`), authored 16:9 at 1600x900 and
capped at 1MB — same whitelist as icons, because an SVG served from our own
origin is an executing document on our domain. Commit the file under
`catalog/assets/editorial/` and reference it as a repo-relative path; the publish
step replaces that path with a content-addressed hosted one.

## Removing an app

Omitting an entry is **not** a removal: a client with a warm cache keeps serving
what it already has. Removal is positive data, so add a tombstone to `removed`:

```json
{ "name": "my-app", "reason": "withdrawn", "since": "2026-08-01", "advice": "keep" }
```

`advice` says what to do about an already-installed copy. It defaults to `keep`;
only a yank escalates to `uninstall`.

> **Operational note — current KiroCrew clients refuse tombstones outright.**
> The shipped client implements no tombstone resolution (date precedence,
> reinstatement clearing, the fail-closed tie rule), and implementing half of
> that mechanism would be worse than none: a withdrawn app must never render
> because the resolver was partial. So a published document carrying a
> non-empty `removed` or `reinstated` list is refused as a whole and the client
> falls back to its bundled seed — publishing the first tombstone today would
> degrade every store to offline listings, not hide one app. Land tombstone
> resolution in the client (or delete the mechanism from this contract) before
> publishing one.

### `advice` is a remote instruction — two rules for whoever writes the client

`advice: "uninstall"` is a fetched document telling a client to remove software
the user already has installed. That is a kill switch, and it is worth writing
the constraints down here because the `advice` read path still does not exist
(clients today refuse the whole document instead — see the note above) and
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

## The publish pipeline

`tools/publish.py` compiles the authored catalog into the documents clients
fetch. Each step exists to remove a human's ability to get it wrong:

| Step | What it does | Why it is not a human's job |
|---|---|---|
| **validate** | Runs the same gate as CI | Never sign something the gate would reject |
| **resolve** | Turns each branch/tag into a commit | A signed index naming `main` signs nothing about the bytes anyone receives |
| **bake** | Copies display fields from each app's `app.json` | Curators cannot author these, so the store's copy cannot drift from the app |
| **stamp** | Adds `generatedAt` and a content-derived `revision` | Revisions are immutable per publish |
| **sign** | Writes a detached ed25519 sidecar | A signature is the acceptance gate for Official trust |

```bash
# offline: exercises stamping and schema conformance, resolves nothing
python tools/publish.py --out dist --dry-run

# real: signs with the KMS key named by the id/ARN/alias
KIROCREW_REGISTRY_KMS_KEY_ID=alias/kirocrew-apps-registry python tools/publish.py --out dist
```

Output is `official-registry.json`, `editorial.json`, and a `.sig` sidecar for
each.

The private half never leaves KMS. Publishing asks for a signature over a digest
it computed; it cannot read key material, so access to a runner buys signing for
the life of that session rather than a key to keep. Before signing anything, the
signer resolves the key's public half and requires the derived keyId to match a
key published in `keys/` — a mistyped id fails the publish instead of minting
signatures no reader can verify.

### Signing fails closed

With no key configured, publishing **exits non-zero and writes nothing**. An
unsigned catalog is not a lesser product — it is a document a client cannot
distinguish from an attacker's copy of it. `.github/workflows/publish.yml`
inherits this: an unset `REGISTRY_KMS_KEY_ID` variable fails the run.

### `summary` is derived, not truncated

Manifest `description` is detail-view body copy and routinely runs past 400
characters, well over `summary`'s 200-char cap — so this is the normal path, not
an edge case. The pipeline takes the **first sentence**, which produces real list
copy instead of a sentence severed mid-clause. Only a first sentence that is
itself over-long gets truncated, and that is reported as a warning.

### Cloning repositories we do not control

Resolve and bake both talk to third-party git remotes, so the git invocations are
hardened at the point of execution rather than delegating safety upward to the
schema:

- `protocol.ext.allow=never` — `ext::` hands a command line to a shell
- `GIT_ALLOW_PROTOCOL=https` — every other transport is refused outright
- `credential.helper=` and `GIT_TERMINAL_PROMPT=0` — no tier of the registry
  confers clone credentials, so a fetch needing them must fail rather than
  quietly succeed as the CI runner
- `submodule.recurse=false` — submodules are a second, attacker-controlled URL list

Resolve-then-fetch is two round trips, so after fetching the pipeline verifies
`HEAD` equals the commit it resolved and that the object is a **commit** — a ref
that moved in between, or an annotated tag's object id, would otherwise publish
bytes that disagree with the pin.

## Where it gets served

```
https://apps.crew.kiro.dev/official-registry.json
https://apps.crew.kiro.dev/editorial.json
```

`docs/distribution.md` has the bucket, the OIDC role, the object layout, and the
CloudFront/DNS steps. **Not reachable yet** — `.github/workflows/s3-publish.yml`
skips with a notice until the bucket and role exist, so nothing in this
repository reaches a client today.

GitHub Pages was tried first and is not available: Pages creation is disabled
org-wide for `kirodotdev`.

The signing key is a CDK-owned KMS key (`RSA_3072`, `SIGN_VERIFY`, alias
`alias/kirocrew-apps-registry`) in the external-apps account, reachable from CI
by the OIDC role. Set `REGISTRY_KMS_KEY_ID` to its alias or ARN to enable a real
publish; with it unset the workflow skips the upload rather than publishing
unsigned.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers how a change gets reviewed — what
listing an app requires, what to run before opening a pull request, and how the
review lanes read [AUTOSDE.yaml](AUTOSDE.yaml). Report problems as a
[GitHub issue](https://github.com/kirodotdev/KiroCrewApps/issues); report
vulnerabilities privately per [SECURITY.md](SECURITY.md), which also says why a
listed third-party app is out of scope.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Applications
listed in the catalog are not covered by it; each is governed by the terms of its
own repository.
