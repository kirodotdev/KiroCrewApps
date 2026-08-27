# Contributing to KiroCrewApps

Thanks for your interest in contributing. This repository is the official app
catalog for the Kiro Crew App Store, so a merge here changes the storefront for
every client with no release in between. That shapes most of the rules below.

The [README](README.md) is the reference for mechanics — the document layout, what
the validator enforces, how removal works, and what the publish pipeline does. This
file covers how to get a change reviewed.

## What kind of change this is

Almost every contribution falls into one of three shapes, and they are reviewed
differently:

| Shape | What it touches | What reviewers look for |
|---|---|---|
| **Listing an app** | `catalog/official-registry.json`, `catalog/editorial.json` | Is the app real, installable, and in the right category |
| **Editorial curation** | `catalog/editorial.json` | Does the Discover layout still partition cleanly |
| **Contract or tooling** | `schema/`, `tools/`, `tests/` | Does the gate still reject what it should |

## Listing an app

You do not need to be the app's author to propose it, but the app has to be
installable as published. An entry is two fields:

```json
{ "name": "my-app", "source": { "type": "git", "url": "https://github.com/org/my-app.git", "ref": "main" } }
```

Then set `"categories"` on that same entry, naming exactly one category id that
`catalog/editorial.json` declares. See the README for why membership lives on the
app rather than in a separate list.

What a reviewer will check, so you can check it first:

- The repository is public and clones over `https` without credentials. No other
  transport is accepted, and nothing in this repository confers clone credentials.
- The repository root (or the `subdirectory` you name) has a valid `app.json`.
  Display copy — `displayName`, `summary`, `author`, `tags` — is **baked from that
  manifest at publish time and must not be written into the catalog**. If the copy
  in the store is wrong, fix the app's manifest, not this file.
- The app does what its manifest says. A listing is an endorsement to the extent
  that it makes the app installable in one click from inside Kiro Crew.

## Contract and tooling changes

`tools/publish.py` reads manifests from repositories we do not control, so
[`AUTOSDE.yaml`](AUTOSDE.yaml) records the rules that govern this code and which of
them block a merge. Read it before changing the pipeline — every blocking rule in it
is there because the defect it describes actually happened here.

Two consequences worth stating up front:

- **Nothing read from a manifest may raise.** A raise propagates out of `publish()`
  and halts the whole run, so one publisher's broken file would stop every app's
  release. Degrade the single field and emit a warning instead.
- **A new gate needs a test that proves it bites.** The contract tests run before
  the validator in CI precisely because a validator with every check silently
  broken passes just as happily as a working one.

## Before you open a pull request

```bash
pip install -r tools/requirements.txt pytest

pytest tests/ -q          # contract tests first — they prove the gate still bites
python tools/validate.py  # the same verdict CI will give
python tools/format.py    # normalize; CI runs --check
```

`format.py` is not cosmetic here. These are hand-edited data files, and a
normalized form keeps the review diff to the semantic change instead of a reflow.

## Pull request workflow

Open the pull request against `main`. Beyond the deterministic gate above, two
agentic review lanes run on same-repo pull requests and read `AUTOSDE.yaml` from the
**base** commit, so a pull request cannot weaken the rules that govern it. A lane
blocks only by emitting an explicit block marker; anything else it says is advisory.

A third agentic lane runs when a pull request adds or re-pins a **git-type
catalog entry**: the app-readiness review checks out each affected app
repository at the pinned ref and judges it against
`review/app-readiness-rules.md` (also read from the base commit). Blocking
tiers there mean "this app cannot install or silently degrades as pinned";
advisory tiers surface reliability and store-metadata gaps for the app's
author. Fixes for its findings land in the app's own repository, not here —
re-pin the entry to the fixed ref and the lane re-reviews.

Say in the description what you verified rather than what you intended. For a
listing, that means you cloned the repository at the ref you wrote down and looked
at the manifest the store will bake its copy from.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <summary>

<body — what and why, not how>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Rules: imperative mood, lowercase summary, no trailing period, wrap body at 72 chars.

## Reporting problems

Open a [GitHub issue](https://github.com/kirodotdev/KiroCrewApps/issues). If the
problem is a listed app misbehaving rather than the catalog being wrong, say which,
because the remedies differ — a bad entry is an edit here, a bad app is a tombstone.

## Security issues

**Do not** report security vulnerabilities through public GitHub issues. See
[SECURITY.md](SECURITY.md) for responsible disclosure instructions and for what is
in scope, since a listed third-party app is not.

## Code of Conduct

This project has adopted a [Code of Conduct](CODE_OF_CONDUCT.md). Participating
means following it, and the file names where to report a concern.

## Licensing

KiroCrewApps is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for
the full text and [NOTICE](NOTICE) for attribution. Contributions are accepted under
the same license as the project.

Applications listed in the catalog are **not** covered by it — each is governed by
the terms of its own repository. Adding a listing does not relicense anything.
