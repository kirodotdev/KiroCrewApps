# Security Policy

## Reporting a Vulnerability

If you discover a potential security issue in this project, please **do not** create a public
GitHub issue. Instead, report it privately:

- **Email:** [kiro-crew-security-support@amazon.com](mailto:kiro-crew-security-support@amazon.com)
- **Subject prefix:** `[SECURITY]`

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within
7 days for critical issues.

## What is in scope

This repository publishes one signed document that every Kiro Crew client fetches and trusts,
and it builds that document by reading `app.json` manifests out of repositories we do not
control. Findings against that pipeline are in scope, and the ones worth reporting privately
rather than as an issue are:

- A way to make `tools/publish.py` emit a document that does not match what the authored
  catalog and the pinned commits say — a display field that can be forged, a pin that can be
  made to resolve to different bytes than the ones verified, a manifest that can steer the
  publish beyond its own entry.
- A way to obtain a valid signature over material that was not published, or to make
  `tools/verify_dist.py` accept a document that the signing key did not sign.
- A way to make a client act on catalog data beyond installing what the pin names — in
  particular anything that turns a fetched document into code execution or into removing
  software the user did not agree to remove.
- A way to reach the signing key or the publishing role from a pull request.

## What is not in scope

- **Third-party applications listed in the catalog.** An entry is a URL and a commit; the
  application it points at is governed by its own repository and its own security policy. If
  a listed application is malicious, report it here as a **catalog** problem — we can
  tombstone it — but the vulnerability itself belongs to that project.
- **Content of an app's own `app.json`.** The pipeline treats every manifest as untrusted
  input by design; a manifest that is merely wrong or sloppy is a validation bug, so open a
  normal issue for it.

## Supported versions

Only the currently published revision of the catalog is supported. Published revisions are
immutable, so a correction is a new revision rather than an edit to an existing one.
