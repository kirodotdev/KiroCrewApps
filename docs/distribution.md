# Distribution

How the signed catalog gets from this repository to a URL clients can fetch.

**Target URL:**

```
https://apps.crew.kiro.dev/official-registry.json
https://apps.crew.kiro.dev/editorial.json
```

Current state: **not yet reachable.** The pipeline produces signed artifacts and
`.github/workflows/s3-publish.yml` is ready to upload them, but it skips with a
notice until the bucket and role below exist.

## Why not GitHub Pages

Tried first, because it needs no AWS. GitHub **Pages creation is disabled
org-wide** for `kirodotdev` (`422: GitHub organization administrators disabled
Pages creation`), so it is not an option without an org policy change.

## A dedicated hostname, not a path on the release CDN

`apps.crew.kiro.dev` gets its own CloudFront distribution rather than a new
behaviour on the one serving `download.crew.kiro.dev`. Worth the extra
distribution because the two have genuinely different needs:

- **Different cache semantics.** Release binaries are immutable and cached hard.
  This catalog's primary object is a rolling pointer that must never be cached.
  Co-tenanting them means one distribution whose behaviours contradict each other,
  and a misordered path pattern silently caches the pointer.
- **Independent failure and change.** Invalidations, logs, WAF rules and origin
  changes stay scoped to the catalog. A mistake here cannot affect installer
  downloads.
- **A clean public surface.** Clients get a hostname that means one thing, and the
  URL carries no path prefix inherited from someone else's bucket layout.

## Account: same one, separate bucket, narrow role

The bucket lives in **`kirocrew-publish` (116101834266)**, in its own bucket,
written by a role that can reach nothing else.

Reasoning, since "separate account" is the obvious alternative:

- The isolation a separate account buys is achieved almost entirely by IAM
  scoping. A role that can only write one dedicated bucket cannot touch release
  binaries whether or not an account boundary exists.
- The `crew.kiro.dev` DNS zone is already here. A separate account would mean
  either delegating a subdomain or managing records cross-account, which is more
  moving parts than the isolation is worth at this size.
- A new account carries permanent overhead — ownership, bindle, billing, on-call —
  against a catalog measured in kilobytes.

**What would change this:** if the account's existing GitHub OIDC trust is broad
(one permissive role shared by workflows), adding a second repository to it is
worse than starting a separate account. Check the existing trust policy before
provisioning; the role below is deliberately new and narrow rather than a reuse of
whatever the release workflows assume.

The eventual case for splitting is real but later: this catalog is data that
*references third-party repositories*, while the release bucket holds first-party
built binaries. When the catalog gets its own signing ceremony those become
different trust domains — a bucket copy and a DNS change, not a redesign.

## Object layout

A dedicated hostname means no prefix; keys sit at the root.

```
/official-registry.json                 <- rolling pointer, no-store
/official-registry.json.sig
/editorial.json
/editorial.json.sig
/keys/*.pub                             <- verification keys
/revisions/<revision>/…                 <- immutable copies, cached hard
/assets/icons/<sha256>.<ext>            <- hosted third-party app icons
/assets/editorial/<sha256>.<ext>        <- hosted editorial artwork
/app-assets/…                           <- RESERVED, see below
```

Clients fetch the root paths. The per-revision copies exist so a publish can be
audited or pinned after the fact.

`/assets/` holds image bytes the catalog hosts rather than links to. Both lanes
are content-addressed: the filename IS the sha256 of the bytes, and that
filename appears in a document that is signed — so one signature covers every
image, and a client verifies a download by hashing it against its own path. The
URL is therefore immutable and cacheable forever, and two entries shipping the
same file converge on one object.

The two lanes differ only in where the bytes come from. An icon under
`assets/icons/` is read from the app author's repository at the pinned commit;
artwork under `assets/editorial/` is a file a curator committed to THIS
repository, referenced from a section as a repo-relative path (`art/hero.png`)
that the publish step replaces with the hosted path. `tools/verify_dist.py`
checks both before anything is uploaded.

`/app-assets/` is reserved, not yet used: app manifests already carry
`iconUrl` and `heroImage` values like `/app-assets/<app>/icon.svg`, and this
hostname is where those will be served. Reserving it now keeps a future asset
lane from colliding with a catalog document name.

**The two-stage upload order is load-bearing.** The immutable copy is written
first, so the pointer never names a revision that is not yet retrievable — a
reader arriving mid-publish gets the previous revision, stale but whole and
correctly signed, instead of a 404.

**Revision keys are write-once.** Re-publishing a revision key with different
bytes is what makes edge caches disagree: some serve old bytes while a fresh
pointer advertises the new digest, and signature verification then fails for some
readers and not others. Revision ids are content-derived, so identical content
reuses a key harmlessly and changed content always gets a new one.

**The pointer is `no-store`, not merely short-lived.** A cached pointer is exactly
how a client keeps missing a tombstone, and a withdrawn app that stays visible is
the failure this catalog exists to prevent. Caching belongs on the immutable
objects, which cannot go stale by construction.

## Provisioning

### 1. Bucket

Private, no public access — reads come through CloudFront with origin access
control, so the bucket itself never needs to be public.

```bash
aws s3api create-bucket --bucket kirocrew-apps-catalog --region us-east-1
aws s3api put-public-access-block --bucket kirocrew-apps-catalog \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
aws s3api put-bucket-versioning --bucket kirocrew-apps-catalog \
  --versioning-configuration Status=Enabled
```

Versioning matters more than usual: the rolling pointer is overwritten every
publish and is the one object with no immutable copy of its own history.

### 2. Role assumed via GitHub OIDC

No long-lived AWS access key is stored in this repository. Trust is scoped to this
repository **and** to `main`, so a fork or feature branch cannot assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::116101834266:oidc-provider/<gh-oidc-host>" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "<gh-oidc-host>:aud": "sts.amazonaws.com",
        "<gh-oidc-host>:sub": "repo:kirodotdev/KiroCrewApps:ref:refs/heads/main"
      }
    }
  }]
}
```

Substitute the org's GitHub OIDC provider host for `<gh-oidc-host>`. Use
`StringEquals` on `sub`, never `StringLike` with a wildcard — a wildcarded subject
is how these roles end up assumable from any branch.

Permissions, confined to the one bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject"],
      "Resource": "arn:aws:s3:::kirocrew-apps-catalog/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::kirocrew-apps-catalog"
    }
  ]
}
```

No `s3:DeleteObject`: publishing never needs to remove anything, and withholding
it means a compromised workflow cannot erase published history. Retiring an app is
a tombstone in the catalog, not a deletion.

### 3. Repository variables

```bash
gh variable set CATALOG_BUCKET --repo kirodotdev/KiroCrewApps --body kirocrew-apps-catalog
gh variable set AWS_ROLE_ARN   --repo kirodotdev/KiroCrewApps \
  --body arn:aws:iam::116101834266:role/KiroCrewAppsCatalogPublisher
```

The workflow skips with a notice until both are set, so it will not fail
obscurely in the meantime.

### 4. Certificate, distribution, DNS

The certificate **must be issued in `us-east-1`** regardless of where the bucket
lives — CloudFront only reads certificates from that region, and this is the step
most likely to be done twice.

```bash
aws acm request-certificate --region us-east-1 \
  --domain-name apps.crew.kiro.dev --validation-method DNS
```

Then a distribution with:

- origin: the bucket, via **origin access control** (keeps the bucket private)
- alternate domain name: `apps.crew.kiro.dev`, with the certificate above
- default root object: none — this serves documents, not a site
- two cache behaviours matching the layout:
  - `revisions/*` → long-lived, immutable
  - everything else → pass-through / no caching, for the rolling pointer

Order matters: the `revisions/*` pattern must precede the default, or the
immutable objects inherit pass-through and lose their whole benefit.

Finally an `A`/`AAAA` alias record for `apps.crew.kiro.dev` in the `crew.kiro.dev`
hosted zone pointing at the distribution.

Because revision keys are write-once, that path never needs invalidation — only
the pointer does, and `no-store` handles it.

## Signing key

Currently a **bootstrap** key — see `keys/README.md`. No client should trust it,
and it is replaced rather than promoted once custody for a production root is
assigned. That is the last thing standing between this and a URL clients can
rely on.
