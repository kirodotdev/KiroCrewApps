#!/usr/bin/env bash
# Upload dist/assets with per-extension content types.
#
# `aws s3 sync --content-type` applies ONE value to every object the call
# uploads, so the documents and the icons cannot share a sync: a PNG served as
# application/json does not render in an <img>. One pass per extension is the
# only way the CLI expresses "type depends on the file".
#
# Icons are content-addressed (the filename is the sha256 of the bytes), so they
# are immutable in both destinations -- the rolling pointer's no-store policy is
# for the documents, which change meaning at the same URL. An icon URL cannot.
#
# The extension list must stay in step with ICON_EXT_ALLOWED in tools/publish.py;
# an extension publish accepts and this script does not upload would land in S3
# with whatever type the CLI guessed, which is the bug this file exists to fix.
set -euo pipefail

DEST="${1:?usage: upload-assets.sh s3://bucket/prefix/}"

if [ ! -d dist/assets ]; then
  echo "no dist/assets to upload"
  exit 0
fi

upload() {
  local pattern="$1" type="$2"
  # --exclude "*" then --include narrows the sync to one extension. Without the
  # blanket exclude, sync would upload everything with this one content type.
  aws s3 sync dist/assets "${DEST}assets/" \
    --exclude "*" \
    --include "$pattern" \
    --cache-control "public, max-age=31536000, immutable" \
    --content-type "$type" \
    --no-progress
}

upload "*.png" "image/png"
upload "*.jpg" "image/jpeg"
upload "*.jpeg" "image/jpeg"
upload "*.webp" "image/webp"
# Served as image/svg+xml so an <img> renders it. A top-level navigation to this
# URL would execute script inside the document, which is why publish screens
# every SVG for script, event handlers and external references before hosting it.
upload "*.svg" "image/svg+xml"

echo "uploaded dist/assets to ${DEST}assets/"
