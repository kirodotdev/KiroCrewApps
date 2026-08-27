#!/usr/bin/env python3
"""Emit the git-type registry entries a PR added or re-pinned.

The app-readiness review lane only wants to fetch and review app
repositories whose catalog coordinates this PR actually touched: an entry
that is new by name, or whose ``source.url`` / ``source.ref`` changed.
Everything else — builtin entries (their content ships from the KiroCrew
monorepo, which has its own CI), removed entries, entries whose only change
is curation text (author, note, categories) — is out of scope for that lane
and is deliberately not emitted.

Reads two authored-registry documents (base and head) and prints a JSON
array of ``{"name", "url", "ref", "subdir"}`` objects to stdout. Malformed
entries are
skipped rather than fatal: the schema gate (`tools/validate.py`) owns
rejecting them, and this script must not mask that report with a crash of
its own.

Usage:
    python tools/changed_entries.py --base <base.json> --head <head.json>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _git_entries(doc: Any) -> dict[str, dict[str, str]]:
    """Index a registry document's git-type entries by app name.

    Only entries carrying a usable name, a ``source.type`` of ``git`` and a
    non-empty URL participate. ``ref`` defaults to empty (publish resolves a
    missing ref itself); it still participates in change detection so that
    adding or removing an explicit ref counts as a re-pin.
    """
    out: dict[str, dict[str, str]] = {}
    if not isinstance(doc, dict):
        return out
    for entry in doc.get("apps") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        source = entry.get("source")
        if not isinstance(name, str) or not name or not isinstance(source, dict):
            continue
        if source.get("type") != "git":
            continue
        url = source.get("url")
        if not isinstance(url, str) or not url:
            continue
        ref = source.get("ref")
        subdir = source.get("subdir")
        out[name] = {
            "name": name,
            "url": url,
            "ref": ref if isinstance(ref, str) else "",
            "subdir": subdir if isinstance(subdir, str) else "",
        }
    return out


def changed_git_entries(base_doc: Any, head_doc: Any) -> list[dict[str, str]]:
    """Return head's git entries that are new or re-pinned relative to base.

    An entry that flips from builtin to git counts as new — the git source
    was never reviewed. One that flips from git to builtin drops out, same
    as a removal. ``subdir`` participates: pointing the same url+ref at a
    different directory selects a different app, which was never reviewed.
    """
    base = _git_entries(base_doc)
    head = _git_entries(head_doc)
    changed = [
        entry
        for name, entry in head.items()
        if name not in base
        or base[name]["url"] != entry["url"]
        or base[name]["ref"] != entry["ref"]
        or base[name]["subdir"] != entry["subdir"]
    ]
    changed.sort(key=lambda e: e["name"])
    return changed


def _load(path: Path) -> Any:
    """Parse one document; an unreadable/unparseable file is an EMPTY one.

    The base side can legitimately be empty (first commit of the catalog) and
    the head side's syntax errors are the schema gate's report to make. Both
    degrade to {} so the diff still runs: with an empty base every head entry
    is "new", which errs toward reviewing more, never less.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path, help="base-ref registry JSON")
    parser.add_argument("--head", required=True, type=Path, help="head-ref registry JSON")
    args = parser.parse_args(argv)
    changed = changed_git_entries(_load(args.base), _load(args.head))
    json.dump(changed, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
