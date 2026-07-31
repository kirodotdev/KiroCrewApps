#!/usr/bin/env python3
"""Normalize the authored catalog files in place.

These files are edited by hand, so without a canonical form every PR risks
carrying an incidental reflow alongside the real change -- and a reviewer
approving a catalog edit needs to see the edit, not a whitespace diff.

Deliberately does NOT sort keys: the authored order (name, then source) reads
in the order a curator thinks, and alphabetizing it would put `source` before
`name`. Only indentation and the trailing newline are enforced.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = ROOT / "catalog"


def normalize(path: Path) -> bool:
    """Rewrite ``path`` in canonical form. Returns True if it changed."""
    raw = path.read_text(encoding="utf-8")
    want = json.dumps(json.loads(raw), indent=2) + "\n"
    if raw == want:
        return False
    path.write_text(want, encoding="utf-8")
    return True


def is_normalized(path: Path) -> bool:
    raw = path.read_text(encoding="utf-8")
    return raw == json.dumps(json.loads(raw), indent=2) + "\n"


def main(argv: list[str]) -> int:
    args = argv[1:]
    check_only = "--check" in args
    args = [a for a in args if a != "--check"]

    paths = [Path(p) for p in args] or sorted(CATALOG_DIR.glob("*.json"))

    if check_only:
        drifted = [p for p in paths if not is_normalized(p)]
        for path in drifted:
            print(f"not normalized: {path.relative_to(ROOT)}")
        if drifted:
            print("run: python tools/format.py")
            return 1
        print(f"all {len(paths)} file(s) normalized")
        return 0

    changed = [p for p in paths if normalize(p)]
    for path in changed:
        print(f"formatted {path.relative_to(ROOT)}")
    if not changed:
        print("already normalized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
