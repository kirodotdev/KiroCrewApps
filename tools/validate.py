#!/usr/bin/env python3
"""Validate the authored catalog against the contract.

This is the PR gate, and it is deliberately OFFLINE and hermetic: it clones
nothing, resolves nothing, and reaches no network. Everything it checks is a
property of the files in this repository, so a curator gets the same verdict
locally that CI gives, in milliseconds.

The checks fall into two layers:

*Schema* -- each document against its own JSON Schema. The authored registry is
checked against ``authored-registry.schema.json`` (NOT the published one): a
curator writes a branch or tag and no generated fields, so validating authored
input against the wire contract would reject perfectly good input and, worse,
would accept hand-written presentation fields.

*Cross-document* -- the invariants no single schema can express, because they
span the two files or compare elements to each other. These are the ones worth
having: a dangling ``appRefs`` entry or an app silently landing in two
categories is exactly the sort of thing that validates fine per-document and
then renders wrong in the store.

Exit code is 0 only when the catalog is publishable.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:  # pragma: no cover - surfaced as a clear operator error
    sys.stderr.write(
        "error: jsonschema is required.\n"
        "       pip install -r tools/requirements.txt\n"
    )
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schema"
CATALOG_DIR = ROOT / "catalog"


class Findings:
    """Accumulates every problem so one run reports all of them.

    Failing on the first error would make a curator re-run the gate once per
    mistake; a catalog edit that breaks three references should report three.
    """

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def ok(self) -> bool:
        return not self.errors


def load_json(path: Path, findings: Findings) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        findings.error(f"{path.relative_to(ROOT)}: missing")
    except json.JSONDecodeError as exc:
        findings.error(f"{path.relative_to(ROOT)}: invalid JSON: {exc}")
    return None


def check_schema(doc: Any, schema_path: Path, label: str, findings: Findings) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    # FormatChecker must be passed explicitly: jsonschema treats `format` as an
    # annotation by default, so without this a `since` of "NOT-A-DATE" validates
    # cleanly -- and then flows into date comparison below.
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    # Sort so the report is stable across runs; unsorted errors come back in
    # whatever order the validator walked the tree, which makes CI diffs noisy.
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        findings.error(f"{label}: {loc}: {err.message}")


def parse_day(value: Any) -> date | None:
    """Parse an ISO date, or None if it is not one.

    Comparing these as STRINGS is not safe even though ISO dates sort lexically:
    a malformed value like "9999-99-99" compares greater than every real date,
    so a bogus reinstatement would outrank a tombstone and silently bring a
    withdrawn app back. Parsing makes that input unrepresentable instead.
    """
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def latest_by_name(
    records: Any, kind: str, findings: Findings
) -> dict[str, date]:
    """Collapse append-only records to the newest valid date per app name."""
    latest: dict[str, date] = {}
    for record in records or []:
        if not isinstance(record, dict):
            continue
        name = record.get("name")
        if not isinstance(name, str):
            continue
        day = parse_day(record.get("since"))
        if day is None:
            # Fail closed and loudly: a record whose date cannot be ordered
            # cannot be resolved against its counterpart, and guessing which
            # one wins is exactly the ambiguity worth refusing.
            findings.error(
                f"registry: {kind} for {name!r} has an invalid 'since' "
                f"({record.get('since')!r}); expected an ISO date (YYYY-MM-DD)"
            )
            continue
        if name not in latest or day > latest[name]:
            latest[name] = day
    return latest


def check_cross_document(
    registry: dict[str, Any],
    editorial: dict[str, Any],
    findings: Findings,
) -> None:
    """Enforce the invariants that span the two documents."""
    apps = registry.get("apps") or []
    names = [a.get("name") for a in apps if isinstance(a, dict)]

    # An app declared twice is ambiguous: the two entries can name different
    # sources, and which one wins would come down to merge order.
    for name, count in Counter(names).items():
        if count > 1:
            findings.error(f"registry: app {name!r} declared {count} times")

    declared = set(names)

    # Effective removal state, NOT the raw `removed` list. Both lists are
    # append-only history, so a name can legitimately appear in each: removed,
    # then later reinstated. A reinstatement is the only thing that clears a
    # persisted tombstone, so whichever record is NEWER decides whether the app
    # is live. Treating `removed` as the answer would wrongly reject every
    # reference to a reinstated app.
    removals = latest_by_name(registry.get("removed"), "tombstone", findings)
    reinstatements = latest_by_name(registry.get("reinstated"), "reinstatement", findings)

    # A reinstatement for a name that was never tombstoned is almost certainly a
    # typo -- and a silent one, because clearing nothing looks like success.
    for name in reinstatements:
        if name not in removals:
            findings.error(
                f"registry: reinstatement for {name!r} has no "
                f"matching tombstone in 'removed'"
            )

    tombstoned = {
        name
        for name, removed_on in removals.items()
        # Live again only if the reinstatement is strictly newer than the
        # removal it clears. Equal dates keep the app removed: a same-day pair
        # is ambiguous, and failing closed is the safe reading for a record
        # that may exist because an app was pulled for cause.
        if not (
            name in reinstatements and reinstatements[name] > removed_on
        )
    }

    categories = editorial.get("categories") or []

    # `order` drives the rail sequence. Duplicate orders make the sequence
    # depend on array position, which is invisible to whoever is editing.
    orders = [c.get("order") for c in categories if isinstance(c.get("order"), int)]
    for order, count in Counter(orders).items():
        if count > 1:
            findings.error(
                f"editorial: category order {order} used by {count} categories; "
                f"orders must be unique so the rail sequence is deterministic"
            )

    ids = [c.get("id") for c in categories if isinstance(c, dict)]
    for cid, count in Counter(ids).items():
        if count > 1:
            findings.error(f"editorial: category id {cid!r} declared {count} times")

    # Single-category membership, enforced by construction. A partitioned rail
    # is the whole point of the taxonomy; an app in two categories renders
    # twice and makes the counts disagree with the catalog. Cross-cutting
    # collections are what `rail` sections are for.
    owner: dict[str, str] = {}
    for cat in categories:
        if not isinstance(cat, dict):
            continue
        cid = cat.get("id")
        for ref in cat.get("appRefs") or []:
            if ref not in owner:
                owner[ref] = cid
            elif owner[ref] == cid:
                # Same category twice is a different mistake from being in two
                # categories, and "in categories 'a' and 'a'" reads as nonsense.
                findings.error(
                    f"editorial: app {ref!r} is listed twice in category {cid!r}"
                )
            else:
                findings.error(
                    f"editorial: app {ref!r} is in categories {owner[ref]!r} and "
                    f"{cid!r}; membership is single-valued (use a 'rail' section "
                    f"for cross-cutting collections)"
                )

    # Every reference must resolve through the registry. Editorial only ever
    # REFERENCES apps, which is what stops it inventing a phantom entry.
    def check_refs(refs: list[Any], where: str) -> None:
        for ref in refs:
            if ref not in declared:
                findings.error(f"{where}: appRef {ref!r} is not declared in the registry")
            elif ref in tombstoned:
                findings.error(f"{where}: appRef {ref!r} refers to a tombstoned app")

    for cat in categories:
        if isinstance(cat, dict):
            check_refs(cat.get("appRefs") or [], f"editorial: category {cat.get('id')!r}")

    for idx, section in enumerate(editorial.get("sections") or []):
        if not isinstance(section, dict):
            continue
        where = f"editorial: section[{idx}] ({section.get('type')})"
        if isinstance(section.get("appRef"), str):
            check_refs([section["appRef"]], where)
        check_refs(section.get("appRefs") or [], where)

    # Not fatal: a declared app in no category is legitimate and lands in the
    # default bucket rather than disappearing. Worth saying out loud, because
    # the usual cause is a forgotten membership edit.
    uncategorized = sorted(declared - set(owner) - tombstoned)
    if uncategorized:
        findings.warn(
            f"{len(uncategorized)} app(s) in no category, will render in the "
            f"default bucket: {', '.join(uncategorized)}"
        )


def validate(registry_path: Path, editorial_path: Path) -> Findings:
    findings = Findings()

    registry = load_json(registry_path, findings)
    editorial = load_json(editorial_path, findings)
    if registry is None or editorial is None:
        return findings

    check_schema(
        registry, SCHEMA_DIR / "authored-registry.schema.json", "registry", findings
    )
    check_schema(editorial, SCHEMA_DIR / "editorial.schema.json", "editorial", findings)

    # Cross-document checks assume both documents are the right SHAPE. Running
    # them on input that failed its schema produces cascading noise about
    # fields that were never valid to begin with.
    if findings.ok and isinstance(registry, dict) and isinstance(editorial, dict):
        check_cross_document(registry, editorial, findings)

    return findings


def main(argv: list[str]) -> int:
    registry_path = Path(argv[1]) if len(argv) > 1 else CATALOG_DIR / "official-registry.json"
    editorial_path = Path(argv[2]) if len(argv) > 2 else CATALOG_DIR / "editorial.json"

    findings = validate(registry_path, editorial_path)

    for warning in findings.warnings:
        print(f"warning: {warning}")
    for error in findings.errors:
        print(f"error: {error}")

    if findings.ok:
        print(f"OK: catalog is valid ({len(findings.warnings)} warning(s))")
        return 0
    print(f"FAILED: {len(findings.errors)} error(s)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
