"""Contract tests for tools/changed_entries.py.

The app-readiness lane fetches and AI-reviews every repository this script
emits, so both directions matter: an entry it wrongly drops is an app that
ships unreviewed, and an entry it wrongly emits burns a review on a repo the
PR never touched. These tests pin the boundary from both sides.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from changed_entries import changed_git_entries  # noqa: E402


def _git(name: str, url: str = "", ref: str = "main", subdir: str = "") -> dict:
    source = {"type": "git", "url": url or f"https://example.com/{name}", "ref": ref}
    if subdir:
        source["subdir"] = subdir
    return {"name": name, "source": source}


def _builtin(name: str) -> dict:
    return {
        "name": name,
        "source": {"type": "builtin", "manifestFrom": {"url": "https://example.com/mono", "ref": "abc"}},
    }


class TestEmits:
    def test_new_git_entry_is_emitted(self):
        base = {"apps": []}
        head = {"apps": [_git("dyna")]}
        assert changed_git_entries(base, head) == [
            {"name": "dyna", "url": "https://example.com/dyna", "ref": "main", "subdir": ""}
        ]

    def test_ref_repin_is_emitted(self):
        base = {"apps": [_git("dyna", ref="main")]}
        head = {"apps": [_git("dyna", ref="v2.0.0")]}
        assert [e["ref"] for e in changed_git_entries(base, head)] == ["v2.0.0"]

    def test_subdir_change_is_emitted(self):
        base = {"apps": [_git("dyna", subdir="apps/one")]}
        head = {"apps": [_git("dyna", subdir="apps/two")]}
        assert [e["subdir"] for e in changed_git_entries(base, head)] == ["apps/two"]

    def test_adding_subdir_counts_as_repin(self):
        base = {"apps": [_git("dyna")]}
        head = {"apps": [_git("dyna", subdir="apps/one")]}
        assert [e["name"] for e in changed_git_entries(base, head)] == ["dyna"]

    def test_url_move_is_emitted(self):
        base = {"apps": [_git("dyna", url="https://old.example.com/dyna")]}
        head = {"apps": [_git("dyna", url="https://new.example.com/dyna")]}
        assert [e["url"] for e in changed_git_entries(base, head)] == ["https://new.example.com/dyna"]

    def test_builtin_flipping_to_git_is_emitted(self):
        base = {"apps": [_builtin("dyna")]}
        head = {"apps": [_git("dyna")]}
        assert [e["name"] for e in changed_git_entries(base, head)] == ["dyna"]

    def test_adding_explicit_ref_counts_as_repin(self):
        base_entry = _git("dyna")
        del base_entry["source"]["ref"]
        base = {"apps": [base_entry]}
        head = {"apps": [_git("dyna", ref="main")]}
        assert [e["name"] for e in changed_git_entries(base, head)] == ["dyna"]

    def test_output_is_sorted_by_name(self):
        base = {"apps": []}
        head = {"apps": [_git("zed"), _git("alpha")]}
        assert [e["name"] for e in changed_git_entries(base, head)] == ["alpha", "zed"]


class TestStaysSilent:
    def test_untouched_entry_is_not_emitted(self):
        doc = {"apps": [_git("dyna")]}
        assert changed_git_entries(doc, doc) == []

    def test_curation_only_change_is_not_emitted(self):
        entry = _git("dyna")
        base = {"apps": [entry]}
        head_entry = dict(entry, note="better note", categories=["productivity"])
        head = {"apps": [head_entry]}
        assert changed_git_entries(base, head) == []

    def test_builtin_entry_is_never_emitted(self):
        base = {"apps": []}
        head = {"apps": [_builtin("agent-worlds")]}
        assert changed_git_entries(base, head) == []

    def test_removal_is_not_emitted(self):
        base = {"apps": [_git("dyna")]}
        head = {"apps": []}
        assert changed_git_entries(base, head) == []

    def test_git_flipping_to_builtin_is_not_emitted(self):
        base = {"apps": [_git("dyna")]}
        head = {"apps": [_builtin("dyna")]}
        assert changed_git_entries(base, head) == []


class TestMalformedInputDegrades:
    """Schema rejection is validate.py's report; this script must not crash over it."""

    def test_non_dict_documents_yield_empty(self):
        assert changed_git_entries(None, [1, 2]) == []

    def test_entry_missing_name_or_url_is_skipped(self):
        head = {
            "apps": [
                {"source": {"type": "git", "url": "https://example.com/x"}},
                {"name": "y", "source": {"type": "git"}},
                {"name": "ok", "source": {"type": "git", "url": "https://example.com/ok"}},
            ]
        }
        assert [e["name"] for e in changed_git_entries({}, head)] == ["ok"]

    def test_non_dict_entry_and_non_string_ref_are_tolerated(self):
        head = {
            "apps": [
                "garbage",
                {"name": "ok", "source": {"type": "git", "url": "https://example.com/ok", "ref": 7}},
            ]
        }
        assert changed_git_entries({}, head) == [
            {"name": "ok", "url": "https://example.com/ok", "ref": "", "subdir": ""}
        ]

    def test_empty_base_treats_every_head_entry_as_new(self):
        head = {"apps": [_git("a"), _git("b")]}
        assert len(changed_git_entries({}, head)) == 2
