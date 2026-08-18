"""Editorial artwork: ingestion, baking, and the integrity chain.

The rejection tests all assert the SECTION SURVIVES without its picture. That is
the contract: a bad image costs one placement its artwork, never the release.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

# `conftest.py` puts `tools/` itself on the path, so these are top-level modules
# rather than a `tools.` package -- matching every other test file here.
import publish  # noqa: E402
import verify_dist  # noqa: E402
from validate import Findings  # noqa: E402

ART_MAX_BYTES = publish.ART_MAX_BYTES
EDITORIAL_ASSET_DIR = publish.EDITORIAL_ASSET_DIR
EditorialAssets = publish.EditorialAssets
bake_editorial_artwork = publish.bake_editorial_artwork
build_editorial = publish.build_editorial
verify_hosted_artwork = verify_dist.verify_hosted_artwork

NOW = datetime(2026, 8, 13, 9, 0, 0, tzinfo=timezone.utc)


def png(width: int, height: int) -> bytes:
    """A real, minimal PNG so `png_dimensions` reads true values from it."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00" * (width * 3 + 1)))
        + chunk(b"IEND", b"")
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "art").mkdir()
    (tmp_path / "art" / "hero.png").write_bytes(png(1600, 900))
    (tmp_path / "art" / "hero-dark.png").write_bytes(png(1600, 900))
    return tmp_path


def section(**over):
    base = {"type": "app", "appRef": "demo", "artwork": {"ref": "art/hero.png"}}
    base.update(over)
    return base


class TestIngestion:
    def test_a_file_becomes_a_content_addressed_path(self, repo):
        f = Findings()
        assets = EditorialAssets(repo)
        got = assets.add("art/hero.png", "sections[0].artwork.ref", f)
        digest = hashlib.sha256((repo / "art/hero.png").read_bytes()).hexdigest()
        assert got == f"{EDITORIAL_ASSET_DIR}/{digest}.png"
        assert assets.files[got] == (repo / "art/hero.png").read_bytes()
        assert not f.errors

    def test_two_sections_sharing_one_image_converge_on_one_file(self, repo):
        f = Findings()
        assets = EditorialAssets(repo)
        a = assets.add("art/hero.png", "a", f)
        b = assets.add("art/hero.png", "b", f)
        assert a == b
        assert len(assets.files) == 1

    @pytest.mark.parametrize("name", ["art/hero.svg", "art/hero.gif", "art/hero", "art/hero.PNG.exe"])
    def test_a_type_the_catalog_does_not_host_is_refused(self, repo, name):
        # The file must EXIST and hold valid image bytes, otherwise the refusal
        # comes from "not a file" and the extension guard is never exercised --
        # a mutation removing the guard survived exactly that way.
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(png(1600, 900))
        f = Findings()
        assert EditorialAssets(repo).add(name, "where", f) is None
        assert any("does not host" in w for w in f.warnings), "refused for its TYPE, not its absence"
        assert not f.errors

    def test_a_path_escaping_the_repository_is_refused(self, repo, tmp_path):
        outside = tmp_path.parent / "secret.png"
        outside.write_bytes(png(16, 16))
        f = Findings()
        assert EditorialAssets(repo).add("../secret.png", "where", f) is None
        assert f.warnings

    def test_a_symlink_pointing_outside_is_refused(self, repo, tmp_path):
        outside = tmp_path.parent / "linked.png"
        outside.write_bytes(png(16, 16))
        link = repo / "art" / "sneaky.png"
        link.symlink_to(outside)
        f = Findings()
        assert EditorialAssets(repo).add("art/sneaky.png", "where", f) is None
        assert f.warnings

    @pytest.mark.parametrize("kind", ["self", "mutual"])
    def test_a_symlink_loop_costs_one_image_not_the_release(self, repo, kind):
        # `Path.resolve()` raises RuntimeError -- not OSError -- on a loop, so a
        # tuple listing only (OSError, ValueError) lets it escape and aborts the
        # whole publish. Both loop shapes, because platforms differ on which one
        # they detect first.
        if kind == "self":
            (repo / "art" / "loop.png").symlink_to("loop.png")
            target = "art/loop.png"
        else:
            (repo / "art" / "a.png").symlink_to("b.png")
            (repo / "art" / "b.png").symlink_to("a.png")
            target = "art/a.png"
        f = Findings()
        assert EditorialAssets(repo).add(target, "where", f) is None
        assert f.warnings and not f.errors

    def test_a_looping_link_does_not_stop_the_other_sections(self, repo):
        (repo / "art" / "loop.png").symlink_to("loop.png")
        f = Findings()
        doc = {"sections": [
            section(artwork={"ref": "art/loop.png"}),
            section(artwork={"ref": "art/hero.png"}),
        ]}
        out = bake_editorial_artwork(doc, EditorialAssets(repo), f)
        assert "artwork" not in out["sections"][0], "the broken one loses its picture"
        assert out["sections"][1]["artwork"]["ref"].startswith(f"{EDITORIAL_ASSET_DIR}/")

    def test_a_missing_file_is_refused(self, repo):
        f = Findings()
        assert EditorialAssets(repo).add("art/nope.png", "where", f) is None
        assert f.warnings

    def test_an_empty_file_is_refused(self, repo):
        (repo / "art" / "empty.png").write_bytes(b"")
        f = Findings()
        assert EditorialAssets(repo).add("art/empty.png", "where", f) is None
        assert f.warnings

    def test_an_oversized_file_is_refused_before_it_is_read(self, repo):
        big = repo / "art" / "big.png"
        big.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * (ART_MAX_BYTES + 1))
        f = Findings()
        assert EditorialAssets(repo).add("art/big.png", "where", f) is None
        assert any(str(ART_MAX_BYTES) in w for w in f.warnings)

    def test_a_wrong_aspect_warns_but_still_publishes(self, repo):
        (repo / "art" / "square.png").write_bytes(png(800, 800))
        f = Findings()
        got = EditorialAssets(repo).add("art/square.png", "where", f)
        assert got, "a mis-cropped image is a curation nit, not a refusal"
        assert any("16:9" in w for w in f.warnings)


class TestBaking:
    def test_authored_paths_are_replaced_by_hosted_ones(self, repo):
        f = Findings()
        doc = {"sections": [section(artwork={"ref": "art/hero.png", "refDark": "art/hero-dark.png"})]}
        out = bake_editorial_artwork(doc, EditorialAssets(repo), f)
        art = out["sections"][0]["artwork"]
        assert art["ref"].startswith(f"{EDITORIAL_ASSET_DIR}/")
        assert art["refDark"].startswith(f"{EDITORIAL_ASSET_DIR}/")

    def test_the_authored_document_is_not_mutated(self, repo):
        f = Findings()
        doc = {"sections": [section()]}
        before = json.dumps(doc, sort_keys=True)
        bake_editorial_artwork(doc, EditorialAssets(repo), f)
        assert json.dumps(doc, sort_keys=True) == before, "republish must be deterministic"

    def test_a_section_without_artwork_passes_through(self, repo):
        f = Findings()
        doc = {"sections": [{"type": "collection", "title": "Picks", "appRefs": ["a", "b"]}]}
        assert bake_editorial_artwork(doc, EditorialAssets(repo), f) == doc

    def test_losing_the_light_variant_drops_the_whole_block(self, repo):
        # `ref` is required by the schema, so a dark-only artwork object would
        # fail the published-schema check. Drop the block, keep the section.
        f = Findings()
        doc = {"sections": [section(artwork={"ref": "art/nope.png", "refDark": "art/hero-dark.png"})]}
        out = bake_editorial_artwork(doc, EditorialAssets(repo), f)
        assert "artwork" not in out["sections"][0]
        assert out["sections"][0]["appRef"] == "demo", "the placement survives"

    def test_losing_only_the_dark_variant_keeps_the_light_one(self, repo):
        f = Findings()
        doc = {"sections": [section(artwork={"ref": "art/hero.png", "refDark": "art/nope.png"})]}
        out = bake_editorial_artwork(doc, EditorialAssets(repo), f)
        art = out["sections"][0]["artwork"]
        assert art["ref"].startswith(f"{EDITORIAL_ASSET_DIR}/")
        assert "refDark" not in art

    def test_alt_text_survives_baking(self, repo):
        f = Findings()
        doc = {"sections": [section(artwork={"ref": "art/hero.png", "alt": "A quiet timeline"})]}
        out = bake_editorial_artwork(doc, EditorialAssets(repo), f)
        assert out["sections"][0]["artwork"]["alt"] == "A quiet timeline"

    def test_build_editorial_without_assets_leaves_artwork_alone(self):
        # The dry-run path passes no ingester; it must not silently strip artwork.
        doc = build_editorial({"schemaVersion": 1, "sections": [section()]}, NOW)
        assert doc["sections"][0]["artwork"] == {"ref": "art/hero.png"}

    def test_the_revision_changes_when_artwork_changes(self, repo):
        f = Findings()
        a = build_editorial({"schemaVersion": 1, "sections": [section()]}, NOW, EditorialAssets(repo), f)
        (repo / "art" / "hero.png").write_bytes(png(1600, 901))
        b = build_editorial({"schemaVersion": 1, "sections": [section()]}, NOW, EditorialAssets(repo), f)
        assert a["revision"] != b["revision"], "a new image must produce a new revision"


class TestIntegrityChain:
    def _dist(self, tmp_path: Path, doc: dict, files: dict[str, bytes]) -> Path:
        dist = tmp_path / "dist"
        dist.mkdir()
        (dist / "editorial.json").write_text(json.dumps(doc), encoding="utf-8")
        for name, payload in files.items():
            p = dist / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(payload)
        return dist

    def test_a_baked_document_verifies(self, repo, tmp_path):
        f = Findings()
        assets = EditorialAssets(repo)
        doc = build_editorial({"schemaVersion": 1, "sections": [section()]}, NOW, assets, f)
        dist = self._dist(tmp_path, doc, assets.files)
        assert verify_hosted_artwork(dist) == []

    def test_tampered_bytes_are_caught(self, repo, tmp_path):
        f = Findings()
        assets = EditorialAssets(repo)
        doc = build_editorial({"schemaVersion": 1, "sections": [section()]}, NOW, assets, f)
        files = dict(assets.files)
        name = next(iter(files))
        files[name] = png(32, 18)  # same path, different bytes
        problems = self._dist(tmp_path, doc, files)
        assert any("hash to" in p for p in verify_hosted_artwork(problems))

    def test_a_missing_file_is_caught(self, repo, tmp_path):
        f = Findings()
        assets = EditorialAssets(repo)
        doc = build_editorial({"schemaVersion": 1, "sections": [section()]}, NOW, assets, f)
        dist = self._dist(tmp_path, doc, {})
        assert any("not in" in p for p in verify_hosted_artwork(dist))

    def test_an_unbaked_authored_path_is_caught(self, tmp_path):
        # If the bake step is skipped, the output names a repo path that no
        # client can fetch and no digest covers. That is a hole in the chain.
        doc = {"schemaVersion": 1, "sections": [section()]}
        dist = self._dist(tmp_path, doc, {})
        assert any("did not run" in p for p in verify_hosted_artwork(dist))

    def test_no_editorial_document_is_not_a_problem(self, tmp_path):
        dist = tmp_path / "dist"
        dist.mkdir()
        assert verify_hosted_artwork(dist) == []
