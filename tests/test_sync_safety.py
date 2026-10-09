from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from void_rules import pipeline
from void_rules.cli import main
from void_rules.codecs import GeodataCodec
from void_rules.errors import BuildError, FetchError
from void_rules.fetch import SourceFetchResult
from void_rules.pipeline import build
from void_rules.publication import publication_digest, publish_files

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sync_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("VOID_RULES_GEODATA", str(GeodataCodec(ROOT).executable()))
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    shutil.copytree(ROOT / "catalog", tmp_path / "catalog")
    shutil.copytree(ROOT / "overlays/discovery", tmp_path / "overlays/discovery")
    document = yaml.safe_load((tmp_path / "catalog/sources.yaml").read_text())
    template = document["sources"][0]
    sources = []
    for name in ("one", "two"):
        source = dict(template)
        source.update(id=name, format="plain-domain", url=f"https://example.com/{name}")
        source.update(allowed_hosts=["example.com"], fallback_urls=[], select_tags=[])
        source.update(polarity="match", behavior=None, whole_source_allowlist=False)
        source.pop("behavior", None)
        source["limits"] = {
            "min_bytes": 1,
            "max_bytes": 10000,
            "min_rules": 1,
            "max_rules": 100,
            "max_growth_ratio": 2,
            "max_shrink_ratio": 0.2,
        }
        sources.append(source)
    document["sources"] = sources
    (tmp_path / "catalog/sources.yaml").write_text(yaml.safe_dump(document))
    (tmp_path / "recipes").mkdir()
    # a -> b, c shares a's source, d is an independent component.
    for name, source_ids, dependencies in (
        ("a", ["one"], []),
        ("b", [], ["a"]),
        ("c", ["one"], []),
        ("d", ["two"], []),
    ):
        overlay = tmp_path / "overlays" / name
        overlay.mkdir(parents=True)
        for kind, content in {
            "include": {"format": "clash-classical", "rules": []},
            "exclude": {"format": "selectors", "selectors": []},
            "assertions": {"format": "assertions", "required": [], "forbidden": []},
        }.items():
            (overlay / f"{kind}.yaml").write_text(
                yaml.safe_dump({"version": 1, "ruleset": name, **content})
            )
        recipe = {
            "version": 1,
            "id": name,
            "description": "sync safety fixture",
            "action": "match",
            "sources": source_ids,
            "rulesets": dependencies,
            "outputs": ["jsonl", "mihomo-domain-text"],
            "limits": {
                "min_rules": 1,
                "max_rules": 100,
                "max_growth_ratio": 2,
                "max_shrink_ratio": 0.2,
            },
            **{
                kind: f"overlays/{name}/{kind}.yaml"
                for kind in ("include", "exclude", "assertions")
            },
        }
        (tmp_path / f"recipes/{name}.yaml").write_text(yaml.safe_dump(recipe))
    cache = tmp_path / ".work/downloads"
    cache.mkdir(parents=True)
    for name in ("one", "two"):
        (cache / f"{name}.blob").write_text(f"{name}.example\n")
    return tmp_path


def test_locked_replay_works_without_cache_and_rejects_corrupt_snapshot(sync_repo: Path) -> None:
    assert not build(sync_repo, offline=True).review_required
    shutil.rmtree(sync_repo / ".work")
    assert not build(sync_repo, locked=True, check=True).changed
    archive = sync_repo / "generated/inputs/sources/one.gz"
    archive.write_bytes(b"broken snapshot")
    with pytest.raises(FetchError, match="locked input"):
        build(sync_repo, locked=True, check=True)


@pytest.mark.parametrize(
    "path",
    [
        "generated/reports/build.json",
        "generated/reports/compatibility.json",
        "generated/sources.lock.json",
    ],
)
def test_check_detects_global_metadata_changes(sync_repo: Path, path: str) -> None:
    build(sync_repo, offline=True)
    target = sync_repo / path
    data = json.loads(target.read_bytes())
    data["unexpected"] = "metadata drift"
    target.write_text(json.dumps(data))
    assert build(sync_repo, locked=True, check=True).changed
    assert json.loads(target.read_bytes())["unexpected"] == "metadata drift"


def test_partial_build_updates_component_and_preserves_global_baseline(sync_repo: Path) -> None:
    build(sync_repo, offline=True)
    unrelated = (sync_repo / "dist/d/manifest.json").read_bytes()
    (sync_repo / ".work/downloads/one.blob").write_text("one.example\nnew.example\n")
    result = build(sync_repo, offline=True, selected_rulesets={"a"})
    assert set(result.rules) == {"a", "b", "c"}
    assert {entry["id"] for entry in result.lock["sources"]} == {"one", "two"}
    assert set(result.compatibility) == {"a", "b", "c", "d"}
    assert result.report["selected_rulesets"] == ["a", "b", "c", "d"]
    assert (sync_repo / "dist/d/manifest.json").read_bytes() == unrelated
    for name in ("a", "b", "c"):
        assert "new.example" in (sync_repo / f"dist/{name}/mihomo-domain.list").read_text()
    assert not build(sync_repo, locked=True, check=True).changed


def test_review_cannot_be_bypassed_by_repeating_a_build(sync_repo: Path) -> None:
    build(sync_repo, offline=True)
    before = publication_digest(sync_repo)
    (sync_repo / ".work/downloads/one.blob").write_text(
        "one.example\ntwo.example\nthree.example\nfour.example\n"
    )
    for _ in range(2):
        result = build(sync_repo, offline=True)
        assert result.review_required
        assert publication_digest(sync_repo) == before
        assert (
            json.loads((sync_repo / ".work/reports/sync-attempt.json").read_bytes())["status"]
            == "review"
        )
    with pytest.raises(SystemExit) as stopped:
        main(["--root", str(sync_repo), "sync", "--offline"])
    assert stopped.value.code == 3
    assert publication_digest(sync_repo) == before


def test_late_render_failure_does_not_publish_earlier_recipes(
    sync_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build(sync_repo, offline=True)
    before = publication_digest(sync_repo)
    (sync_repo / ".work/downloads/one.blob").write_text("one.example\nnew.example\n")
    original = pipeline.render_outputs

    def failing_render(recipe_id: str, *args: Any, **kwargs: Any) -> Any:
        if recipe_id == "b":
            raise BuildError("late codec failure")
        return original(recipe_id, *args, **kwargs)

    monkeypatch.setattr(pipeline, "render_outputs", failing_render)
    with pytest.raises(BuildError, match="late codec"):
        build(sync_repo, offline=True)
    assert publication_digest(sync_repo) == before


def test_ordinary_unavailable_source_preserves_verified_inputs(
    sync_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build(sync_repo, offline=True)
    original = pipeline.fetch_sources

    def unavailable(*args: Any, **kwargs: Any) -> SourceFetchResult:
        fetched = original(*args, **kwargs)
        del fetched.downloaded["one"]
        return SourceFetchResult(fetched.downloaded, {"one": "unavailable"})

    monkeypatch.setattr(pipeline, "fetch_sources", unavailable)
    result = build(sync_repo, offline=True)
    assert not result.review_required
    assert result.lock["sources"][0]["sync_status"] == "stale"
    assert not build(sync_repo, locked=True, check=True).changed


def test_publication_rolls_back_after_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from void_rules import publication

    (tmp_path / "first").write_bytes(b"old")
    original = publication.os.replace

    def fail_second(source: Any, target: Any) -> None:
        if Path(target) == tmp_path / "second":
            raise OSError("disk failure")
        original(source, target)

    monkeypatch.setattr(publication.os, "replace", fail_second)
    with pytest.raises(OSError, match="disk failure"):
        publish_files(tmp_path, {"first": b"new", "second": b"new"}, set())
    assert (tmp_path / "first").read_bytes() == b"old"
    assert not (tmp_path / "second").exists()
