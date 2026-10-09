from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from void_rules.codecs import GeodataCodec
from void_rules.discovery import (
    _extract_json_path,
    _json_api_candidates,
    _load_rejections,
    discover,
    stable_candidate_id,
)
from void_rules.errors import CatalogError, FetchError


def test_candidate_id_is_stable_and_identity_sensitive() -> None:
    first = stable_candidate_id("cards", "json-value", '"bybit"')

    assert first == stable_candidate_id("cards", "json-value", '"bybit"')
    assert first != stable_candidate_id("cards", "json-value", '"okx"')
    assert first.startswith("candidate-")


def test_json_path_extracts_only_scalar_values() -> None:
    document = {"items": [{"id": "one"}, {"id": 2}, {"id": {"bad": True}}, None]}

    assert _extract_json_path(document, "$.items[*].id") == ["one", 2]


def test_unsupported_json_path_fails_closed() -> None:
    with pytest.raises(CatalogError, match="unsupported"):
        _extract_json_path({"items": []}, "$..items")


def test_rejection_store_requires_id_and_reason(tmp_path: Path) -> None:
    valid = tmp_path / "valid.yaml"
    valid.write_text(
        "version: 1\nrejected:\n  - id: candidate-abc\n    reason: not official\n",
        encoding="utf-8",
    )
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("version: 1\nrejected:\n  - id: candidate-abc\n", encoding="utf-8")

    assert _load_rejections(valid) == {"candidate-abc": "not official"}
    with pytest.raises(CatalogError, match="invalid discovery rejection"):
        _load_rejections(invalid)


def paginated_discoverer() -> dict[str, Any]:
    return {
        "id": "cards",
        "type": "json-api",
        "url": "https://example.com/cards?limit=1000&offset=0",
        "json_paths": ["$.items[*].id"],
        "allowed_hosts": ["example.com"],
        "purpose": "test pagination",
        "promotion": "candidate-only",
        "max_candidates": 5000,
        "pagination": {
            "offset_parameter": "offset",
            "next_offset_field": "nextOffset",
            "total_field": "total",
            "items_field": "items",
            "max_pages": 5,
        },
    }


def cache_page(root: Path, offset: int, document: dict[str, Any]) -> None:
    url = f"https://example.com/cards?limit=1000&offset={offset}"
    key = hashlib.sha256(url.encode()).hexdigest()[:16]
    path = root / ".work/discovery" / f"cards-{key}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document))


def test_server_page_cap_does_not_truncate_candidates(tmp_path: Path) -> None:
    cache_page(
        tmp_path,
        0,
        {
            "items": [{"id": index} for index in range(500)],
            "total": 614,
            "nextOffset": 500,
        },
    )
    cache_page(
        tmp_path,
        500,
        {
            "items": [{"id": index} for index in range(500, 614)],
            "total": 614,
            "nextOffset": None,
        },
    )
    candidates, report = _json_api_candidates(tmp_path, paginated_discoverer(), offline=True)
    assert {item["value"] for item in candidates} == set(range(614))
    assert report["endpoints"] == 2


@pytest.mark.parametrize(
    "second",
    [
        {"items": [{"id": "one"}], "total": 2, "nextOffset": None},  # duplicate across pages
        {"items": [], "total": 2, "nextOffset": None},  # incomplete
        {"items": [{"id": "two"}], "total": 3, "nextOffset": None},  # changing total
        {"items": [{"id": "two"}], "total": 2, "nextOffset": 0},  # cycle
        {"items": [{"wrong": "two"}], "total": 2, "nextOffset": None},  # missing ID
    ],
)
def test_pagination_rejects_incomplete_or_inconsistent_pages(
    tmp_path: Path,
    second: dict[str, Any],
) -> None:
    cache_page(tmp_path, 0, {"items": [{"id": "one"}], "total": 2, "nextOffset": 1})
    cache_page(tmp_path, 1, second)
    with pytest.raises(FetchError):
        _json_api_candidates(tmp_path, paginated_discoverer(), offline=True)


def test_discovery_locked_replay_in_clean_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("VOID_RULES_GEODATA", str(GeodataCodec(root).executable()))
    for directory in ("catalog", "recipes", "overlays", "schemas"):
        shutil.copytree(root / directory, tmp_path / directory)
    policy = tmp_path / "catalog/discovery.yaml"
    document = yaml.safe_load(policy.read_text())
    document["discoverers"] = [paginated_discoverer()]
    policy.write_text(yaml.safe_dump(document))
    cache_page(tmp_path, 0, {"items": [{"id": "one"}], "total": 1, "nextOffset": None})
    assert discover(tmp_path, offline=True).changed
    shutil.rmtree(tmp_path / ".work")
    assert not discover(tmp_path, locked=True, check=True).changed
    summary = tmp_path / "generated/discovery/summary.json"
    summary.write_text("{}")
    assert discover(tmp_path, locked=True, check=True).changed
