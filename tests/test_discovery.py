from __future__ import annotations

from pathlib import Path

import pytest

from void_rules.discovery import _extract_json_path, _load_rejections, stable_candidate_id
from void_rules.errors import CatalogError


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
