from __future__ import annotations

from pathlib import Path

from void_rules.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[1]


def test_repository_catalog_is_semantically_valid() -> None:
    catalog = load_catalog(ROOT)

    assert len(catalog.sources) == 43
    assert set(catalog.recipes) == {
        "ads",
        "ai",
        "cross-border-finance",
        "fake-ip-bypass",
        "fake-ip-force",
        "global-legal",
        "ip-proxy-pools",
        "pcdn",
    }
    assert len(catalog.discovery["discoverers"]) == 2
    fallback = catalog.recipes["cross-border-finance"].domain_keyword_fallback
    assert fallback is not None
    assert fallback.min_label_length == 4
    assert {"okx", "o2", "n26"} <= fallback.always_include
