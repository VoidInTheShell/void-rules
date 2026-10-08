from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from void_rules.catalog import Catalog, load_catalog
from void_rules.errors import BuildError
from void_rules.model import Rule, RuleKind
from void_rules.pipeline import _fakeip_coverage_overlaps, _resolve_fakeip_conflicts

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def catalog(tmp_path: Path) -> Catalog:
    catalog = load_catalog(ROOT)
    assertions = tmp_path / "assertions.yaml"
    assertions.write_text("required: []\nforbidden: []\n")
    return replace(
        catalog,
        recipes={
            name: replace(recipe, assertions=assertions) for name, recipe in catalog.recipes.items()
        },
    )


def test_reviewed_ntp_keeps_real_ip_exception_and_reports_force_parent(catalog: Catalog) -> None:
    child = Rule(RuleKind.DOMAIN, "time.google.com")
    parent = Rule(RuleKind.DOMAIN_SUFFIX, "google.com")
    built = {"fake-ip-bypass": [child], "fake-ip-force": [child, parent]}

    report, reasons = _resolve_fakeip_conflicts(catalog, built)

    assert not reasons
    assert built["fake-ip-bypass"] == [child]
    assert built["fake-ip-force"] == [parent]
    assert report["items"][0]["explicit"] is True
    assert report["coverage_overlaps"] == {
        "total": 1,
        "items": [
            {
                "bypass": {"kind": "domain", "value": "time.google.com"},
                "force": {"kind": "domain_suffix", "value": "google.com"},
            }
        ],
    }


def test_firefox_and_japanese_ntp_conflicts_are_reviewed(catalog: Catalog) -> None:
    rules = [
        Rule(RuleKind.DOMAIN_SUFFIX, "firefox-portal-detection.com"),
        Rule(RuleKind.DOMAIN_SUFFIX, "ntp.jst.mfeed.ad.jp"),
    ]
    built = {"fake-ip-bypass": rules[:], "fake-ip-force": rules[:]}

    report, reasons = _resolve_fakeip_conflicts(catalog, built)

    assert not reasons
    assert built["fake-ip-bypass"] == rules
    assert not built["fake-ip-force"]
    assert report["total"] == 2
    assert all(item["explicit"] for item in report["items"])


def test_new_exact_conflicts_still_require_review(catalog: Catalog) -> None:
    rule = Rule(RuleKind.DOMAIN, "new-time.example")
    built = {"fake-ip-bypass": [rule], "fake-ip-force": [rule]}

    report, reasons = _resolve_fakeip_conflicts(catalog, built)

    assert reasons == ["unreviewed Fake-IP overlap: domain,new-time.example"]
    assert report["items"][0]["explicit"] is False


def test_unreviewed_protected_conflict_still_fails(catalog: Catalog) -> None:
    rule = Rule(RuleKind.DOMAIN, "new-time.example", protected=True)
    with pytest.raises(BuildError, match="requires an explicit resolution"):
        _resolve_fakeip_conflicts(catalog, {"fake-ip-bypass": [rule], "fake-ip-force": [rule]})


def test_coverage_includes_reverse_and_same_host_but_respects_label_boundaries() -> None:
    bypass = [
        Rule(RuleKind.DOMAIN_SUFFIX, "real.example"),
        Rule(RuleKind.DOMAIN, "time.google.com"),
    ]
    force = [
        Rule(RuleKind.DOMAIN, "child.real.example"),
        Rule(RuleKind.DOMAIN_SUFFIX, "time.google.com"),
        Rule(RuleKind.DOMAIN_SUFFIX, "oogle.com"),
        Rule(RuleKind.DOMAIN_SUFFIX, "notreal.example"),
    ]

    report = _fakeip_coverage_overlaps(bypass, force)

    assert report["total"] == 2
    assert {item["force"]["value"] for item in report["items"]} == {
        "child.real.example",
        "time.google.com",
    }
    assert report == _fakeip_coverage_overlaps(list(reversed(bypass)), list(reversed(force)))


def test_coverage_is_calculated_after_explicit_force_resolution(
    catalog: Catalog, tmp_path: Path
) -> None:
    conflicts = tmp_path / "conflicts.yaml"
    conflicts.write_text(
        yaml.safe_dump(
            {"allow": [{"kind": "domain", "value": "time.example", "winner": "fake-ip-force"}]}
        )
    )
    catalog = replace(
        catalog,
        recipes={
            name: replace(recipe, conflict_resolutions=conflicts)
            for name, recipe in catalog.recipes.items()
        },
    )
    child = Rule(RuleKind.DOMAIN, "time.example")
    parent = Rule(RuleKind.DOMAIN_SUFFIX, "example")
    built = {"fake-ip-bypass": [child], "fake-ip-force": [child, parent]}

    report, reasons = _resolve_fakeip_conflicts(catalog, built)

    assert not reasons
    assert not built["fake-ip-bypass"]
    assert report["coverage_overlaps"]["total"] == 0
