from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def domain_values(ruleset: str) -> set[str]:
    path = ROOT / "dist" / ruleset / "mihomo-domain.list"
    return set(path.read_text(encoding="utf-8").splitlines())


def classical_keywords(ruleset: str) -> set[str]:
    path = ROOT / "dist" / ruleset / "mihomo-classical.list"
    return {
        line.removeprefix("DOMAIN-KEYWORD,")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("DOMAIN-KEYWORD,")
    }


def test_all_manifest_outputs_exist_and_match_hashes() -> None:
    manifests = sorted((ROOT / "dist").glob("*/manifest.json"))
    assert len(manifests) == 8

    for manifest_path in manifests:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        for output in document["outputs"].values():
            artifact = manifest_path.parent / output["path"]
            assert artifact.is_file(), artifact
            data = artifact.read_bytes()
            assert len(data) == output["size"]
            assert hashlib.sha256(data).hexdigest() == output["sha256"]
        jsonl = manifest_path.parent / document["outputs"]["jsonl"]["path"]
        assert jsonl.name == "rules.jsonl.gz"
        with gzip.open(jsonl, "rt", encoding="utf-8") as handle:
            first = json.loads(handle.readline())
        assert {"kind", "value", "action", "provenance"} <= set(first)


def test_cross_border_finance_protected_requirements_are_present() -> None:
    domains = domain_values("cross-border-finance")

    assert {
        "+.standardchartered.com",
        "+.n26.com",
        "+.ifastcorp.com",
        "+.ifastglobalbank.com",
        "+.bybit.com",
        "+.bybit.eu",
        "+.bybit.nl",
        "+.okx.com",
        "+.plasma.org",
        "+.plasma.to",
        "+.t-mobile.com",
        "+.o2.co.uk",
    } <= domains
    assert "+.plasma.io" not in domains


def test_cross_border_finance_has_repository_wide_keyword_fallbacks() -> None:
    domains = domain_values("cross-border-finance")
    keywords = classical_keywords("cross-border-finance")

    assert {
        "binance",
        "bitget",
        "bybit",
        "hsbc",
        "interactivebrokers",
        "okx",
        "plasma-one",
    } <= keywords
    assert len(keywords) >= len(domains) * 0.7
    assert {"cash", "crypto", "home", "payment", "plasma"}.isdisjoint(keywords)
    xray = (ROOT / "dist" / "cross-border-finance" / "xray-domain-list.txt").read_text(
        encoding="utf-8"
    )
    assert "keyword:bitget\n" in xray
    assert "keyword:plasma-one\n" in xray


def test_ip_proxy_pool_protected_requirements_are_present() -> None:
    domains = domain_values("ip-proxy-pools")
    force = domain_values("fake-ip-force")

    assert {
        "+.seekproxy.com",
        "+.oxylabs.io",
        "+.iproyal.com",
        "+.proxy-seller.com",
        "+.dataimpulse.com",
        "+.webshare.io",
        "+.decodo.com",
        "+.smartproxy.com",
        "+.soax.com",
        "+.brightdata.com",
        "+.netnut.net",
    } <= domains
    assert "+.smartproxy.org" not in domains
    assert "+.smartproxy.cn" not in domains
    assert domains <= force


def test_fake_ip_force_and_bypass_remain_disjoint_and_compatible() -> None:
    bypass = domain_values("fake-ip-bypass")
    force = domain_values("fake-ip-force")

    assert "+.pool.ntp.org" in bypass
    assert "+.nflxvideo.net" in bypass
    assert "+.bybit.com" in force
    assert "+.openai.com" in force
    assert "+.pool.ntp.org" not in force
    assert "+.nflxvideo.net" not in force
    assert "Mijia Cloud" not in bypass
    assert bypass.isdisjoint(force)


def test_discovery_summary_tracks_card_catalog_and_reproducible_bundle() -> None:
    summary = json.loads(
        (ROOT / "generated" / "discovery" / "summary.json").read_text(encoding="utf-8")
    )
    bundle = ROOT / summary["candidate_store"]["path"]

    assert summary["candidate_store"]["total"] == sum(summary["counts"].values())
    assert summary["counts"]["candidate"] >= 4000
    assert summary["counts"]["registered"] >= 5
    assert any(
        source["discoverer"] == "cross-border-card-catalog" and source["matched"] >= 250
        for source in summary["sources"]
    )
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == summary["candidate_store"]["sha256"]


def test_source_lock_contains_only_stable_public_urls() -> None:
    lock = json.loads((ROOT / "generated" / "sources.lock.json").read_text(encoding="utf-8"))

    for source in lock["sources"]:
        parsed = urlsplit(source["final_url"])
        assert parsed.username is None
        assert parsed.password is None
        assert not parsed.query
        assert not parsed.fragment
