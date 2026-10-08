from __future__ import annotations

import gzip
import json
import shutil
from pathlib import Path

import pytest
import yaml

from void_rules.catalog import load_catalog
from void_rules.codecs import GeodataCodec
from void_rules.errors import BuildError, CatalogError, FetchError
from void_rules.fetch import SourceFetchResult, fetch_source
from void_rules.model import Action, Rule, RuleKind
from void_rules.pipeline import build
from void_rules.separation import exclude_ruleset_members, is_stun_turn_rule

ROOT = Path(__file__).resolve().parents[1]
MIXED_SOURCES = {"dustinwin-fakeip", "rfm-fakeip", "quixotic-fakeip", "shellcrash-fakeip"}


def test_stun_is_independent_and_exclusion_is_a_build_dependency() -> None:
    catalog = load_catalog(ROOT)
    stun = catalog.recipes["stun"]
    assert stun.action is Action.MATCH
    assert set(stun.sources) == {"metacubex-stun", *MIXED_SOURCES}
    assert set(stun.filtered_sources) == MIXED_SOURCES
    assert stun.source_filter == "stun-turn"
    assert stun.review_unmatched_sources == ("dustinwin-fakeip",)
    assert catalog.recipes["fake-ip-bypass"].exclude_rulesets == ("stun",)
    assert all("stun" not in recipe.rulesets for recipe in catalog.recipes.values())
    assert catalog.recipe_order.index("stun") < catalog.recipe_order.index("fake-ip-bypass")


def test_exclusions_remove_members_without_removing_unrelated_parent_names() -> None:
    exclusions = [
        Rule(RuleKind.DOMAIN, "relay.example"),
        Rule(RuleKind.DOMAIN_SUFFIX, "metered.live"),
        Rule(RuleKind.DOMAIN_WILDCARD, "+.stun.*.*"),
    ]
    removed = [
        Rule(RuleKind.DOMAIN, "relay.example", action=Action.FAKE_IP_BYPASS, protected=True),
        Rule(RuleKind.DOMAIN, "new.metered.live"),
        Rule(RuleKind.DOMAIN_SUFFIX, "region.metered.live"),
        Rule(RuleKind.DOMAIN, "new.stun.example.net"),
        Rule(RuleKind.DOMAIN_SUFFIX, "stun.example.net"),
        Rule(RuleKind.DOMAIN_WILDCARD, "+.stun.*.*"),
        Rule(RuleKind.DOMAIN_WILDCARD, "*.region.metered.live"),
        Rule(RuleKind.DOMAIN_WILDCARD, "+.*.metered.live"),
    ]
    kept = [
        Rule(RuleKind.DOMAIN, "notmetered.live"),
        Rule(RuleKind.DOMAIN, "time.google.com"),
        Rule(RuleKind.DOMAIN_SUFFIX, "example"),
        Rule(RuleKind.DOMAIN_SUFFIX, "other.example.net"),
        Rule(RuleKind.DOMAIN_WILDCARD, "*.live"),
        Rule(RuleKind.DOMAIN_WILDCARD, "*.notmetered.live"),
    ]
    assert exclude_ruleset_members(removed + kept, exclusions) == (kept, removed)


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("VOID_RULES_GEODATA", str(GeodataCodec(ROOT).executable()))
    for directory in ("catalog", "schemas", "overlays"):
        shutil.copytree(ROOT / directory, tmp_path / directory)
    recipe_dir = tmp_path / "recipes"
    recipe_dir.mkdir()
    for name in ("stun", "fake-ip-bypass"):
        document = yaml.safe_load((ROOT / "recipes" / f"{name}.yaml").read_text())
        document["outputs"] = ["jsonl", "mihomo-domain-text", "mihomo-classical-text"]
        document["limits"]["min_rules"] = 1
        if name == "fake-ip-bypass":
            document["sources"] = sorted(MIXED_SOURCES)
        (recipe_dir / f"{name}.yaml").write_text(yaml.safe_dump(document))
    sources_path = tmp_path / "catalog/sources.yaml"
    sources = yaml.safe_load(sources_path.read_text())
    for source in sources["sources"]:
        if source["id"] in {"metacubex-stun", *MIXED_SOURCES}:
            source["limits"]["min_rules"] = 1
            source["limits"]["min_bytes"] = 1
    sources_path.write_text(yaml.safe_dump(sources))
    (tmp_path / ".work/downloads").mkdir(parents=True)
    revision(tmp_path, "rfm-fakeip", ["payload:", "  - time.google.com"])
    revision(tmp_path, "shellcrash-fakeip", ["time.google.com"])
    (tmp_path / ".work/downloads/dustinwin-fakeip.blob").write_text(
        "DOMAIN,numb.viagenie.ca\nDOMAIN,stun.l.google.com\nDOMAIN-SUFFIX,metered.live\n"
        "DOMAIN,time.google.com\nDOMAIN,stun.dustin-only.example\n"
    )
    return tmp_path


def revision(root: Path, source: str, names: list[str]) -> None:
    (root / ".work/downloads" / f"{source}.blob").write_text("\n".join(names) + "\n")


def test_new_upstream_stun_members_leave_bypass_and_removed_members_leave_stun(
    isolated: Path,
) -> None:
    stable = ["stun.l.google.com", "numb.viagenie.ca", "+.metered.live"]
    mixed = [*stable, "time.google.com", "relay-no-stun-name.example", "+.stun.*.*"]
    revision(isolated, "metacubex-stun", [*stable, "retired.example"])
    revision(isolated, "quixotic-fakeip", [*mixed, "retired.example"])
    first = build(isolated, offline=True)
    assert not first.review_required
    assert "relay-no-stun-name.example" in {r.value for r in first.rules["fake-ip-bypass"]}
    revision(isolated, "metacubex-stun", [*stable, "relay-no-stun-name.example"])
    revision(isolated, "quixotic-fakeip", mixed)
    updated = build(isolated, offline=True)
    assert not updated.review_required
    assert updated.changed
    bypass = {r.value for r in updated.rules["fake-ip-bypass"]}
    stun = {r.value for r in updated.rules["stun"]}
    assert "relay-no-stun-name.example" in stun - bypass
    assert "retired.example" not in stun | bypass
    assert "time.google.com" in bypass - stun
    assert "stun.l.google.com" in stun - bypass
    assert "stun.dustin-only.example" in stun - bypass
    shared = next(rule for rule in updated.rules["stun"] if rule.value == "numb.viagenie.ca")
    assert {p.source_id for p in shared.provenance} == {
        "metacubex-stun",
        "dustinwin-fakeip",
        "quixotic-fakeip",
    }
    assert all(r.action is Action.MATCH for r in updated.rules["stun"])
    assert not build(isolated, offline=True, check=True).changed
    selected = build(isolated, offline=True, check=True, selected_rulesets={"fake-ip-bypass"})
    assert not selected.review_required
    assert {s["id"] for s in selected.lock["sources"]} == {"metacubex-stun", *MIXED_SOURCES}


def test_stale_exclusion_source_blocks_bypass_rebuild(
    isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    revision(isolated, "metacubex-stun", ["numb.viagenie.ca", "+.metered.live"])
    revision(isolated, "quixotic-fakeip", ["time.google.com"])
    build(isolated, offline=True)
    catalog = load_catalog(isolated)
    downloaded = {
        sid: fetch_source(catalog.sources[sid], isolated / ".work", offline=True)
        for sid in MIXED_SOURCES
    }
    monkeypatch.setattr(
        "void_rules.pipeline.fetch_sources",
        lambda *args, **kwargs: SourceFetchResult(
            downloaded=downloaded,
            failures={"metacubex-stun": "unavailable"},
        ),
    )
    with pytest.raises(FetchError, match="exclusion dependency stun requires fresh sources"):
        build(isolated)


def test_exclusion_dependency_cycles_are_rejected(isolated: Path) -> None:
    path = isolated / "recipes/stun.yaml"
    document = yaml.safe_load(path.read_text())
    document["exclude_rulesets"] = ["fake-ip-bypass"]
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(CatalogError, match="dependency cycle"):
        load_catalog(isolated)


def test_published_stun_and_bypass_have_no_stun_members_in_common() -> None:
    def read(name: str) -> list[Rule]:
        with gzip.open(ROOT / "dist" / name / "rules.jsonl.gz", "rt") as handle:
            return [Rule.from_dict(json.loads(line)) for line in handle]

    stun, bypass = read("stun"), read("fake-ip-bypass")
    assert not exclude_ruleset_members(bypass, stun)[1]
    assert all(rule.action is Action.MATCH for rule in stun)
    shared = next(rule for rule in stun if rule.value == "numb.viagenie.ca")
    assert {"metacubex-stun", "dustinwin-fakeip"} <= {p.source_id for p in shared.provenance}
    assert {"time.google.com", "pool.ntp.org"} <= {rule.value for rule in bypass}
    assert not any("stun" in rule.value.lower() for rule in bypass)
    manifest = json.loads((ROOT / "dist/fake-ip-bypass/manifest.json").read_text())
    assert manifest["exclude_rulesets"] == ["stun"]
    assert manifest["composition"]["excluded_rulesets"]["stun"]["count"] > 0


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        (RuleKind.DOMAIN, "turn7.only-dustin.example", True),
        (RuleKind.DOMAIN_SUFFIX, "stun-v4.provider.example", True),
        (RuleKind.DOMAIN_WILDCARD, "*.*.turn.*", True),
        (RuleKind.DOMAIN_WILDCARD, "+.stun.*.*", True),
        (RuleKind.DOMAIN_REGEX, r"^.*\.stun\.[^.]+\.[^.]+$", True),
        (RuleKind.DOMAIN_REGEX, r"^.*\.stun\.[^.]+\.[^.]+$|ntp.example", False),
        (RuleKind.DOMAIN, "return.example", False),
        (RuleKind.DOMAIN, "stunning.example", False),
        (RuleKind.DOMAIN, "turnkey.example", False),
        (RuleKind.DOMAIN, "time.google.com", False),
        (RuleKind.DOMAIN_SUFFIX, "pool.ntp.org", False),
        (RuleKind.DOMAIN, "relay-without-protocol-name.example", False),
        (RuleKind.PROCESS_NAME, "stun", False),
    ],
)
def test_protocol_labels_are_classified_without_substring_false_positives(
    kind: RuleKind, value: str, expected: bool
) -> None:
    assert is_stun_turn_rule(Rule(kind, value)) is expected


def test_mixed_upstream_rules_and_provenance_follow_additions_and_deletions(isolated: Path) -> None:
    revision(isolated, "metacubex-stun", ["numb.viagenie.ca", "+.metered.live"])
    revision(isolated, "quixotic-fakeip", ["+.turn.vendor.example", "time.google.com"])
    revision(isolated, "rfm-fakeip", ["payload:", "  - '*.*.turn.*'", "  - 'return.example'"])
    revision(isolated, "shellcrash-fakeip", ["*.*.turn.*", "*.stun.media.example"])
    first = build(isolated, offline=True)
    shared = next(r for r in first.rules["stun"] if r.value == "*.*.turn.*")
    assert {p.source_id for p in shared.provenance} == {"rfm-fakeip", "shellcrash-fakeip"}
    assert not shared.protected
    assert "return.example" not in {r.value for r in first.rules["stun"]}
    revision(isolated, "quixotic-fakeip", ["+.turn.new-vendor.example", "time.google.com"])
    revision(isolated, "rfm-fakeip", ["payload:", "  - return.example"])
    updated = build(isolated, offline=True)
    shared = next(r for r in updated.rules["stun"] if r.value == "*.*.turn.*")
    assert {p.source_id for p in shared.provenance} == {"shellcrash-fakeip"}
    assert "turn.vendor.example" not in {r.value for r in updated.rules["stun"]}
    assert "turn.new-vendor.example" in {r.value for r in updated.rules["stun"]}
    revision(isolated, "shellcrash-fakeip", ["time.google.com"])
    final = build(isolated, offline=True)
    assert "*.*.turn.*" not in {r.value for r in final.rules["stun"]}
    assert not exclude_ruleset_members(final.rules["fake-ip-bypass"], final.rules["stun"])[1]
    assert not build(isolated, offline=True, check=True).changed


def test_dustin_unknown_additions_block_until_classified_without_advancing_baseline(
    isolated: Path,
) -> None:
    stable = ["numb.viagenie.ca", "+.metered.live"]
    revision(isolated, "metacubex-stun", stable)
    revision(isolated, "quixotic-fakeip", ["time.google.com"])
    build(isolated, offline=True)
    source = isolated / ".work/downloads/dustinwin-fakeip.blob"
    source.write_text(source.read_text() + "DOMAIN,turn7.only-dustin.example\n")
    named = build(isolated, offline=True)
    assert "turn7.only-dustin.example" in {r.value for r in named.rules["stun"]}
    protected_files = [*isolated.glob("dist/**/*"), isolated / "generated/sources.lock.json"]
    before = {p: p.read_bytes() for p in protected_files if p.is_file()}
    source.write_text(source.read_text() + "DOMAIN,unclassified-relay.example\n")
    for _ in range(2):
        with pytest.raises(BuildError, match="unclassified additions from dustinwin-fakeip"):
            build(isolated, offline=True)
        assert all(p.read_bytes() == data for p, data in before.items())
    revision(isolated, "metacubex-stun", [*stable, "unclassified-relay.example"])
    classified = build(isolated, offline=True)
    assert "unclassified-relay.example" in {r.value for r in classified.rules["stun"]}
    assert "unclassified-relay.example" not in {r.value for r in classified.rules["fake-ip-bypass"]}
    assert "time.google.com" in {r.value for r in classified.rules["fake-ip-bypass"]}


def test_invalid_exclusion_regex_fails_with_a_build_error() -> None:
    with pytest.raises(BuildError, match="cannot safely evaluate exclusion regex"):
        exclude_ruleset_members(
            [Rule(RuleKind.DOMAIN, "time.google.com")], [Rule(RuleKind.DOMAIN_REGEX, "[")]
        )
