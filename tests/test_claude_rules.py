from __future__ import annotations

import gzip
import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from void_rules.catalog import load_catalog
from void_rules.codecs import GeodataCodec
from void_rules.model import Rule
from void_rules.normalize import wildcard_to_regex
from void_rules.pipeline import build

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "void-claude-rules"
SOURCES = {"vpsdance-anthropic", "metacubex-anthropic", "xiaolai-anthropic", "blackmatrix-claude"}


def test_claude_recipe_joins_default_sync_with_four_strict_sources() -> None:
    catalog = load_catalog(ROOT)
    recipe = catalog.recipes["void-claude-rules"]

    assert "void-claude-rules" in catalog.recipe_order
    assert set(recipe.sources) == SOURCES
    assert "void-claude-rules" in catalog.recipes["fake-ip-force"].rulesets
    assert catalog.recipe_order.index("void-claude-rules") < catalog.recipe_order.index(
        "fake-ip-force"
    )
    assert all(catalog.sources[source].strict for source in SOURCES)
    assert all(catalog.sources[source].limits.min_rules > 0 for source in SOURCES)


def test_claude_ai_overlap_is_generated_from_both_recipe_outputs() -> None:
    catalog = load_catalog(ROOT)
    recipe = catalog.recipes["void-claude-ai-overlap"]
    assert recipe.intersect_rulesets == ("ai", "void-claude-rules")
    assert recipe.intersection_kinds == ("domain", "domain_suffix", "domain_wildcard")
    assert catalog.recipe_order.index("ai") < catalog.recipe_order.index(recipe.id)
    assert catalog.recipe_order.index("void-claude-rules") < catalog.recipe_order.index(recipe.id)

    def read(ruleset: str) -> dict[tuple[str, str, tuple[str, ...]], Rule]:
        with gzip.open(
            ROOT / "dist" / ruleset / "rules.jsonl.gz", "rt", encoding="utf-8"
        ) as handle:
            return {
                rule.content_key: rule
                for line in handle
                for rule in [Rule.from_dict(json.loads(line))]
            }

    ai = read("ai")
    claude = read("void-claude-rules")
    overlap = read("void-claude-ai-overlap")

    def matches(domain: str, rules: dict[tuple[str, str, tuple[str, ...]], Rule]) -> bool:
        for rule in rules.values():
            if rule.kind.value == "domain" and rule.value == domain:
                return True
            if rule.kind.value == "domain_suffix" and (
                domain == rule.value or domain.endswith("." + rule.value)
            ):
                return True
            if rule.kind.value == "domain_wildcard" and re.fullmatch(
                wildcard_to_regex(rule.value), domain
            ):
                return True
        return False

    samples = {"unrelated.invalid"}
    for rule in (*ai.values(), *claude.values(), *overlap.values()):
        if rule.kind.value not in {"domain", "domain_suffix", "domain_wildcard"}:
            continue
        domain = rule.value.removeprefix("+.").removeprefix(".").replace("*", "probe")
        samples.update({domain, "child." + domain, "deep.child." + domain, "not" + domain})
    for domain in samples:
        assert matches(domain, overlap) == (matches(domain, ai) and matches(domain, claude)), domain
    assert all(rule.action.value == "match" for rule in overlap.values())
    assert len(overlap) >= 5


def test_claude_union_deduplicates_rules_and_retains_all_source_attribution() -> None:
    with gzip.open(DIST / "rules.jsonl.gz", "rt", encoding="utf-8") as handle:
        rules = [Rule.from_dict(json.loads(line)) for line in handle]

    assert len({rule.semantic_key for rule in rules}) == len(rules)
    assert {p.source_id for rule in rules for p in rule.provenance} == SOURCES
    anthropic = [rule for rule in rules if rule.value == "anthropic.com"]
    assert len(anthropic) == 1
    assert {p.source_id for p in anthropic[0].provenance} == SOURCES
    assert all(p.sha256 and p.line for rule in rules for p in rule.provenance)


def test_claude_classical_keeps_network_process_and_shared_service_rules() -> None:
    classical = (DIST / "mihomo-classical.list").read_text().splitlines()
    assert len(classical) == len(set(classical))
    assert {
        "DOMAIN-SUFFIX,claudemcpclient.com",
        "DOMAIN-SUFFIX,claudemcpcontent.com",
        "DOMAIN-SUFFIX,claudeusercontent.com",
        "DOMAIN,downloads.claude.ai",
        "DOMAIN,storage.googleapis.com",
        "DOMAIN-KEYWORD,sentry",
        "PROCESS-NAME,Claude",
        "PROCESS-NAME,claude",
        "IP-ASN,399358,no-resolve",
        "IP-CIDR,160.79.104.0/23,no-resolve",
        "IP-CIDR6,2607:6bc0::/48,no-resolve",
    } <= set(classical)
    report = json.loads((DIST / "compatibility.json").read_text())["outputs"]
    assert report["mihomo-classical-yaml"]["skipped"] == 0
    assert report["mihomo-domain-mrs"]["skipped_by_kind"]["process_name"] > 0
    assert report["mihomo-domain-mrs"]["skipped_by_kind"]["opaque_classical"] > 0


def test_fake_ip_force_inherits_claude_rules_and_provenance() -> None:
    with gzip.open(DIST / "rules.jsonl.gz", "rt", encoding="utf-8") as handle:
        claude = [Rule.from_dict(json.loads(line)) for line in handle]
    force_dir = ROOT / "dist" / "fake-ip-force"
    with gzip.open(force_dir / "rules.jsonl.gz", "rt", encoding="utf-8") as handle:
        force = {
            rule.content_key: rule for line in handle for rule in [Rule.from_dict(json.loads(line))]
        }

    for rule in claude:
        inherited = force[rule.content_key]
        assert inherited.action.value == "fake_ip_force"
        assert set(rule.provenance) <= set(inherited.provenance)

    manifest = json.loads((force_dir / "manifest.json").read_text())
    assert "void-claude-rules" in manifest["rulesets"]
    claude_domains = set((DIST / "mihomo-domain.list").read_text().splitlines())
    force_domains = set((force_dir / "mihomo-domain.list").read_text().splitlines())
    assert claude_domains <= force_domains


def test_upstream_changes_rebuild_claude_fake_ip_force_and_dns_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Use the real catalog, parsers, dependency ordering and build pipeline with
    # small cached upstream revisions; unrelated recipes and native codecs have
    # their own coverage.
    monkeypatch.setenv("VOID_RULES_GEODATA", str(GeodataCodec(ROOT).executable()))
    for directory in ("catalog", "schemas", "overlays"):
        shutil.copytree(ROOT / directory, tmp_path / directory)
    recipe_dir = tmp_path / "recipes"
    recipe_dir.mkdir()
    for name in ("ai", "void-claude-rules", "fake-ip-force", "void-claude-ai-overlap"):
        document = yaml.safe_load((ROOT / "recipes" / f"{name}.yaml").read_text())
        document["outputs"] = ["jsonl", "mihomo-classical-text", "mihomo-domain-text"]
        if name == "ai":
            document["sources"] = ["blackmatrix-openai"]
            document["limits"]["min_rules"] = 1
            for kind in ("include", "exclude", "assertions"):
                overlay = yaml.safe_load((ROOT / document[kind]).read_text())
                for key in ("rules", "selectors", "required", "forbidden"):
                    if key in overlay:
                        overlay[key] = []
                (tmp_path / document[kind]).write_text(yaml.safe_dump(overlay))
        if name == "fake-ip-force":
            document["sources"] = []
            document["rulesets"] = [
                item for item in document["rulesets"] if item == "void-claude-rules"
            ]
            document["limits"]["min_rules"] = 1
            for kind in ("include", "exclude", "assertions"):
                overlay = yaml.safe_load(
                    (ROOT / f"overlays/void-claude-rules/{kind}.yaml").read_text()
                )
                overlay["ruleset"] = name
                (tmp_path / document[kind]).write_text(yaml.safe_dump(overlay))
        (recipe_dir / f"{name}.yaml").write_text(yaml.safe_dump(document))

    catalog = load_catalog(tmp_path)
    cache = tmp_path / ".work/downloads"
    cache.mkdir(parents=True)
    stable = {
        "anthropic.com",
        "clau.de",
        "claude.ai",
        "claude.com",
        "claudeusercontent.com",
        "claudemcpclient.com",
        "claudemcpcontent.com",
        *(f"stable-{index}.example" for index in range(25)),
    }

    def revision(source_id: str, domains: set[str]) -> None:
        lines = [f"DOMAIN-SUFFIX,{domain}" for domain in sorted(domains)]
        source_format = catalog.sources[source_id].format
        if source_format == "clash-classical-yaml":
            data = yaml.safe_dump({"payload": lines})
        elif source_format == "mihomo-domain-text":
            data = "\n".join(f"+.{domain}" for domain in sorted(domains)) + "\n"
        else:
            assert source_format == "clash-classical-text"
            data = "\n".join(lines) + "\n"
        (cache / f"{source_id}.blob").write_text(data)

    for source_id in SOURCES:
        extra = (
            {"retired.example", "child.ai-parent.example"}
            if source_id == "vpsdance-anthropic"
            else set()
        )
        revision(source_id, stable | {"shared.example"} | extra)
    ai_domains = stable | {"shared.example", "ai-only.example", "ai-parent.example"}
    revision("blackmatrix-openai", ai_domains)
    first = build(tmp_path, offline=True)
    assert not first.review_required
    assert set(first.rules) == {
        "ai",
        "void-claude-rules",
        "fake-ip-force",
        "void-claude-ai-overlap",
    }
    first_overlap = {rule.value for rule in first.rules["void-claude-ai-overlap"]}
    assert "child.ai-parent.example" in first_overlap
    assert not {"ai-parent.example", "ai-only.example", "retired.example"} & first_overlap

    # A source adds one domain and drops two. A domain still present in other
    # sources must survive with updated provenance, while an orphan disappears.
    revision("vpsdance-anthropic", stable | {"new.example", "child.ai-parent.example"})
    updated = build(tmp_path, offline=True)
    assert updated.changed
    assert not updated.review_required
    for name in ("void-claude-rules", "fake-ip-force"):
        rules = updated.rules[name]
        values = {rule.value for rule in rules}
        assert "new.example" in values
        assert "retired.example" not in values
        assert len(rules) == len({rule.semantic_key for rule in rules})
        shared = next(rule for rule in rules if rule.value == "shared.example")
        assert {p.source_id for p in shared.provenance} == SOURCES - {"vpsdance-anthropic"}
        assert updated.manifests[name] != first.manifests[name]
        domain_lines = (tmp_path / "dist" / name / "mihomo-domain.list").read_text().splitlines()
        assert "+.new.example" in domain_lines
        assert "+.retired.example" not in domain_lines
        assert domain_lines.count("+.shared.example") == 1

    assert all(rule.action.value == "fake_ip_force" for rule in updated.rules["fake-ip-force"])
    assert "new.example" not in {rule.value for rule in updated.rules["void-claude-ai-overlap"]}

    # Membership follows both sources. Adding the Claude-only domain to AI
    # creates overlap; removing an AI parent must not retain its Claude child.
    revision("blackmatrix-openai", ai_domains - {"ai-parent.example"} | {"new.example"})
    joined = build(tmp_path, offline=True)
    assert not joined.review_required
    joined_overlap = {rule.value for rule in joined.rules["void-claude-ai-overlap"]}
    assert "new.example" in joined_overlap
    assert not {"child.ai-parent.example", "ai-only.example"} & joined_overlap
    assert "child.ai-parent.example" in {rule.value for rule in joined.rules["void-claude-rules"]}

    revision("vpsdance-anthropic", stable | {"child.ai-parent.example"})
    removed = build(tmp_path, offline=True)
    assert not removed.review_required
    assert "new.example" not in {rule.value for rule in removed.rules["void-claude-ai-overlap"]}
    check = build(tmp_path, offline=True, check=True)
    assert not check.changed
    assert not check.review_required
