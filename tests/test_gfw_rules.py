from __future__ import annotations

import gzip
import json
import shutil
from pathlib import Path

import pytest
import yaml

from void_rules.codecs import GeodataCodec
from void_rules.model import Action, RuleKind
from void_rules.pipeline import build

ROOT = Path(__file__).resolve().parents[1]


def test_gfw_yaml_additions_deletions_and_provenance_reach_force(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VOID_RULES_GEODATA", str(GeodataCodec(ROOT).executable()))
    for directory in ("catalog", "schemas", "overlays"):
        shutil.copytree(ROOT / directory, tmp_path / directory)
    (tmp_path / "recipes").mkdir()
    recipe = yaml.safe_load((ROOT / "recipes/fake-ip-force.yaml").read_text())
    recipe.update(sources=["loyalsoldier-gfw"], rulesets=[])
    recipe["outputs"] = ["mihomo-domain-text", "mihomo-classical-text"]
    recipe["limits"]["min_rules"] = 1
    (tmp_path / "recipes/fake-ip-force.yaml").write_text(yaml.safe_dump(recipe))
    (tmp_path / recipe["assertions"]).write_text(
        "version: 1\nruleset: fake-ip-force\nformat: assertions\nrequired: []\nforbidden: []\n"
    )
    source_path = tmp_path / "catalog/sources.yaml"
    catalog = yaml.safe_load(source_path.read_text())
    for source in catalog["sources"]:
        if source["id"] == "loyalsoldier-gfw":
            source["limits"].update(min_bytes=1, min_rules=1)
    source_path.write_text(yaml.safe_dump(catalog))
    cache = tmp_path / ".work/downloads/loyalsoldier-gfw.blob"
    cache.parent.mkdir(parents=True)
    cache.write_text("payload:\n  - '+.gfw-only.example'\n  - '+.retired.example'\n")
    first = build(tmp_path, offline=True)
    contributed = [
        r
        for r in first.rules["fake-ip-force"]
        if any(p.source_id == "loyalsoldier-gfw" for p in r.provenance)
    ]
    assert len(contributed) == 2
    assert all(r.kind is RuleKind.DOMAIN_SUFFIX for r in contributed)
    assert all(r.action is Action.FAKE_IP_FORCE for r in contributed)
    assert b"+.gfw-only.example\n" in first.rendered["fake-ip-force"]["mihomo-domain-text"].data
    cache.write_text("payload:\n  - '+.gfw-only.example'\n  - '+.new.example'\n")
    updated = build(tmp_path, offline=True)
    output = updated.rendered["fake-ip-force"]["mihomo-domain-text"]
    assert b"+.new.example\n" in output.data
    assert b"retired.example" not in output.data
    assert not output.skipped
    assert not build(tmp_path, offline=True, check=True).changed


def test_published_gfw_contribution_contains_no_opaque_rules() -> None:
    with gzip.open(ROOT / "dist/fake-ip-force/rules.jsonl.gz", "rt") as handle:
        rules = [json.loads(line) for line in handle]
    gfw = [r for r in rules if any(p["source_id"] == "loyalsoldier-gfw" for p in r["provenance"])]
    assert gfw
    assert all(r["kind"] == "domain_suffix" for r in gfw)
    output = (ROOT / "dist/fake-ip-force/mihomo-domain.list").read_text().splitlines()
    assert {"+." + r["value"] for r in gfw} <= set(output)
    assert "+.nflxvideo.net" not in output  # Reviewed real-IP compatibility exception.
