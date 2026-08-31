from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from void_rules.errors import BuildError
from void_rules.model import Action, Provenance, Rule, RuleKind
from void_rules.snapshots import load_published_source_snapshot


def _write_snapshot(
    root: Path,
    *,
    source_sha: str,
    artifact_sha_override: str | None = None,
) -> None:
    ruleset_dir = root / "dist" / "example"
    ruleset_dir.mkdir(parents=True)
    rules = [
        Rule(
            kind=RuleKind.DOMAIN_SUFFIX,
            value="example.com",
            action=Action.MATCH,
            provenance=(
                Provenance(source_id="missing", line=1, sha256=source_sha, raw="example.com"),
                Provenance(source_id="healthy", line=2, sha256="c" * 64, raw="example.com"),
            ),
            protected=True,
        ),
        Rule(
            kind=RuleKind.DOMAIN,
            value="healthy.example",
            provenance=(Provenance(source_id="healthy", line=3, sha256="c" * 64),),
        ),
    ]
    payload = (
        "\n".join(
            json.dumps(rule.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for rule in rules
        )
        + "\n"
    ).encode()
    compressed = gzip.compress(payload, mtime=0)
    (ruleset_dir / "rules.jsonl.gz").write_bytes(compressed)
    artifact_sha = hashlib.sha256(compressed).hexdigest()
    manifest = {
        "ruleset": "example",
        "sources": ["missing", "healthy"],
        "source_contributions": {"missing": 1, "healthy": 2},
        "outputs": {
            "jsonl": {
                "path": "rules.jsonl.gz",
                "size": len(compressed),
                "sha256": artifact_sha_override or artifact_sha,
            }
        },
    }
    (ruleset_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_published_snapshot_recovers_only_locked_source_provenance(tmp_path: Path) -> None:
    source_sha = "a" * 64
    _write_snapshot(tmp_path, source_sha=source_sha)

    snapshot = load_published_source_snapshot(
        tmp_path,
        ruleset_id="example",
        source_id="missing",
        expected_source_sha=source_sha,
    )

    assert snapshot.provenance_records == 1
    assert len(snapshot.rules) == 1
    recovered = snapshot.rules[0]
    assert recovered.value == "example.com"
    assert recovered.protected is False
    assert [item.source_id for item in recovered.provenance] == ["missing"]


def test_published_snapshot_rejects_source_sha_mismatch(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, source_sha="a" * 64)

    with pytest.raises(BuildError, match="provenance SHA-256"):
        load_published_source_snapshot(
            tmp_path,
            ruleset_id="example",
            source_id="missing",
            expected_source_sha="b" * 64,
        )


def test_published_snapshot_rejects_artifact_manifest_mismatch(tmp_path: Path) -> None:
    _write_snapshot(tmp_path, source_sha="a" * 64, artifact_sha_override="0" * 64)

    with pytest.raises(BuildError, match="published JSONL SHA-256"):
        load_published_source_snapshot(
            tmp_path,
            ruleset_id="example",
            source_id="missing",
            expected_source_sha="a" * 64,
        )
