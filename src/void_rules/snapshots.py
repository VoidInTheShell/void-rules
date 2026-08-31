from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import BuildError
from .model import Rule, deduplicate_rules


@dataclass(frozen=True, slots=True)
class PublishedSourceSnapshot:
    rules: tuple[Rule, ...]
    provenance_records: int


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"{label}: cannot read published manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise BuildError(f"{label}: published manifest must be a JSON object")
    return value


def load_published_source_snapshot(
    root: Path,
    *,
    ruleset_id: str,
    source_id: str,
    expected_source_sha: str,
) -> PublishedSourceSnapshot:
    """Recover one source's last published contribution with provenance verification."""

    label = f"{source_id} via dist/{ruleset_id}"
    ruleset_dir = root / "dist" / ruleset_id
    manifest = _load_json_object(ruleset_dir / "manifest.json", label)
    if manifest.get("ruleset") != ruleset_id:
        raise BuildError(f"{label}: manifest ruleset identity does not match")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or source_id not in sources:
        raise BuildError(f"{label}: source is not a direct member of the published ruleset")
    contributions = manifest.get("source_contributions")
    if not isinstance(contributions, dict) or source_id not in contributions:
        raise BuildError(f"{label}: manifest has no source contribution record")
    try:
        expected_provenance = int(contributions[source_id])
        output = manifest["outputs"]["jsonl"]
        relative_path = str(output["path"])
        expected_size = int(output["size"])
        expected_artifact_sha = str(output["sha256"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BuildError(f"{label}: invalid published JSONL metadata") from exc

    artifact = ruleset_dir / relative_path
    try:
        artifact.resolve().relative_to(ruleset_dir.resolve())
    except ValueError as exc:
        raise BuildError(f"{label}: published JSONL path escapes its ruleset directory") from exc
    try:
        compressed = artifact.read_bytes()
    except OSError as exc:
        raise BuildError(f"{label}: cannot read published JSONL: {exc}") from exc
    if len(compressed) != expected_size:
        raise BuildError(f"{label}: published JSONL size does not match its manifest")
    if hashlib.sha256(compressed).hexdigest() != expected_artifact_sha:
        raise BuildError(f"{label}: published JSONL SHA-256 does not match its manifest")
    try:
        payload = gzip.decompress(compressed).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BuildError(f"{label}: published JSONL cannot be decompressed as UTF-8") from exc

    recovered: list[Rule] = []
    provenance_records = 0
    for line_number, line in enumerate(payload.splitlines(), start=1):
        if not line:
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("rule must be an object")
            rule = Rule.from_dict(value)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BuildError(f"{label}: invalid rule at JSONL line {line_number}: {exc}") from exc
        source_provenance = tuple(item for item in rule.provenance if item.source_id == source_id)
        if not source_provenance:
            continue
        if any(item.sha256 != expected_source_sha for item in source_provenance):
            raise BuildError(f"{label}: provenance SHA-256 does not match the source lock")
        provenance_records += len(source_provenance)
        recovered.append(
            Rule(
                kind=rule.kind,
                value=rule.value,
                action=rule.action,
                attributes=rule.attributes,
                provenance=source_provenance,
                protected=False,
            )
        )

    if provenance_records != expected_provenance:
        raise BuildError(
            f"{label}: recovered {provenance_records} provenance records, "
            f"manifest requires {expected_provenance}"
        )
    return PublishedSourceSnapshot(
        rules=tuple(deduplicate_rules(recovered)),
        provenance_records=provenance_records,
    )
