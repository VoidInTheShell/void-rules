from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters import parse_source
from .catalog import Catalog, Recipe, load_catalog, load_overlay
from .errors import BuildError, FetchError, ParseError
from .fetch import (
    STALE_SOURCE_REASON,
    build_lock_entry,
    build_stale_lock_entry,
    fetch_sources,
    load_previous_lock,
    write_json_atomic,
)
from .model import Action, ParseResult, Provenance, Rule, RuleKind, deduplicate_rules
from .normalize import normalize_domain, normalize_ip_network
from .parsers import parse_classical_line, parse_mihomo_domain_line
from .render import RenderedFile, output_manifest, render_outputs, rule_counts
from .snapshots import load_published_source_snapshot
from .transforms import derive_domain_keyword_fallbacks


@dataclass(slots=True)
class BuildResult:
    rules: dict[str, list[Rule]]
    rendered: dict[str, dict[str, RenderedFile]]
    manifests: dict[str, dict[str, Any]]
    compatibility: dict[str, dict[str, Any]]
    lock: dict[str, Any]
    report: dict[str, Any]
    changed: bool
    review_required: bool


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _normalized_overlay_value(kind: RuleKind, value: str) -> str:
    if kind in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
        return normalize_domain(value)
    if kind in {RuleKind.IP_CIDR, RuleKind.SRC_IP_CIDR}:
        return normalize_ip_network(value)
    return value.strip()


def _overlay_rules(recipe: Recipe) -> list[Rule]:
    document = load_overlay(recipe.include)
    source_id = f"overlay:{recipe.id}"
    digest = _sha256_path(recipe.include)
    default_reason = str(document.get("default_reason", "protected local requirement"))
    overlay_format = str(document.get("format", "plain"))
    rules: list[Rule] = []
    for line_number, item in enumerate(document.get("rules", []), start=1):
        if isinstance(item, str):
            if overlay_format == "mihomo-domain":
                parsed = parse_mihomo_domain_line(
                    item,
                    source_id=source_id,
                    line=line_number,
                    sha256=digest,
                    action=recipe.action,
                    protected=True,
                )
            elif overlay_format == "clash-classical":
                parsed = parse_classical_line(
                    item,
                    source_id=source_id,
                    line=line_number,
                    sha256=digest,
                    action=recipe.action,
                    protected=True,
                )
            else:
                parsed = parse_mihomo_domain_line(
                    item,
                    source_id=source_id,
                    line=line_number,
                    sha256=digest,
                    action=recipe.action,
                    protected=True,
                )
            provenance = parsed.provenance[0]
            parsed = Rule(
                kind=parsed.kind,
                value=parsed.value,
                action=parsed.action,
                attributes=parsed.attributes,
                provenance=(
                    Provenance(
                        source_id=provenance.source_id,
                        line=provenance.line,
                        sha256=provenance.sha256,
                        evidence=default_reason,
                        raw=provenance.raw,
                    ),
                ),
                protected=True,
            )
            rules.append(parsed)
            continue
        if not isinstance(item, dict):
            raise BuildError(f"{recipe.id}: overlay rule {line_number} is not a string/object")
        try:
            kind = RuleKind(str(item["kind"]))
            value = _normalized_overlay_value(kind, str(item["value"]))
            action = Action(str(item.get("action", recipe.action.value)))
            reason = str(item["reason"])
        except (KeyError, ValueError, ParseError) as exc:
            raise BuildError(f"{recipe.id}: invalid overlay rule {line_number}: {exc}") from exc
        rules.append(
            Rule(
                kind=kind,
                value=value,
                action=action,
                attributes=tuple(sorted(str(value) for value in item.get("attributes", []))),
                provenance=(
                    Provenance(
                        source_id=source_id,
                        line=line_number,
                        sha256=digest,
                        evidence=str(item.get("evidence", reason)),
                        raw=json.dumps(item, ensure_ascii=False, sort_keys=True),
                    ),
                ),
                protected=True,
            )
        )
    return rules


def _selector_matches(rule: Rule, selector: dict[str, Any]) -> bool:
    try:
        kind = RuleKind(str(selector["kind"]))
        value = _normalized_overlay_value(kind, str(selector["value"]))
    except (KeyError, ValueError, ParseError):
        return False
    if rule.kind is not kind or rule.value != value:
        return False
    if selector.get("action") and rule.action.value != str(selector["action"]):
        return False
    source_id = selector.get("source_id")
    return not (source_id and all(item.source_id != source_id for item in rule.provenance))


def _apply_excludes(recipe: Recipe, rules: list[Rule]) -> tuple[list[Rule], list[Rule]]:
    document = load_overlay(recipe.exclude)
    selectors = [item for item in document.get("selectors", []) if isinstance(item, dict)]
    kept: list[Rule] = []
    removed: list[Rule] = []
    for rule in rules:
        if any(_selector_matches(rule, selector) for selector in selectors):
            removed.append(rule)
        else:
            kept.append(rule)
    return kept, removed


def _run_assertions(recipe: Recipe, rules: list[Rule]) -> None:
    document = load_overlay(recipe.assertions)
    missing = [
        selector
        for selector in document.get("required", [])
        if isinstance(selector, dict)
        and not any(_selector_matches(rule, selector) for rule in rules)
    ]
    forbidden = [
        selector
        for selector in document.get("forbidden", [])
        if isinstance(selector, dict) and any(_selector_matches(rule, selector) for rule in rules)
    ]
    if missing or forbidden:
        details: list[str] = []
        if missing:
            details.append("missing required: " + json.dumps(missing, ensure_ascii=False))
        if forbidden:
            details.append("present but forbidden: " + json.dumps(forbidden, ensure_ascii=False))
        raise BuildError(f"{recipe.id}: assertion failure; " + "; ".join(details))


def _recast(rule: Rule, action: Action) -> Rule:
    if action is Action.BLOCK and rule.action is Action.ALLOW:
        return rule
    return rule.with_action(action)


def _compose_recipe(
    recipe: Recipe,
    parsed_sources: dict[str, ParseResult],
    stale_sources: dict[str, list[Rule]],
    built_rules: dict[str, list[Rule]],
) -> tuple[list[Rule], dict[str, Any]]:
    rules: list[Rule] = []
    for source_id in recipe.sources:
        if source_id in parsed_sources:
            rules.extend(_recast(rule, recipe.action) for rule in parsed_sources[source_id].rules)
        elif source_id not in stale_sources:
            raise BuildError(f"{recipe.id}: source {source_id} has no fresh or published rules")
    for dependency in recipe.rulesets:
        rules.extend(_recast(rule, recipe.action) for rule in built_rules[dependency])
    rules.extend(_overlay_rules(recipe))
    rules = deduplicate_rules(rules)
    if recipe.domain_keyword_fallback is not None:
        rules.extend(derive_domain_keyword_fallbacks(rules, recipe.domain_keyword_fallback))
        rules = deduplicate_rules(rules)
    for source_id in recipe.sources:
        rules.extend(stale_sources.get(source_id, []))
    rules = deduplicate_rules(rules)
    rules, removed = _apply_excludes(recipe, rules)
    rules = deduplicate_rules(rules)
    if not recipe.limits.min_rules <= len(rules) <= recipe.limits.max_rules:
        raise BuildError(
            f"{recipe.id}: effective rule count {len(rules)} outside "
            f"[{recipe.limits.min_rules}, {recipe.limits.max_rules}]"
        )
    _run_assertions(recipe, rules)
    return rules, {
        "excluded_rules": len(removed),
        "excluded_protected_rules": sum(1 for rule in removed if rule.protected),
    }


def _load_conflict_resolutions(catalog: Catalog) -> dict[tuple[str, str], dict[str, Any]]:
    paths = {
        recipe.conflict_resolutions
        for recipe in catalog.recipes.values()
        if recipe.conflict_resolutions is not None
    }
    resolutions: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted(paths):
        document = load_overlay(path)
        for item in document.get("allow", []):
            if not isinstance(item, dict):
                continue
            try:
                kind = RuleKind(str(item["kind"]))
                value = _normalized_overlay_value(kind, str(item["value"]))
            except (KeyError, ValueError, ParseError) as exc:
                raise BuildError(f"invalid Fake-IP conflict resolution in {path}: {exc}") from exc
            resolutions[(kind.value, value)] = item
    return resolutions


def _resolve_fakeip_conflicts(
    catalog: Catalog,
    built: dict[str, list[Rule]],
) -> tuple[dict[str, Any], list[str]]:
    if "fake-ip-bypass" not in built or "fake-ip-force" not in built:
        return {"total": 0, "items": []}, []
    bypass = {rule.content_key: rule for rule in built["fake-ip-bypass"]}
    force = {rule.content_key: rule for rule in built["fake-ip-force"]}
    overlap = sorted(set(bypass) & set(force))
    resolutions = _load_conflict_resolutions(catalog)
    remove_bypass: set[tuple[str, str, tuple[str, ...]]] = set()
    remove_force: set[tuple[str, str, tuple[str, ...]]] = set()
    review_reasons: list[str] = []
    items: list[dict[str, Any]] = []
    for key in overlap:
        bypass_rule = bypass[key]
        force_rule = force[key]
        resolution = resolutions.get((bypass_rule.kind.value, bypass_rule.value))
        winner = str(resolution.get("winner")) if resolution else "fake-ip-bypass"
        if winner == "fake-ip-bypass":
            remove_force.add(key)
        elif winner == "fake-ip-force":
            remove_bypass.add(key)
        elif winner != "both":
            raise BuildError(f"invalid Fake-IP conflict winner: {winner}")
        protected_both = bypass_rule.protected and force_rule.protected
        if resolution is None:
            review_reasons.append(
                f"unreviewed Fake-IP overlap: {bypass_rule.kind.value},{bypass_rule.value}"
            )
            if protected_both:
                raise BuildError(
                    "protected Fake-IP force/bypass conflict requires an explicit resolution: "
                    f"{bypass_rule.kind.value},{bypass_rule.value}"
                )
        items.append(
            {
                "kind": bypass_rule.kind.value,
                "value": bypass_rule.value,
                "winner": winner,
                "explicit": resolution is not None,
                "protected_bypass": bypass_rule.protected,
                "protected_force": force_rule.protected,
            }
        )
    built["fake-ip-bypass"] = [
        rule for rule in built["fake-ip-bypass"] if rule.content_key not in remove_bypass
    ]
    built["fake-ip-force"] = [
        rule for rule in built["fake-ip-force"] if rule.content_key not in remove_force
    ]
    _run_assertions(catalog.recipes["fake-ip-bypass"], built["fake-ip-bypass"])
    _run_assertions(catalog.recipes["fake-ip-force"], built["fake-ip-force"])
    return {"total": len(items), "items": items}, review_reasons


def _previous_by_id(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("id")): item
        for item in lock.get("sources", [])
        if isinstance(item, dict) and item.get("id")
    }


def _ratio_review(
    label: str,
    current: int,
    previous: int,
    max_growth: float,
    max_shrink: float,
) -> str | None:
    if previous <= 0:
        return None
    ratio = current / previous
    if ratio > max_growth:
        return f"{label} grew from {previous} to {current} ({ratio:.2f}x > {max_growth:.2f}x)"
    if ratio < max_shrink:
        return f"{label} shrank from {previous} to {current} ({ratio:.2f}x < {max_shrink:.2f}x)"
    return None


def _compatibility_report(rendered: dict[str, RenderedFile]) -> dict[str, Any]:
    outputs: dict[str, Any] = {}
    for output_id, item in sorted(rendered.items()):
        counts: dict[str, int] = {}
        for skipped in item.skipped:
            kind = skipped["kind"]
            counts[kind] = counts.get(kind, 0) + 1
        outputs[output_id] = {
            "represented": item.represented,
            "skipped": len(item.skipped),
            "skipped_by_kind": dict(sorted(counts.items())),
            "examples": list(item.skipped[:100]),
        }
    return {"outputs": outputs}


def _manifest(
    recipe: Recipe,
    rules: list[Rule],
    rendered: dict[str, RenderedFile],
    composition: dict[str, Any],
) -> dict[str, Any]:
    source_counts: dict[str, int] = {}
    for rule in rules:
        for provenance in rule.provenance:
            source_counts[provenance.source_id] = source_counts.get(provenance.source_id, 0) + 1
    return {
        "version": 1,
        "ruleset": recipe.id,
        "description": recipe.description,
        "action": recipe.action.value,
        "sources": list(recipe.sources),
        "rulesets": list(recipe.rulesets),
        "counts": rule_counts(rules),
        "source_contributions": dict(sorted(source_counts.items())),
        "composition": composition,
        "outputs": output_manifest(rendered),
    }


def _collect_expected_files(
    rendered: dict[str, RenderedFile], manifest: dict[str, Any], compatibility: dict[str, Any]
) -> dict[str, bytes]:
    files = {item.name: item.data for item in rendered.values()}
    files["manifest.json"] = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    files["compatibility.json"] = (
        json.dumps(compatibility, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    return files


def _directory_matches(path: Path, expected: dict[str, bytes]) -> bool:
    actual_names = (
        {item.name for item in path.iterdir() if item.is_file()} if path.is_dir() else set()
    )
    if actual_names != set(expected):
        return False
    return all((path / name).read_bytes() == data for name, data in expected.items())


def _write_directory(path: Path, expected: dict[str, bytes]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()
    for existing in path.iterdir():
        if existing.is_file() and existing.name not in expected:
            if existing.resolve().parent != resolved:
                raise BuildError(f"refusing to remove file outside target: {existing}")
            existing.unlink()
    for name, data in expected.items():
        target = path / name
        handle, temporary = tempfile.mkstemp(prefix=target.name + ".", dir=path)
        try:
            with os.fdopen(handle, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def build(
    root: Path,
    *,
    offline: bool = False,
    check: bool = False,
    skip_binary: bool = False,
    selected_rulesets: set[str] | None = None,
    workers: int = 8,
) -> BuildResult:
    catalog = load_catalog(root)
    selected = set(catalog.recipes) if not selected_rulesets else set(selected_rulesets)
    unknown = selected - set(catalog.recipes)
    if unknown:
        raise BuildError(f"unknown rulesets: {', '.join(sorted(unknown))}")
    expanded = set(selected)
    changed_dependency = True
    while changed_dependency:
        changed_dependency = False
        for recipe_id in list(expanded):
            before = len(expanded)
            expanded.update(catalog.recipes[recipe_id].rulesets)
            changed_dependency = changed_dependency or len(expanded) != before

    source_ids = {
        source_id for recipe_id in expanded for source_id in catalog.recipes[recipe_id].sources
    }
    source_specs = [catalog.sources[source_id] for source_id in sorted(source_ids)]
    previous_lock = load_previous_lock(root / "generated" / "sources.lock.json")
    previous_sources = _previous_by_id(previous_lock)
    work_dir = root / ".work"
    forced_stale = {
        spec.id
        for spec in source_specs
        if offline and previous_sources.get(spec.id, {}).get("sync_status") == "stale"
    }
    fetch_result = fetch_sources(
        [spec for spec in source_specs if spec.id not in forced_stale],
        work_dir,
        offline=offline,
        workers=workers,
    )
    fetch_failures = dict(fetch_result.failures)
    fetch_failures.update(
        {
            source_id: "source remains marked stale during offline rebuild"
            for source_id in forced_stale
        }
    )

    parsed: dict[str, ParseResult] = {}
    stale_by_recipe: dict[str, dict[str, list[Rule]]] = {}
    stale_report: list[dict[str, Any]] = []
    lock_entries: list[dict[str, Any]] = []
    review_reasons: list[str] = []
    rejected: list[dict[str, Any]] = []
    unrecoverable: list[str] = []
    for source_id in sorted(source_ids):
        previous = previous_sources.get(source_id)
        item = fetch_result.downloaded.get(source_id)
        if item is not None:
            result = parse_source(item.spec, item.data, item.sha256, root=root)
            count = len(result.rules)
            if not item.spec.limits.min_rules <= count <= item.spec.limits.max_rules:
                raise BuildError(
                    f"{source_id}: parsed rule count {count} outside "
                    f"[{item.spec.limits.min_rules}, {item.spec.limits.max_rules}]"
                )
            if previous:
                reason = _ratio_review(
                    f"source {source_id}",
                    count,
                    int(previous.get("parsed_rules", 0)),
                    item.spec.limits.max_growth_ratio,
                    item.spec.limits.max_shrink_ratio,
                )
                if reason:
                    review_reasons.append(reason)
            parsed[source_id] = result
            rejected.extend(entry.as_dict() for entry in result.rejected)
            lock_entries.append(
                build_lock_entry(
                    item,
                    parsed_rules=count,
                    rejected_rules=len(result.rejected),
                    previous=previous,
                )
            )
            continue

        spec = catalog.sources[source_id]
        if source_id not in fetch_failures:
            unrecoverable.append(f"{source_id}: source fetch produced no result")
            continue
        if previous is None:
            unrecoverable.append(
                f"{source_id}: {fetch_failures[source_id]}; no previous source lock exists"
            )
            continue
        expected_sha = str(previous.get("sha256", ""))
        direct_recipes = sorted(
            recipe_id for recipe_id in expanded if source_id in catalog.recipes[recipe_id].sources
        )
        snapshots: list[dict[str, Any]] = []
        try:
            if not direct_recipes:
                raise BuildError("no selected ruleset directly references this source")
            for recipe_id in direct_recipes:
                snapshot = load_published_source_snapshot(
                    root,
                    ruleset_id=recipe_id,
                    source_id=source_id,
                    expected_source_sha=expected_sha,
                )
                stale_by_recipe.setdefault(recipe_id, {})[source_id] = list(snapshot.rules)
                snapshots.append(
                    {
                        "ruleset": recipe_id,
                        "rules": len(snapshot.rules),
                        "provenance_records": snapshot.provenance_records,
                    }
                )
            lock_entries.append(
                build_stale_lock_entry(
                    spec,
                    previous=previous,
                    preserved_rules=sum(int(entry["rules"]) for entry in snapshots),
                    preserved_provenance=sum(
                        int(entry["provenance_records"]) for entry in snapshots
                    ),
                    stale_rulesets=direct_recipes,
                )
            )
        except (BuildError, FetchError) as exc:
            unrecoverable.append(f"{source_id}: {fetch_failures[source_id]}; {exc}")
            continue
        stale_report.append(
            {
                "id": source_id,
                "reason": STALE_SOURCE_REASON,
                "rulesets": snapshots,
            }
        )

    if unrecoverable:
        raise FetchError("source synchronization failed:\n- " + "\n- ".join(unrecoverable))

    built_rules: dict[str, list[Rule]] = {}
    compositions: dict[str, dict[str, Any]] = {}
    for recipe_id in catalog.recipe_order:
        if recipe_id not in expanded:
            continue
        rules, composition = _compose_recipe(
            catalog.recipes[recipe_id],
            parsed,
            stale_by_recipe.get(recipe_id, {}),
            built_rules,
        )
        built_rules[recipe_id] = rules
        compositions[recipe_id] = composition

    conflict_report, conflict_review = _resolve_fakeip_conflicts(catalog, built_rules)
    review_reasons.extend(conflict_review)

    rendered_by_ruleset: dict[str, dict[str, RenderedFile]] = {}
    manifests: dict[str, dict[str, Any]] = {}
    compatibility: dict[str, dict[str, Any]] = {}
    changed = False
    for recipe_id in sorted(selected):
        recipe = catalog.recipes[recipe_id]
        rules = built_rules[recipe_id]
        rendered = render_outputs(
            recipe_id,
            rules,
            recipe.action,
            recipe.outputs,
            root=root,
            skip_binary=skip_binary,
        )
        manifest = _manifest(recipe, rules, rendered, compositions[recipe_id])
        prior_manifest_path = root / "dist" / recipe_id / "manifest.json"
        if prior_manifest_path.exists():
            try:
                prior_manifest = json.loads(prior_manifest_path.read_text(encoding="utf-8"))
                prior_count = int(prior_manifest.get("counts", {}).get("total", 0))
            except (json.JSONDecodeError, TypeError, ValueError):
                prior_count = 0
            reason = _ratio_review(
                f"ruleset {recipe_id}",
                len(rules),
                prior_count,
                recipe.limits.max_growth_ratio,
                recipe.limits.max_shrink_ratio,
            )
            if reason:
                review_reasons.append(reason)
        compatible = _compatibility_report(rendered)
        expected = _collect_expected_files(rendered, manifest, compatible)
        target = root / "dist" / recipe_id
        matches = _directory_matches(target, expected)
        changed = changed or not matches
        if check:
            if not matches:
                review_reasons.append(f"dist/{recipe_id} is not reproducible")
        else:
            _write_directory(target, expected)
        rendered_by_ruleset[recipe_id] = rendered
        manifests[recipe_id] = manifest
        compatibility[recipe_id] = compatible

    lock = {"version": 1, "sources": lock_entries}
    report = {
        "version": 1,
        "selected_rulesets": sorted(selected),
        "review_required": bool(review_reasons),
        "review_reasons": sorted(set(review_reasons)),
        "fake_ip_conflicts": conflict_report,
        "rejected_lines": rejected,
        "stale_sources": stale_report,
    }
    if not check:
        write_json_atomic(root / "generated" / "sources.lock.json", lock)
        write_json_atomic(root / "generated" / "reports" / "build.json", report)
        write_json_atomic(root / "generated" / "reports" / "compatibility.json", compatibility)
    return BuildResult(
        rules={key: value for key, value in built_rules.items() if key in selected},
        rendered=rendered_by_ruleset,
        manifests=manifests,
        compatibility=compatibility,
        lock=lock,
        report=report,
        changed=changed,
        review_required=bool(review_reasons),
    )
