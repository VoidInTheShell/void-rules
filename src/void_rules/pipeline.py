from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters import parse_source
from .catalog import Catalog, Recipe, load_catalog, load_overlay
from .errors import BuildError, FetchError, ParseError
from .fetch import (
    STALE_SOURCE_REASON,
    DownloadedSource,
    SourceFetchResult,
    _guard_payload,
    build_lock_entry,
    build_stale_lock_entry,
    fetch_sources,
    load_previous_lock,
    write_json_atomic,
)
from .inputs import InputStore
from .intersection import intersect_ruleset_members
from .model import Action, ParseResult, Provenance, Rule, RuleKind, deduplicate_rules
from .normalize import normalize_domain, normalize_ip_network
from .parsers import parse_classical_line, parse_mihomo_domain_line
from .publication import (
    changed_files,
    json_bytes,
    obsolete_files,
    publication_digest,
    publish_files,
)
from .render import RenderedFile, output_manifest, render_outputs, rule_counts
from .separation import exclude_ruleset_members, is_stun_turn_rule
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
    changed_paths: tuple[str, ...]
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
    local_rules = _overlay_rules(recipe)
    membership = list(local_rules)
    filtering: dict[str, Any] = {}
    if recipe.filtered_sources:
        missing = sorted(set(recipe.sources) - set(parsed_sources))
        if missing:
            raise FetchError(
                f"{recipe.id}: mixed-source filtering requires fresh sources: " + ", ".join(missing)
            )
        for source_id in recipe.sources:
            if source_id not in recipe.filtered_sources:
                membership.extend(parsed_sources[source_id].rules)
            elif recipe.source_filter == "stun-turn":
                membership.extend(
                    rule for rule in parsed_sources[source_id].rules if is_stun_turn_rule(rule)
                )
    for source_id in recipe.sources:
        if source_id in parsed_sources:
            source_rules = parsed_sources[source_id].rules
            if source_id in recipe.filtered_sources:
                omitted, source_rules = exclude_ruleset_members(source_rules, membership)
                filtering[source_id] = {"selected": len(source_rules), "omitted": len(omitted)}
                if source_id in recipe.review_unmatched_sources:
                    filtering[source_id]["omitted_items"] = [
                        rule.as_dict(include_provenance=False)
                        for rule in deduplicate_rules(omitted)
                    ]
            rules.extend(_recast(rule, recipe.action) for rule in source_rules)
        elif source_id not in stale_sources:
            raise BuildError(f"{recipe.id}: source {source_id} has no fresh or published rules")
    if recipe.intersect_rulesets:
        shared_rules = built_rules[recipe.intersect_rulesets[0]]
        for dependency in recipe.intersect_rulesets[1:]:
            shared_rules = intersect_ruleset_members(
                shared_rules, built_rules[dependency], recipe.action
            )
        rules.extend(
            rule
            for rule in shared_rules
            if not recipe.intersection_kinds or rule.kind.value in recipe.intersection_kinds
        )
    else:
        for dependency in recipe.rulesets:
            rules.extend(_recast(rule, recipe.action) for rule in built_rules[dependency])
    rules.extend(local_rules)
    rules = deduplicate_rules(rules)
    if recipe.domain_keyword_fallback is not None:
        rules.extend(derive_domain_keyword_fallbacks(rules, recipe.domain_keyword_fallback))
        rules = deduplicate_rules(rules)
    for source_id in recipe.sources:
        rules.extend(stale_sources.get(source_id, []))
    rules = deduplicate_rules(rules)
    rules, removed = _apply_excludes(recipe, rules)
    separation: dict[str, Any] = {}
    for dependency in recipe.exclude_rulesets:
        rules, excluded = exclude_ruleset_members(rules, built_rules[dependency])
        removed.extend(excluded)
        separation[dependency] = {
            "count": len(excluded),
            "items": [{"kind": rule.kind.value, "value": rule.value} for rule in excluded],
            "retained_domain_suffix_overlaps": [
                {"excluded": pair["bypass"], "retained": pair["force"]}
                for pair in _fakeip_coverage_overlaps(built_rules[dependency], rules)["items"]
            ],
        }
    rules = deduplicate_rules(rules)
    if not recipe.limits.min_rules <= len(rules) <= recipe.limits.max_rules:
        raise BuildError(
            f"{recipe.id}: effective rule count {len(rules)} outside "
            f"[{recipe.limits.min_rules}, {recipe.limits.max_rules}]"
        )
    _run_assertions(recipe, rules)
    composition: dict[str, Any] = {
        "excluded_rules": len(removed),
        "excluded_protected_rules": sum(1 for rule in removed if rule.protected),
    }
    if filtering:
        composition["filtered_sources"] = filtering
    if recipe.intersect_rulesets:
        composition["intersect_rulesets"] = list(recipe.intersect_rulesets)
        if recipe.intersection_kinds:
            composition["intersection_kinds"] = list(recipe.intersection_kinds)
    if separation:
        return rules, {**composition, "excluded_rulesets": separation}
    return rules, composition


def _check_unmatched_source_changes(
    catalog: Catalog,
    recipe: Recipe,
    composition: dict[str, Any],
    previous_sources: dict[str, dict[str, Any]],
) -> None:
    """Reject unknown additions before writing outputs or advancing the baseline."""
    if not recipe.review_unmatched_sources:
        return
    manifest_path = catalog.root / "dist" / recipe.id / "manifest.json"
    previous: dict[str, Any] = {}
    if manifest_path.exists():
        try:
            previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BuildError(f"{recipe.id}: cannot read classification baseline: {exc}") from exc
        if not isinstance(previous, dict):
            raise BuildError(f"{recipe.id}: classification baseline must be an object")
    for source_id in recipe.review_unmatched_sources:
        if source_id not in previous_sources:
            continue  # First build: source/recipe registration is the review boundary.
        old_items = (
            previous.get("composition", {})
            .get("filtered_sources", {})
            .get(source_id, {})
            .get("omitted_items")
        )
        if old_items is not None:
            known = {Rule.from_dict(item).content_key for item in old_items}
        else:
            # Migrate the old count-only manifest using verified published
            # bypass provenance, never the just-downloaded mixed-source data.
            known = set()
            for consumer in catalog.recipes.values():
                if recipe.id in consumer.exclude_rulesets and source_id in consumer.sources:
                    snapshot = load_published_source_snapshot(
                        catalog.root,
                        ruleset_id=consumer.id,
                        source_id=source_id,
                        expected_source_sha=str(previous_sources[source_id]["sha256"]),
                    )
                    known.update(rule.content_key for rule in snapshot.rules)
            if not known:
                raise BuildError(f"{recipe.id}: no reviewed unmatched baseline for {source_id}")
        current = composition["filtered_sources"][source_id]["omitted_items"]
        added = [item for item in current if Rule.from_dict(item).content_key not in known]
        if added:
            raise BuildError(
                f"{recipe.id}: {len(added)} unclassified additions from {source_id} "
                "require review: " + json.dumps(added, ensure_ascii=False, sort_keys=True)
            )


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


def _fakeip_coverage_overlaps(bypass: list[Rule], force: list[Rule]) -> dict[str, Any]:
    """Report domain/suffix coverage left for ordered DNS rules to resolve.

    A positive domain set cannot subtract a child from a parent suffix. Keep
    both rules and expose those intersections separately from exact conflicts.
    Keywords, regexes and wildcards are outside this diagnostic's scope.
    """

    domain_kinds = {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}
    bypass_keys = {(rule.kind.value, rule.value) for rule in bypass if rule.kind in domain_kinds}
    force_keys = {(rule.kind.value, rule.value) for rule in force if rule.kind in domain_kinds}
    overlaps: set[tuple[str, str, str, str]] = set()
    for narrow, broad, reversed_sides in (
        (bypass_keys, force_keys, False),
        (force_keys, bypass_keys, True),
    ):
        suffixes = {value for kind, value in broad if kind == RuleKind.DOMAIN_SUFFIX.value}
        for kind, value in narrow:
            labels = value.split(".")
            for offset in range(len(labels)):
                suffix = ".".join(labels[offset:])
                if suffix not in suffixes or (offset == 0 and kind == RuleKind.DOMAIN_SUFFIX.value):
                    continue
                pair = (kind, value, RuleKind.DOMAIN_SUFFIX.value, suffix)
                if reversed_sides:
                    pair = (pair[2], pair[3], pair[0], pair[1])
                overlaps.add(pair)
    items = [
        {
            "bypass": {"kind": bypass_kind, "value": bypass_value},
            "force": {"kind": force_kind, "value": force_value},
        }
        for bypass_kind, bypass_value, force_kind, force_value in sorted(overlaps)
    ]
    return {"total": len(items), "items": items}


def _resolve_fakeip_conflicts(
    catalog: Catalog,
    built: dict[str, list[Rule]],
) -> tuple[dict[str, Any], list[str]]:
    if "fake-ip-bypass" not in built or "fake-ip-force" not in built:
        return {"total": 0, "items": [], "coverage_overlaps": {"total": 0, "items": []}}, []
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
    return {
        "total": len(items),
        "items": items,
        "coverage_overlaps": _fakeip_coverage_overlaps(
            built["fake-ip-bypass"], built["fake-ip-force"]
        ),
    }, review_reasons


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
    manifest = {
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
    if recipe.exclude_rulesets:
        manifest["exclude_rulesets"] = list(recipe.exclude_rulesets)
    if recipe.intersect_rulesets:
        manifest["intersect_rulesets"] = list(recipe.intersect_rulesets)
        if recipe.intersection_kinds:
            manifest["intersection_kinds"] = list(recipe.intersection_kinds)
    if recipe.filtered_sources:
        manifest["filtered_sources"] = list(recipe.filtered_sources)
    if recipe.source_filter:
        manifest["source_filter"] = recipe.source_filter
    if recipe.review_unmatched_sources:
        manifest["review_unmatched_sources"] = list(recipe.review_unmatched_sources)
    return manifest


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


def _build(
    root: Path,
    *,
    offline: bool = False,
    locked: bool = False,
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
    inputs = InputStore(root, "sources", required=locked)
    previous_report: dict[str, Any] = {}
    previous_compatibility: dict[str, Any] = {}
    if selected != set(catalog.recipes):
        try:
            previous_report = json.loads((root / "generated/reports/build.json").read_bytes())
            previous_compatibility = json.loads(
                (root / "generated/reports/compatibility.json").read_bytes()
            )
            complete = (
                set(previous_report["selected_rulesets"]) == set(catalog.recipes)
                and set(previous_compatibility) == set(catalog.recipes)
                and previous_report["review_required"] is False
                and bool(inputs.entries)
            )
        except (OSError, ValueError, KeyError, TypeError):
            complete = False
        if not complete:
            selected = set(catalog.recipes)
            previous_report = {}
            previous_compatibility = {}
    expanded = set(selected)
    while True:
        before = set(expanded)
        touched_sources = {
            source for recipe_id in expanded for source in catalog.recipes[recipe_id].sources
        }
        for recipe_id, recipe in catalog.recipes.items():
            if recipe_id in expanded:
                expanded.update(recipe.dependencies)
            if set(recipe.dependencies) & expanded or set(recipe.sources) & touched_sources:
                expanded.add(recipe_id)
        fakeip_pair = {"fake-ip-force", "fake-ip-bypass"} & set(catalog.recipes)
        if expanded & fakeip_pair:
            expanded.update(fakeip_pair)
        if expanded == before:
            break
    selected = expanded

    source_ids = {
        source_id for recipe_id in expanded for source_id in catalog.recipes[recipe_id].sources
    }
    source_specs = [catalog.sources[source_id] for source_id in sorted(source_ids)]
    previous_lock = load_previous_lock(root / "generated" / "sources.lock.json")
    previous_sources = _previous_by_id(previous_lock)
    if locked:
        previous_sources = {key: entry["metadata"] for key, entry in inputs.entries.items()}
    work_dir = root / ".work"
    forced_stale = {
        spec.id
        for spec in source_specs
        if (offline or locked) and previous_sources.get(spec.id, {}).get("sync_status") == "stale"
    }
    if locked:
        downloaded = {}
        for spec in source_specs:
            data, metadata = inputs.read(spec.id)
            _guard_payload(spec, data, "")
            digest = hashlib.sha256(data).hexdigest()
            if metadata.get("sha256") != digest or metadata.get("id") != spec.id:
                raise FetchError(f"{spec.id}: locked source metadata does not match input")
            if spec.id not in forced_stale:
                downloaded[spec.id] = DownloadedSource(
                    spec,
                    data,
                    digest,
                    metadata["final_url"],
                    metadata["etag"],
                    metadata["last_modified"],
                    True,
                )
        fetch_result = SourceFetchResult(downloaded, {})
    else:
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

    # An old exclusion list could silently re-admit new members from another
    # source. Require fresh inputs for every exclusion dependency, even when
    # ordinary rulesets are allowed to preserve an unavailable upstream.
    for recipe_id in sorted(expanded):
        pending = list(catalog.recipes[recipe_id].exclude_rulesets)
        seen: set[str] = set()
        while pending:
            dependency = pending.pop()
            if dependency in seen:
                continue
            seen.add(dependency)
            dependency_recipe = catalog.recipes[dependency]
            missing = sorted(set(dependency_recipe.sources) - set(parsed))
            if missing:
                raise FetchError(
                    f"{recipe_id}: exclusion dependency {dependency} requires fresh sources: "
                    + ", ".join(missing)
                )
            pending.extend(dependency_recipe.dependencies)

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
        _check_unmatched_source_changes(
            catalog, catalog.recipes[recipe_id], composition, previous_sources
        )
        built_rules[recipe_id] = rules
        compositions[recipe_id] = composition

    conflict_report, conflict_review = _resolve_fakeip_conflicts(catalog, built_rules)
    review_reasons.extend(conflict_review)

    rendered_by_ruleset: dict[str, dict[str, RenderedFile]] = {}
    manifests: dict[str, dict[str, Any]] = {}
    compatibility: dict[str, dict[str, Any]] = {
        key: value for key, value in previous_compatibility.items() if key not in selected
    }
    files: dict[str, bytes] = {}
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
        files.update({f"dist/{recipe_id}/{name}": data for name, data in expected.items()})
        rendered_by_ruleset[recipe_id] = rendered
        manifests[recipe_id] = manifest
        compatibility[recipe_id] = compatible

    active_sources = {source for recipe in catalog.recipes.values() for source in recipe.sources}
    lock_entries.extend(
        value for key, value in previous_sources.items() if key in active_sources - source_ids
    )
    lock_entries.sort(key=lambda item: str(item["id"]))
    if {entry["id"] for entry in lock_entries} != active_sources:
        raise BuildError("partial build has no complete source baseline; run a full sync")
    for entry in lock_entries:
        source_id = str(entry["id"])
        item = fetch_result.downloaded.get(source_id)
        if item is not None:
            data = item.data
        else:
            data, _ = inputs.read(source_id)
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise FetchError(f"{source_id}: preserved input does not match source lock")
        inputs.capture(source_id, data, entry)
    lock = {"version": 1, "sources": lock_entries}
    if selected != set(catalog.recipes):
        rejected.extend(
            entry
            for entry in previous_report["rejected_lines"]
            if entry["source_id"] not in source_ids
        )
        stale_report.extend(
            entry for entry in previous_report["stale_sources"] if entry["id"] not in source_ids
        )
        if not {"fake-ip-force", "fake-ip-bypass"} & selected:
            conflict_report = previous_report["fake_ip_conflicts"]
    report = {
        "version": 1,
        "selected_rulesets": sorted(catalog.recipes),
        "binary_outputs": not skip_binary
        and (selected == set(catalog.recipes) or previous_report.get("binary_outputs", True)),
        "review_required": bool(review_reasons),
        "review_reasons": sorted(set(review_reasons)),
        "fake_ip_conflicts": conflict_report,
        "rejected_lines": sorted(rejected, key=lambda entry: json.dumps(entry, sort_keys=True)),
        "stale_sources": sorted(stale_report, key=lambda entry: str(entry["id"])),
    }
    files.update(inputs.files())
    files["generated/sources.lock.json"] = json_bytes(lock)
    files["generated/reports/build.json"] = json_bytes(report)
    files["generated/reports/compatibility.json"] = json_bytes(compatibility)
    directories = [f"dist/{recipe_id}" for recipe_id in selected]
    if selected == set(catalog.recipes):
        directories = ["dist"]
    directories.append(inputs.directory)
    removed = obsolete_files(root, files, directories)
    differences = changed_files(root, files, removed)
    changed = bool(differences)
    if not check and not review_reasons:
        publish_files(root, files, removed)
    return BuildResult(
        rules={key: value for key, value in built_rules.items() if key in selected},
        rendered=rendered_by_ruleset,
        manifests=manifests,
        compatibility=compatibility,
        lock=lock,
        report=report,
        changed=changed,
        changed_paths=tuple(sorted(differences)),
        review_required=bool(review_reasons),
    )


def build(
    root: Path,
    *,
    offline: bool = False,
    locked: bool = False,
    check: bool = False,
    skip_binary: bool = False,
    selected_rulesets: set[str] | None = None,
    workers: int = 8,
) -> BuildResult:
    root = root.resolve()
    attempt_path = root / ".work/reports/sync-attempt.json"
    write_json_atomic(attempt_path, {"status": "running"})
    try:
        result = _build(
            root,
            offline=offline,
            locked=locked,
            check=check,
            skip_binary=skip_binary,
            selected_rulesets=selected_rulesets,
            workers=workers,
        )
    except Exception as exc:
        write_json_atomic(attempt_path, {"status": "failed", "error": str(exc)})
        raise
    status = "review" if result.review_required else "changed" if check and result.changed else "ok"
    write_json_atomic(
        attempt_path,
        {
            "status": status,
            "rulesets": sorted(result.rules),
            "binary_outputs": not skip_binary,
            "locked_check": locked and check,
            "changed_paths": list(result.changed_paths),
            "publication_sha256": publication_digest(root) if status == "ok" else None,
            "report": result.report,
        },
    )
    return result
