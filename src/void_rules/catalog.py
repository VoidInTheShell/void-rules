from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from .errors import CatalogError
from .model import Action


@dataclass(frozen=True, slots=True)
class Limits:
    min_bytes: int = 0
    max_bytes: int = 100 * 1024 * 1024
    min_rules: int = 0
    max_rules: int = 5_000_000
    max_growth_ratio: float = 5.0
    max_shrink_ratio: float = 0.2

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Limits:
        return cls(
            min_bytes=int(data.get("min_bytes", 0)),
            max_bytes=int(data.get("max_bytes", 100 * 1024 * 1024)),
            min_rules=int(data.get("min_rules", 0)),
            max_rules=int(data.get("max_rules", 5_000_000)),
            max_growth_ratio=float(data.get("max_growth_ratio", 5.0)),
            max_shrink_ratio=float(data.get("max_shrink_ratio", 0.2)),
        )


@dataclass(frozen=True, slots=True)
class SourceSpec:
    id: str
    name: str
    url: str
    fallback_urls: tuple[str, ...]
    format: str
    behavior: str | None
    polarity: Action
    whole_source_allowlist: bool
    select_tags: tuple[str, ...]
    companion_source: str | None
    license: str
    homepage: str
    allowed_hosts: frozenset[str]
    strict: bool
    enabled: bool
    headers: tuple[tuple[str, str], ...]
    limits: Limits
    notes: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceSpec:
        polarity = Action(str(data.get("polarity", "match")))
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            url=str(data["url"]),
            fallback_urls=tuple(str(item) for item in data.get("fallback_urls", [])),
            format=str(data["format"]),
            behavior=str(data["behavior"]) if data.get("behavior") else None,
            polarity=polarity,
            whole_source_allowlist=bool(data.get("whole_source_allowlist", False)),
            select_tags=tuple(str(item) for item in data.get("select_tags", [])),
            companion_source=(
                str(data["companion_source"]) if data.get("companion_source") else None
            ),
            license=str(data["license"]),
            homepage=str(data["homepage"]),
            allowed_hosts=frozenset(str(item).lower() for item in data["allowed_hosts"]),
            strict=bool(data["strict"]),
            enabled=bool(data.get("enabled", True)),
            headers=tuple(
                sorted((str(key), str(value)) for key, value in data.get("headers", {}).items())
            ),
            limits=Limits.from_dict(data["limits"]),
            notes=str(data.get("notes", "")),
        )


@dataclass(frozen=True, slots=True)
class Recipe:
    id: str
    description: str
    action: Action
    sources: tuple[str, ...]
    rulesets: tuple[str, ...]
    include: Path
    exclude: Path
    assertions: Path
    conflict_resolutions: Path | None
    outputs: tuple[str, ...]
    limits: Limits
    notes: str

    @classmethod
    def from_dict(cls, data: dict[str, Any], root: Path) -> Recipe:
        return cls(
            id=str(data["id"]),
            description=str(data["description"]),
            action=Action(str(data["action"])),
            sources=tuple(str(item) for item in data["sources"]),
            rulesets=tuple(str(item) for item in data["rulesets"]),
            include=root / str(data["include"]),
            exclude=root / str(data["exclude"]),
            assertions=root / str(data["assertions"]),
            conflict_resolutions=(
                root / str(data["conflict_resolutions"])
                if data.get("conflict_resolutions")
                else None
            ),
            outputs=tuple(str(item) for item in data["outputs"]),
            limits=Limits.from_dict(data["limits"]),
            notes=str(data.get("notes", "")),
        )


@dataclass(frozen=True, slots=True)
class Catalog:
    root: Path
    sources: dict[str, SourceSpec]
    recipes: dict[str, Recipe]
    discovery: dict[str, Any]

    @property
    def recipe_order(self) -> tuple[str, ...]:
        ordered: list[str] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(recipe_id: str) -> None:
            if recipe_id in visiting:
                raise CatalogError(f"recipe dependency cycle at {recipe_id}")
            if recipe_id in visited:
                return
            visiting.add(recipe_id)
            for dependency in self.recipes[recipe_id].rulesets:
                visit(dependency)
            visiting.remove(recipe_id)
            visited.add(recipe_id)
            ordered.append(recipe_id)

        for recipe_id in sorted(self.recipes):
            visit(recipe_id)
        return tuple(ordered)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CatalogError(f"missing catalog file: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CatalogError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CatalogError(f"expected mapping in {path}")
    return data


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"invalid JSON schema {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CatalogError(f"schema must be an object: {path}")
    return data


def _validate(instance: dict[str, Any], schema: dict[str, Any], label: Path) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path))
    if errors:
        details = []
        for error in errors[:20]:
            location = ".".join(str(item) for item in error.absolute_path) or "<root>"
            details.append(f"{location}: {error.message}")
        raise CatalogError(f"schema validation failed for {label}: " + "; ".join(details))


def _ensure_inside(root: Path, path: Path) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise CatalogError(f"path escapes repository: {path}") from exc


def load_catalog(root: Path) -> Catalog:
    root = root.resolve()
    sources_document = _load_yaml(root / "catalog" / "sources.yaml")
    source_schema = _load_schema(root / "schemas" / "sources.schema.json")
    recipe_schema = _load_schema(root / "schemas" / "recipe.schema.json")
    overlay_schema = _load_schema(root / "schemas" / "overlay.schema.json")
    discovery_schema = _load_schema(root / "schemas" / "discovery.schema.json")
    _validate(sources_document, source_schema, root / "catalog" / "sources.yaml")
    discovery_path = root / "catalog" / "discovery.yaml"
    discovery_document = _load_yaml(discovery_path)
    _validate(discovery_document, discovery_schema, discovery_path)

    candidate_store = root / str(discovery_document["candidate_store"])
    summary_store = root / str(discovery_document["summary_store"])
    rejection_store = root / str(discovery_document["rejection_store"])
    _ensure_inside(root, candidate_store)
    _ensure_inside(root, summary_store)
    _ensure_inside(root, rejection_store)
    if not rejection_store.is_file():
        raise CatalogError(f"missing discovery rejection store: {rejection_store}")
    discoverer_ids: set[str] = set()
    for discoverer in discovery_document["discoverers"]:
        discoverer_id = str(discoverer["id"])
        if discoverer_id in discoverer_ids:
            raise CatalogError(f"duplicate discoverer id: {discoverer_id}")
        discoverer_ids.add(discoverer_id)
        discoverer_type = str(discoverer["type"])
        required = (
            ("repository", "ref", "include_regex")
            if discoverer_type == "github-tree"
            else ("url", "json_paths")
        )
        missing = [key for key in required if not discoverer.get(key)]
        if missing:
            raise CatalogError(f"{discoverer_id}: missing discovery fields: {', '.join(missing)}")
        allowed_hosts = {str(item).lower() for item in discoverer["allowed_hosts"]}
        if discoverer_type == "github-tree" and "api.github.com" not in allowed_hosts:
            raise CatalogError(f"{discoverer_id}: github-tree must allow api.github.com")
        if discoverer_type == "json-api":
            hostname = (urlparse(str(discoverer["url"])).hostname or "").lower()
            if hostname not in allowed_hosts:
                raise CatalogError(f"{discoverer_id}: URL host {hostname!r} is not allowed")

    sources: dict[str, SourceSpec] = {}
    for source_data in sources_document["sources"]:
        source = SourceSpec.from_dict(source_data)
        if source.id in sources:
            raise CatalogError(f"duplicate source id: {source.id}")
        for url in (source.url, *source.fallback_urls):
            hostname = (urlparse(url).hostname or "").lower()
            if hostname not in source.allowed_hosts:
                raise CatalogError(f"{source.id}: URL host {hostname!r} is not allowed")
        sources[source.id] = source
    for source in sources.values():
        if source.companion_source and source.companion_source not in sources:
            raise CatalogError(f"{source.id}: unknown companion source {source.companion_source!r}")

    recipes: dict[str, Recipe] = {}
    for recipe_path in sorted((root / "recipes").glob("*.yaml")):
        document = _load_yaml(recipe_path)
        _validate(document, recipe_schema, recipe_path)
        recipe = Recipe.from_dict(document, root)
        if recipe.id != recipe_path.stem:
            raise CatalogError(f"recipe id/path mismatch: {recipe.id} vs {recipe_path.name}")
        if recipe.id in recipes:
            raise CatalogError(f"duplicate recipe id: {recipe.id}")
        for source_id in recipe.sources:
            if source_id not in sources:
                raise CatalogError(f"{recipe.id}: unknown source {source_id}")
            if not sources[source_id].enabled:
                raise CatalogError(f"{recipe.id}: source {source_id} is disabled")
        for overlay_path in (recipe.include, recipe.exclude, recipe.assertions):
            _ensure_inside(root, overlay_path)
            overlay = _load_yaml(overlay_path)
            _validate(overlay, overlay_schema, overlay_path)
            if overlay.get("ruleset") != recipe.id:
                raise CatalogError(f"overlay {overlay_path} belongs to another ruleset")
        if recipe.conflict_resolutions:
            _ensure_inside(root, recipe.conflict_resolutions)
            overlay = _load_yaml(recipe.conflict_resolutions)
            _validate(overlay, overlay_schema, recipe.conflict_resolutions)
        recipes[recipe.id] = recipe

    for recipe in recipes.values():
        for dependency in recipe.rulesets:
            if dependency not in recipes:
                raise CatalogError(f"{recipe.id}: unknown recipe dependency {dependency}")

    catalog = Catalog(
        root=root,
        sources=sources,
        recipes=recipes,
        discovery=discovery_document,
    )
    _ = catalog.recipe_order
    return catalog


def load_overlay(path: Path) -> dict[str, Any]:
    return _load_yaml(path)
