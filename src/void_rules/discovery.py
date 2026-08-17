from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import yaml

from .artifacts import deterministic_gzip
from .catalog import Catalog, load_catalog
from .errors import CatalogError, FetchError
from .fetch import RestrictedRedirectHandler, write_bytes_atomic, write_json_atomic

JSON_PATH = re.compile(r"^\$\.([A-Za-z0-9_-]+)\[\*\]\.([A-Za-z0-9_-]+)$")


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    document: dict[str, Any]
    changed: bool


def stable_candidate_id(discoverer_id: str, kind: str, identity: str) -> str:
    canonical = json.dumps(
        [discoverer_id, kind, identity],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return "candidate-" + hashlib.sha256(canonical).hexdigest()[:24]


def _read_limited(response: Any, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(f"discovery response exceeds {max_bytes} bytes")
    return b"".join(chunks)


def _fetch_json(
    root: Path,
    discoverer: dict[str, Any],
    url: str,
    *,
    offline: bool,
) -> tuple[Any, str]:
    discoverer_id = str(discoverer["id"])
    cache_key = hashlib.sha256(url.encode()).hexdigest()[:16]
    cache_path = root / ".work" / "discovery" / f"{discoverer_id}-{cache_key}.json"
    if offline:
        if not cache_path.is_file():
            raise FetchError(f"{discoverer_id}: offline discovery cache is missing")
        data = cache_path.read_bytes()
    else:
        allowed_hosts = frozenset(str(item).lower() for item in discoverer["allowed_hosts"])
        hostname = (urlparse(url).hostname or "").lower()
        if urlparse(url).scheme != "https" or hostname not in allowed_hosts:
            raise FetchError(f"{discoverer_id}: unapproved discovery URL: {url}")
        headers = {
            "Accept": "application/vnd.github+json,application/json;q=0.9",
            "User-Agent": (
                "void-rules-discovery/0.1 (+https://github.com/VoidInTheShell/void-rules)"
            ),
        }
        if hostname == "api.github.com":
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        opener = urllib.request.build_opener(RestrictedRedirectHandler(allowed_hosts))
        errors: list[str] = []
        data = b""
        for attempt in range(1, 4):
            try:
                request = urllib.request.Request(url, headers=headers)
                with opener.open(request, timeout=60) as response:
                    final_url = response.geturl()
                    final_host = (urlparse(final_url).hostname or "").lower()
                    if final_host not in allowed_hosts:
                        raise FetchError(
                            f"{discoverer_id}: final host {final_host!r} is not approved"
                        )
                    content_type = str(response.headers.get("Content-Type", ""))
                    data = _read_limited(response, 50 * 1024 * 1024)
                prefix = data[:512].lstrip().lower()
                if "html" in content_type.lower() or prefix.startswith(
                    (b"<!doctype", b"<html", b"<head", b"<body")
                ):
                    raise FetchError(f"{discoverer_id}: discovery endpoint returned HTML")
                write_bytes_atomic(cache_path, data)
                break
            except (FetchError, OSError, urllib.error.URLError) as exc:
                errors.append(f"attempt {attempt}: {exc}")
                if attempt < 3:
                    time.sleep(0.5 * attempt)
        else:
            raise FetchError(f"{discoverer_id}: discovery request failed: " + " | ".join(errors))
    digest = hashlib.sha256(data).hexdigest()
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchError(f"{discoverer_id}: invalid JSON discovery response: {exc}") from exc
    return document, digest


def _extract_json_path(document: Any, path: str) -> list[Any]:
    match = JSON_PATH.fullmatch(path)
    if not match:
        raise CatalogError(f"unsupported discovery JSON path: {path}")
    collection_key, value_key = match.groups()
    if not isinstance(document, dict):
        return []
    collection = document.get(collection_key)
    if not isinstance(collection, list):
        return []
    values: list[Any] = []
    for item in collection:
        if not isinstance(item, dict):
            continue
        value = item.get(value_key)
        if isinstance(value, (str, int, float, bool)) and str(value):
            values.append(value)
    return values


def _github_tree_candidates(
    root: Path,
    catalog: Catalog,
    discoverer: dict[str, Any],
    *,
    offline: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    repository = str(discoverer["repository"])
    ref = str(discoverer["ref"])
    responses: dict[str, str] = {}

    def fetch_tree(tree_ref: str, *, recursive: bool) -> dict[str, Any]:
        suffix = "?recursive=1" if recursive else ""
        endpoint = (
            f"https://api.github.com/repos/{repository}/git/trees/"
            f"{quote(tree_ref, safe='')}{suffix}"
        )
        document, response_digest = _fetch_json(
            root,
            discoverer,
            endpoint,
            offline=offline,
        )
        if not isinstance(document, dict) or not isinstance(document.get("tree"), list):
            raise FetchError(f"{discoverer['id']}: GitHub tree response has no tree array")
        responses[endpoint] = response_digest
        return document

    def walk_tree(tree_sha: str, prefix: str) -> list[dict[str, Any]]:
        pending = [(tree_sha, prefix)]
        files: list[dict[str, Any]] = []
        while pending:
            current_sha, current_prefix = pending.pop()
            document = fetch_tree(current_sha, recursive=False)
            for entry in document["tree"]:
                if not isinstance(entry, dict):
                    continue
                entry_path = str(entry.get("path", ""))
                full_path = f"{current_prefix}/{entry_path}" if current_prefix else entry_path
                if entry.get("type") == "blob":
                    files.append({**entry, "path": full_path})
                elif entry.get("type") == "tree" and entry.get("sha"):
                    pending.append((str(entry["sha"]), full_path))
        return files

    root_document = fetch_tree(ref, recursive=False)
    tree_items: list[dict[str, Any]] = []
    configured_roots = [str(item).strip("/") for item in discoverer.get("roots", [])]
    roots = configured_roots or [""]
    for scan_root in roots:
        if not scan_root:
            recursive_document = fetch_tree(ref, recursive=True)
            if recursive_document.get("truncated") is True:
                tree_sha = str(root_document.get("sha", ""))
                if not tree_sha:
                    raise FetchError(f"{discoverer['id']}: root tree has no SHA")
                tree_items.extend(walk_tree(tree_sha, ""))
            else:
                tree_items.extend(recursive_document["tree"])
            continue

        current_document = root_document
        subtree_sha = ""
        traversed: list[str] = []
        for segment in scan_root.split("/"):
            matches = [
                item
                for item in current_document["tree"]
                if isinstance(item, dict)
                and item.get("type") == "tree"
                and item.get("path") == segment
            ]
            if len(matches) != 1 or not matches[0].get("sha"):
                raise FetchError(f"{discoverer['id']}: discovery root not found: {scan_root}")
            subtree_sha = str(matches[0]["sha"])
            traversed.append(segment)
            if len(traversed) < len(scan_root.split("/")):
                current_document = fetch_tree(subtree_sha, recursive=False)

        subtree_document = fetch_tree(subtree_sha, recursive=True)
        if subtree_document.get("truncated") is True:
            tree_items.extend(walk_tree(subtree_sha, scan_root))
        else:
            for entry in subtree_document["tree"]:
                if isinstance(entry, dict):
                    relative = str(entry.get("path", ""))
                    tree_items.append({**entry, "path": f"{scan_root}/{relative}"})

    try:
        include = re.compile(str(discoverer["include_regex"]))
    except re.error as exc:
        raise CatalogError(f"{discoverer['id']}: invalid include_regex: {exc}") from exc

    registered_urls: dict[str, list[str]] = {}
    for source in catalog.sources.values():
        registered_urls.setdefault(source.url, []).append(source.id)

    candidates: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for item in tree_items:
        if not isinstance(item, dict) or item.get("type") != "blob":
            continue
        path = str(item.get("path", ""))
        if not include.search(path):
            continue
        if path in seen_paths:
            continue
        seen_paths.add(path)
        raw_url = (
            f"https://raw.githubusercontent.com/{repository}/"
            f"{quote(ref, safe='')}/{quote(path, safe='/')}"
        )
        identity = f"{repository}@{ref}:{path}"
        candidate: dict[str, Any] = {
            "id": stable_candidate_id(str(discoverer["id"]), "github-file", identity),
            "discoverer": str(discoverer["id"]),
            "kind": "github-file",
            "identity": identity,
            "path": path,
            "url": raw_url,
            "evidence": {
                "blob_sha": str(item.get("sha", "")),
                "size": int(item.get("size", 0)),
            },
            "registered_source_ids": sorted(registered_urls.get(raw_url, [])),
        }
        candidates.append(candidate)

    matched_files = len(candidates)
    if bool(discoverer.get("group_by_stem", False)):
        grouped: dict[str, dict[str, Any]] = {}
        for candidate in candidates:
            path = str(candidate["path"])
            stem, separator, extension = path.rpartition(".")
            family_path = stem if separator else path
            identity = f"{repository}@{ref}:{family_path}"
            candidate_id = stable_candidate_id(
                str(discoverer["id"]),
                "github-file-family",
                identity,
            )
            family = grouped.get(candidate_id)
            if family is None:
                family = {
                    "id": candidate_id,
                    "discoverer": str(discoverer["id"]),
                    "kind": "github-file-family",
                    "identity": identity,
                    "path": family_path,
                    "assets": [],
                    "evidence": {},
                    "registered_source_ids": [],
                }
                grouped[candidate_id] = family
            family["assets"].append(
                {
                    "format": extension.lower(),
                    "path": path,
                    "url": candidate["url"],
                }
            )
            registered = set(family["registered_source_ids"])
            registered.update(candidate["registered_source_ids"])
            family["registered_source_ids"] = sorted(registered)
        candidates = list(grouped.values())
        for family in candidates:
            family["assets"].sort(key=lambda item: str(item["path"]))

    response_fingerprint = hashlib.sha256(
        json.dumps(responses, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return candidates, {
        "discoverer": str(discoverer["id"]),
        "endpoints": len(responses),
        "response_set_sha256": response_fingerprint,
        "matched_files": matched_files,
        "candidates": len(candidates),
    }


def _json_api_candidates(
    root: Path,
    discoverer: dict[str, Any],
    *,
    offline: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    url = str(discoverer["url"])
    document, digest = _fetch_json(root, discoverer, url, offline=offline)
    by_id: dict[str, dict[str, Any]] = {}
    for path in discoverer["json_paths"]:
        for value in _extract_json_path(document, str(path)):
            canonical_value = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            candidate_id = stable_candidate_id(
                str(discoverer["id"]),
                "json-value",
                canonical_value,
            )
            existing = by_id.get(candidate_id)
            if existing is None:
                by_id[candidate_id] = {
                    "id": candidate_id,
                    "discoverer": str(discoverer["id"]),
                    "kind": "json-value",
                    "identity": canonical_value,
                    "value": value,
                    "url": url,
                    "evidence": {
                        "json_paths": [str(path)],
                    },
                    "registered_source_ids": [],
                }
            else:
                paths = existing["evidence"]["json_paths"]
                if str(path) not in paths:
                    paths.append(str(path))
                    paths.sort()
    candidates = sorted(by_id.values(), key=lambda item: str(item["id"]))
    return candidates, {
        "discoverer": str(discoverer["id"]),
        "endpoint": url,
        "response_sha256": digest,
        "matched": len(candidates),
    }


def _load_rejections(path: Path) -> dict[str, str]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogError(f"invalid discovery rejection store {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise CatalogError(f"invalid discovery rejection store: {path}")
    rejected = document.get("rejected", [])
    if not isinstance(rejected, list):
        raise CatalogError(f"discovery rejected must be a list: {path}")
    result: dict[str, str] = {}
    for index, item in enumerate(rejected, start=1):
        if not isinstance(item, dict) or not item.get("id") or not item.get("reason"):
            raise CatalogError(f"invalid discovery rejection #{index}: {path}")
        candidate_id = str(item["id"])
        if candidate_id in result:
            raise CatalogError(f"duplicate discovery rejection: {candidate_id}")
        result[candidate_id] = str(item["reason"])
    return result


def discover(root: Path, *, offline: bool = False, check: bool = False) -> DiscoveryResult:
    root = root.resolve()
    catalog = load_catalog(root)
    config = catalog.discovery
    rejection_path = root / str(config["rejection_store"])
    rejections = _load_rejections(rejection_path)
    candidates: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []

    for discoverer in sorted(config["discoverers"], key=lambda item: str(item["id"])):
        if discoverer["type"] == "github-tree":
            found, source = _github_tree_candidates(
                root,
                catalog,
                discoverer,
                offline=offline,
            )
        elif discoverer["type"] == "json-api":
            found, source = _json_api_candidates(root, discoverer, offline=offline)
        else:
            raise CatalogError(f"unsupported discoverer type: {discoverer['type']}")
        maximum = int(discoverer.get("max_candidates", 20000))
        if len(found) > maximum:
            raise FetchError(f"{discoverer['id']}: {len(found)} candidates exceeds limit {maximum}")
        promotion = str(discoverer["promotion"])
        for candidate in found:
            candidate["promotion"] = promotion
            if candidate["registered_source_ids"]:
                candidate["status"] = "registered"
            elif candidate["id"] in rejections:
                candidate["status"] = "rejected"
                candidate["rejection_reason"] = rejections[candidate["id"]]
            elif promotion == "candidate-only":
                candidate["status"] = "candidate"
            else:
                candidate["status"] = "review"
                candidate["review_reason"] = (
                    "policy promotion requires target ruleset and parser evidence"
                )
        candidates.extend(found)
        sources.append(source)

    candidates.sort(key=lambda item: (str(item["discoverer"]), str(item["id"])))
    seen_ids: set[str] = set()
    for candidate in candidates:
        candidate_id = str(candidate["id"])
        if candidate_id in seen_ids:
            raise CatalogError(f"duplicate discovery candidate ID: {candidate_id}")
        seen_ids.add(candidate_id)
    counts: dict[str, int] = {}
    for candidate in candidates:
        status = str(candidate["status"])
        counts[status] = counts.get(status, 0) + 1
    stale_rejections = sorted(set(rejections) - seen_ids)
    policy_path = root / "catalog" / "discovery.yaml"
    result_document = {
        "version": 1,
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "counts": dict(sorted(counts.items())),
        "sources": sources,
        "stale_rejections": stale_rejections,
        "candidates": candidates,
    }
    candidate_path = root / str(config["candidate_store"])
    candidate_json = (
        json.dumps(result_document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    candidate_data = (
        deterministic_gzip(candidate_json, root)
        if candidate_path.suffix == ".gz"
        else candidate_json
    )
    candidate_digest = hashlib.sha256(candidate_data).hexdigest()
    summary_document = {
        "version": 1,
        "policy_sha256": result_document["policy_sha256"],
        "counts": result_document["counts"],
        "sources": result_document["sources"],
        "stale_rejections": stale_rejections,
        "candidate_store": {
            "path": str(config["candidate_store"]).replace("\\", "/"),
            "sha256": candidate_digest,
            "size": len(candidate_data),
            "total": len(candidates),
        },
    }
    summary_path = root / str(config["summary_store"])
    summary_data = (
        json.dumps(summary_document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    changed = (
        not candidate_path.is_file()
        or candidate_path.read_bytes() != candidate_data
        or not summary_path.is_file()
        or summary_path.read_bytes() != summary_data
    )
    if not check:
        write_bytes_atomic(candidate_path, candidate_data)
        write_json_atomic(summary_path, summary_document)
    return DiscoveryResult(document=result_document, changed=changed)
