from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

from .catalog import SourceSpec
from .errors import FetchError


@dataclass(frozen=True, slots=True)
class DownloadedSource:
    spec: SourceSpec
    data: bytes
    sha256: str
    final_url: str
    etag: str
    last_modified: str
    from_cache: bool


@dataclass(frozen=True, slots=True)
class SourceFetchResult:
    downloaded: dict[str, DownloadedSource]
    failures: dict[str, str]


STALE_SOURCE_REASON = "upstream unavailable; preserved from published rules"


def _stable_public_url(value: str) -> str:
    """Remove ephemeral credentials/query data before metadata is persisted."""

    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


class RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        parsed = urlparse(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in self.allowed_hosts:
            raise FetchError(f"redirect to unapproved URL: {_stable_public_url(newurl)}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def write_bytes_atomic(path: Path, data: bytes) -> None:
    _atomic_write(path, data)


def _guard_payload(spec: SourceSpec, data: bytes, content_type: str) -> None:
    if len(data) < spec.limits.min_bytes:
        raise FetchError(f"{spec.id}: payload is too small ({len(data)} < {spec.limits.min_bytes})")
    if len(data) > spec.limits.max_bytes:
        raise FetchError(f"{spec.id}: payload is too large ({len(data)} > {spec.limits.max_bytes})")
    prefix = data[:512].lstrip().lower()
    if prefix.startswith((b"<!doctype", b"<html", b"<head", b"<body")):
        raise FetchError(f"{spec.id}: upstream returned an HTML/error document")
    if "text/html" in content_type.lower():
        raise FetchError(f"{spec.id}: upstream content type is HTML")
    if spec.format not in {"xray-json"} and prefix.startswith((b'{"message"', b'{"error"')):
        raise FetchError(f"{spec.id}: upstream returned an API error object")


def _read_response(response: Any, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(f"download exceeds configured maximum of {max_bytes} bytes")
    return b"".join(chunks)


def fetch_source(spec: SourceSpec, work_dir: Path, *, offline: bool = False) -> DownloadedSource:
    cache_path = work_dir / "downloads" / f"{spec.id}.blob"
    metadata_path = work_dir / "downloads" / f"{spec.id}.json"
    if offline:
        if not cache_path.is_file():
            raise FetchError(f"{spec.id}: offline cache is missing")
        data = cache_path.read_bytes()
        metadata = (
            json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
        )
        _guard_payload(spec, data, str(metadata.get("content_type", "")))
        return DownloadedSource(
            spec=spec,
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
            final_url=_stable_public_url(str(metadata.get("final_url", spec.url))),
            etag=str(metadata.get("etag", "")),
            last_modified=str(metadata.get("last_modified", "")),
            from_cache=True,
        )

    opener = urllib.request.build_opener(RestrictedRedirectHandler(spec.allowed_hosts))
    headers = {
        "Accept": (
            "application/octet-stream,text/plain,application/yaml,application/json;q=0.9,*/*;q=0.1"
        ),
        "User-Agent": "void-rules-sync/0.1 (+https://github.com/VoidInTheShell/void-rules)",
        **dict(spec.headers),
    }
    errors: list[str] = []
    for url in (spec.url, *spec.fallback_urls):
        for attempt in range(1, 4):
            try:
                request = urllib.request.Request(url, headers=headers)
                with opener.open(request, timeout=60) as response:
                    response_url = response.geturl()
                    final_host = (urlparse(response_url).hostname or "").lower()
                    if final_host not in spec.allowed_hosts:
                        raise FetchError(f"{spec.id}: final host {final_host!r} is not approved")
                    data = _read_response(response, spec.limits.max_bytes)
                    content_type = str(response.headers.get("Content-Type", ""))
                    etag = str(response.headers.get("ETag", ""))
                    last_modified = str(response.headers.get("Last-Modified", ""))
                    final_url = _stable_public_url(response_url)
                _guard_payload(spec, data, content_type)
                sha256 = hashlib.sha256(data).hexdigest()
                _atomic_write(cache_path, data)
                metadata = {
                    "source_id": spec.id,
                    "final_url": final_url,
                    "content_type": content_type,
                    "etag": etag,
                    "last_modified": last_modified,
                    "sha256": sha256,
                }
                _atomic_write(
                    metadata_path,
                    (
                        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
                    ).encode(),
                )
                return DownloadedSource(
                    spec=spec,
                    data=data,
                    sha256=sha256,
                    final_url=final_url,
                    etag=etag,
                    last_modified=last_modified,
                    from_cache=False,
                )
            except (FetchError, OSError, urllib.error.URLError) as exc:
                errors.append(f"{_stable_public_url(url)} attempt {attempt}: {exc}")
                if attempt < 3:
                    time.sleep(0.5 * attempt)
    raise FetchError(f"{spec.id}: all download attempts failed: " + " | ".join(errors))


def fetch_sources(
    specs: list[SourceSpec],
    work_dir: Path,
    *,
    offline: bool = False,
    workers: int = 8,
) -> SourceFetchResult:
    downloaded: dict[str, DownloadedSource] = {}
    failures: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(specs) or 1))) as executor:
        futures = {
            executor.submit(fetch_source, spec, work_dir, offline=offline): spec.id
            for spec in specs
        }
        for future in as_completed(futures):
            source_id = futures[future]
            try:
                downloaded[source_id] = future.result()
            except Exception as exc:
                failures[source_id] = str(exc)
    return SourceFetchResult(downloaded=downloaded, failures=failures)


def load_previous_lock(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "sources": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FetchError(f"invalid existing source lock: {exc}") from exc
    if not isinstance(value, dict):
        raise FetchError("existing source lock must be a JSON object")
    return value


def build_lock_entry(
    downloaded: DownloadedSource,
    *,
    parsed_rules: int,
    rejected_rules: int,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    changed_at = now
    if previous and previous.get("sha256") == downloaded.sha256:
        changed_at = str(previous.get("changed_at", now))
    return {
        "id": downloaded.spec.id,
        "url": downloaded.spec.url,
        "final_url": _stable_public_url(downloaded.final_url),
        "format": downloaded.spec.format,
        "behavior": downloaded.spec.behavior,
        "license": downloaded.spec.license,
        "size": len(downloaded.data),
        "sha256": downloaded.sha256,
        "etag": downloaded.etag,
        "last_modified": downloaded.last_modified,
        "parsed_rules": parsed_rules,
        "rejected_rules": rejected_rules,
        "changed_at": changed_at,
    }


def build_stale_lock_entry(
    spec: SourceSpec,
    *,
    previous: dict[str, Any],
    preserved_rules: int,
    preserved_provenance: int,
    stale_rulesets: list[str],
) -> dict[str, Any]:
    source_sha = str(previous.get("sha256", ""))
    if previous.get("id") != spec.id or len(source_sha) != 64:
        raise FetchError(f"{spec.id}: previous source lock is missing a valid SHA-256")
    entry = dict(previous)
    entry.update(
        {
            "id": spec.id,
            "url": spec.url,
            "final_url": _stable_public_url(str(previous.get("final_url", spec.url))),
            "format": spec.format,
            "behavior": spec.behavior,
            "license": spec.license,
            "sync_status": "stale",
            "stale_reason": STALE_SOURCE_REASON,
            "preserved_rules": preserved_rules,
            "preserved_provenance": preserved_provenance,
            "stale_rulesets": sorted(stale_rulesets),
        }
    )
    return entry


def write_json_atomic(path: Path, value: Any) -> None:
    payload = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    _atomic_write(path, payload)
