from __future__ import annotations

import io
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest

from void_rules.catalog import Limits, SourceSpec
from void_rules.errors import FetchError
from void_rules.fetch import (
    DownloadedSource,
    RestrictedRedirectHandler,
    _guard_payload,
    _read_response,
    _stable_public_url,
    build_lock_entry,
    build_stale_lock_entry,
    fetch_sources,
)
from void_rules.model import Action


def source_spec(source_format: str = "plain-domain") -> SourceSpec:
    return SourceSpec(
        id="fixture",
        name="fixture",
        url="https://example.com/rules",
        fallback_urls=(),
        format=source_format,
        behavior=None,
        polarity=Action.MATCH,
        whole_source_allowlist=False,
        select_tags=(),
        companion_source=None,
        license="MIT",
        homepage="https://example.com",
        allowed_hosts=frozenset({"example.com"}),
        strict=True,
        enabled=True,
        headers=(),
        limits=Limits(min_bytes=1, max_bytes=32, min_rules=0, max_rules=10),
        notes="",
    )


@pytest.mark.parametrize(
    "url",
    ["http://example.com/rules", "https://example.com.evil.invalid/rules"],
)
def test_redirect_handler_rejects_scheme_and_host_escape(url: str) -> None:
    handler = RestrictedRedirectHandler(frozenset({"example.com"}))

    with pytest.raises(FetchError, match="unapproved"):
        handler.redirect_request(
            urllib.request.Request("https://example.com/start"),
            None,
            302,
            "Found",
            {},
            url,
        )


def test_stable_public_url_strips_ephemeral_credentials_and_fragment() -> None:
    value = _stable_public_url(
        "https://user:secret@release-assets.githubusercontent.com:443/path/file?sig=secret#part"
    )

    assert value == "https://release-assets.githubusercontent.com:443/path/file"


def test_payload_guard_rejects_html_and_api_errors() -> None:
    spec = source_spec()

    with pytest.raises(FetchError, match="HTML"):
        _guard_payload(spec, b"<html>error</html>", "text/html")
    with pytest.raises(FetchError, match="API error"):
        _guard_payload(spec, b'{"error":"rate limited"}', "application/json")


def test_response_reader_enforces_size_before_unbounded_read() -> None:
    with pytest.raises(FetchError, match="exceeds"):
        _read_response(io.BytesIO(b"123456"), 5)


def test_fetch_sources_returns_other_downloads_when_one_source_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    healthy = source_spec()
    failed = replace(healthy, id="failed")

    def fake_fetch(spec: SourceSpec, work_dir: Path, *, offline: bool) -> DownloadedSource:
        del work_dir, offline
        if spec.id == "failed":
            raise FetchError("upstream is gone")
        return DownloadedSource(
            spec=spec,
            data=b"ok",
            sha256="a" * 64,
            final_url=spec.url,
            etag="",
            last_modified="",
            from_cache=False,
        )

    monkeypatch.setattr("void_rules.fetch.fetch_source", fake_fetch)

    result = fetch_sources([healthy, failed], tmp_path, workers=2)

    assert set(result.downloaded) == {"fixture"}
    assert result.failures == {"failed": "upstream is gone"}


def test_stale_lock_preserves_last_success_and_records_fallback() -> None:
    previous = {
        "id": "fixture",
        "sha256": "b" * 64,
        "changed_at": "2026-08-01T00:00:00+00:00",
        "parsed_rules": 3,
        "rejected_rules": 0,
        "final_url": "https://example.com/rules?signature=secret",
    }

    entry = build_stale_lock_entry(
        source_spec(),
        previous=previous,
        preserved_rules=3,
        preserved_provenance=4,
        stale_rulesets=["example"],
    )

    assert entry["sha256"] == "b" * 64
    assert entry["changed_at"] == "2026-08-01T00:00:00+00:00"
    assert entry["sync_status"] == "stale"
    assert entry["preserved_rules"] == 3
    assert entry["preserved_provenance"] == 4
    assert entry["final_url"] == "https://example.com/rules"


def test_successful_download_clears_previous_stale_state() -> None:
    spec = source_spec()
    downloaded = DownloadedSource(
        spec=spec,
        data=b"ok",
        sha256="d" * 64,
        final_url=spec.url,
        etag="",
        last_modified="",
        from_cache=False,
    )

    entry = build_lock_entry(
        downloaded,
        parsed_rules=1,
        rejected_rules=0,
        previous={
            "id": "fixture",
            "sha256": "d" * 64,
            "changed_at": "2026-08-01T00:00:00+00:00",
            "sync_status": "stale",
            "stale_reason": "old failure",
        },
    )

    assert entry["changed_at"] == "2026-08-01T00:00:00+00:00"
    assert "sync_status" not in entry
    assert "stale_reason" not in entry
