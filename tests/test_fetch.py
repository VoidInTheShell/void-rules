from __future__ import annotations

import io
import urllib.request

import pytest

from void_rules.catalog import Limits, SourceSpec
from void_rules.errors import FetchError
from void_rules.fetch import (
    RestrictedRedirectHandler,
    _guard_payload,
    _read_response,
    _stable_public_url,
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
