from __future__ import annotations

from pathlib import Path

import pytest

from void_rules.adapters import _detect_format, parse_source
from void_rules.catalog import Limits, SourceSpec
from void_rules.errors import ParseError
from void_rules.model import Action, RuleKind


def source_spec(source_format: str, *, allowlist: bool = False) -> SourceSpec:
    return SourceSpec(
        id="fixture",
        name="fixture",
        url="https://example.com/rules",
        fallback_urls=(),
        format=source_format,
        behavior=None,
        polarity=Action.BLOCK,
        whole_source_allowlist=allowlist,
        select_tags=(),
        companion_source=None,
        license="MIT",
        homepage="https://example.com",
        allowed_hosts=frozenset({"example.com"}),
        strict=True,
        enabled=True,
        headers=(),
        limits=Limits(min_rules=0, max_rules=100),
        notes="",
    )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"payload:\n  - '+.Example.COM'\n", "mihomo-domain-yaml"),
        (b"payload:\n  - '1.2.3.4/24'\n", "mihomo-ipcidr-yaml"),
        (b"payload:\n  - 'DOMAIN-SUFFIX,example.com'\n", "clash-classical-yaml"),
        (b"rules:\n  - '+.example.com'\n", "mihomo-domain-yaml"),
        (b"- '+.example.com'\n", "mihomo-domain-yaml"),
        (b"# source comment\n- '+.example.com'\n", "mihomo-domain-yaml"),
        (b"||example.com^\n", "adguard"),
        (b"DOMAIN-SUFFIX,example.com\n", "clash-classical-text"),
    ],
)
def test_auto_detection_inspects_yaml_payload_content(payload: bytes, expected: str) -> None:
    assert _detect_format(payload) == expected


def test_domain_yaml_does_not_leak_yaml_markers_into_rules() -> None:
    result = parse_source(
        source_spec("mihomo-domain-yaml"),
        b"payload:\n  - '+.Example.COM'\n  - 'api.example.net'\n",
        "0" * 64,
        root=Path("."),
    )

    assert [(rule.kind, rule.value) for rule in result.rules] == [
        (RuleKind.DOMAIN_SUFFIX, "example.com"),
        (RuleKind.DOMAIN, "api.example.net"),
    ]
    assert all(not rule.value.startswith("-") for rule in result.rules)


def test_whole_source_allowlist_overrides_default_block_polarity() -> None:
    result = parse_source(
        source_spec("plain-domain", allowlist=True),
        b"allowed.example\n",
        "0" * 64,
        root=Path("."),
    )

    assert result.rules[0].action is Action.ALLOW


def test_invalid_auto_detected_yaml_fails_closed() -> None:
    with pytest.raises(ParseError, match="invalid"):
        _detect_format(b"payload:\n  - [unterminated\n")


@pytest.mark.parametrize("container", ["payload:\n", "rules:\n", ""])
def test_domain_text_rejects_yaml_instead_of_emitting_opaque_rules(container: str) -> None:
    with pytest.raises(ParseError, match="declare mihomo-domain-yaml"):
        parse_source(
            source_spec("mihomo-domain-text"),
            (container + "  - '+.gfw-only.example'\n").encode(),
            "0" * 64,
            root=Path("."),
        )


@pytest.mark.parametrize("entry", ["null", "false", "123", "{}", "[]", "''"])
def test_yaml_rule_entries_must_be_nonempty_strings(entry: str) -> None:
    with pytest.raises(ParseError, match="nonempty strings"):
        parse_source(
            source_spec("mihomo-domain-yaml"),
            f"payload:\n  - {entry}\n".encode(),
            "0" * 64,
            root=Path("."),
        )


def test_large_yaml_auto_detection_does_not_parse_a_truncated_document() -> None:
    data = ("payload:\n" + "  - '+.long-example-domain.example'\n" * 4000).encode()
    assert len(data) > 65536
    assert _detect_format(data) == "mihomo-domain-yaml"


@pytest.mark.parametrize(
    "data", [b"payload: ['+.example.com']", b"rules : []", b"['a.example', 'b.example']"]
)
def test_inline_yaml_cannot_pass_as_opaque_domain_text(data: bytes) -> None:
    with pytest.raises(ParseError, match="YAML container"):
        parse_source(source_spec("mihomo-domain-text"), data, "0" * 64, root=Path("."))


def test_yaml_word_in_a_comment_does_not_change_auto_detection() -> None:
    assert _detect_format(b"# payload: is a YAML key\nexample.com\n") == "plain"
