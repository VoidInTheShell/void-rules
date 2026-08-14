from __future__ import annotations

import pytest

from void_rules.errors import ParseError
from void_rules.model import Action, RuleKind
from void_rules.parsers import parse_adguard, parse_xray_json


def parse_adguard_text(text: str, *, strict: bool = True):
    return parse_adguard(
        text,
        source_id="fixture",
        sha256="0" * 64,
        default_action=Action.BLOCK,
        strict=strict,
    )


def test_adguard_domain_rules_accept_optional_terminal_caret() -> None:
    result = parse_adguard_text("||example.com^\n||cdn.example.net\n|host.example.org^")

    assert [(rule.kind, rule.value) for rule in result.rules] == [
        (RuleKind.DOMAIN_SUFFIX, "example.com"),
        (RuleKind.DOMAIN_SUFFIX, "cdn.example.net"),
        (RuleKind.DOMAIN, "host.example.org"),
    ]


def test_adguard_accepts_standard_and_legacy_pcdn_regex_delimiters() -> None:
    result = parse_adguard_text(r"/^.*pcdn.*biliapi\.net$/" + "\n" + r"/^.*p2p.*qq\.com^")

    assert [(rule.kind, rule.value) for rule in result.rules] == [
        (RuleKind.DOMAIN_REGEX, r"^.*pcdn.*biliapi\.net$"),
        (RuleKind.DOMAIN_REGEX, r"^.*p2p.*qq\.com"),
    ]
    assert result.rejected == []


def test_adguard_unknown_line_still_fails_closed() -> None:
    with pytest.raises(ParseError, match="unknown AdGuard lines"):
        parse_adguard_text("this is not a rule")


def test_adguard_allow_rule_preserves_polarity() -> None:
    result = parse_adguard_text("@@||allowed.example^")

    assert len(result.rules) == 1
    assert result.rules[0].action is Action.ALLOW
    assert result.rules[0].kind is RuleKind.DOMAIN_SUFFIX
    assert result.rules[0].value == "allowed.example"


def test_adguard_unsupported_modifier_is_ignored_by_spec_not_fatal() -> None:
    result = parse_adguard_text("||ignored.example^$redirect=noop")

    assert result.rules == []
    assert len(result.rejected) == 1
    assert result.rejected[0].ignored_by_spec is True


def test_xray_json_preserves_domain_and_ip_kinds() -> None:
    result = parse_xray_json(
        """{
          "routing": {"rules": [{
            "domain": ["full:api.example.com", "domain:example.net", "geosite:private"],
            "ip": ["192.0.2.1", "geoip:private"]
          }]}
        }""",
        source_id="xray",
        sha256="0" * 64,
        action=Action.MATCH,
        strict=True,
    )

    assert {(rule.kind, rule.value) for rule in result.rules} == {
        (RuleKind.DOMAIN, "api.example.com"),
        (RuleKind.DOMAIN_SUFFIX, "example.net"),
        (RuleKind.GEOSITE, "private"),
        (RuleKind.IP_CIDR, "192.0.2.1/32"),
        (RuleKind.GEOIP, "private"),
    }
