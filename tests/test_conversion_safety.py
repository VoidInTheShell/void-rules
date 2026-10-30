from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pytest

from void_rules.errors import ParseError
from void_rules.model import Action, Rule, RuleKind
from void_rules.normalize import adguard_host_pattern, wildcard_to_regex
from void_rules.parsers import parse_adguard, parse_classical_line
from void_rules.render import render_outputs


def parse(text: str):
    return parse_adguard(
        text, source_id="fixture", sha256="0" * 64, default_action=Action.BLOCK, strict=True
    )


def test_character_globs_become_regex_not_literal_suffixes() -> None:
    rule = parse("||apd-*.example.net^").rules[0]
    assert rule.kind is RuleKind.DOMAIN_REGEX
    for host in ("apd-demo.example.net", "child.apd-demo.example.net"):
        assert re.search(rule.value, host)
    for host in ("other.example.net", "apd-demo.example.net.invalid"):
        assert not re.search(rule.value, host)
    outputs = render_outputs(
        "fixture",
        [rule],
        Action.BLOCK,
        ("mihomo-classical-text", "mihomo-domain-text", "xray-domain-list", "adguard-block"),
        root=Path("."),
        skip_binary=True,
    )
    assert outputs["mihomo-classical-text"].data.decode().startswith("DOMAIN-REGEX,")
    assert outputs["xray-domain-list"].data.decode().startswith("regexp:")
    assert outputs["mihomo-domain-text"].represented == 0
    assert len(outputs["mihomo-domain-text"].skipped) == 1


def test_middle_label_adguard_glob_is_not_narrowed_to_one_dns_label() -> None:
    rule = parse("||edge.*.example.net^").rules[0]
    assert rule.kind is RuleKind.DOMAIN_REGEX
    assert re.search(rule.value, "edge.a.b.example.net")


def test_leading_glob_maps_losslessly_to_subdomains_only() -> None:
    kind, value = adguard_host_pattern("*.example.net", suffix=True)
    assert (kind, value) == (RuleKind.DOMAIN_WILDCARD, ".example.net")
    pattern = wildcard_to_regex(value)
    assert re.search(pattern, "a.b.example.net")
    assert not re.search(pattern, "example.net")


def test_exact_adguard_glob_does_not_gain_suffix_anchor() -> None:
    rule = parse("|apd-*.example.net^").rules[0]
    assert re.search(rule.value, "apd-demo.example.net")
    assert not re.search(rule.value, "child.apd-demo.example.net")


@pytest.mark.parametrize(
    "modifier",
    ["dnstype=AAAA", "client=one", "dnsrewrite=NXDOMAIN", "denyallow=one.example", "important"],
)
def test_conditions_are_reported_instead_of_becoming_unconditional_rules(modifier: str) -> None:
    rule = parse("||example.net^$" + modifier).rules[0]
    outputs = render_outputs(
        "fixture",
        [rule],
        Action.BLOCK,
        ("mihomo-classical-text", "mihomo-domain-text", "xray-domain-list", "adguard-block"),
        root=Path("."),
        skip_binary=True,
    )
    for name in ("mihomo-classical-text", "mihomo-domain-text", "xray-domain-list"):
        assert outputs[name].represented == 0
        assert len(outputs[name].skipped) == 1
    assert "$" + modifier in outputs["adguard-block"].data.decode()


def test_badfilter_cannot_be_promoted_to_a_block_or_silently_ignored() -> None:
    with pytest.raises(ParseError, match="unknown AdGuard lines"):
        parse("||example.net^\n||example.net^$badfilter")


@pytest.mark.parametrize(
    "line",
    [
        "DOMAIN-REGEX,(",
        r"DOMAIN-REGEX,(?=api)example",
        r"DOMAIN-REGEX,(x)\1",
        r"DOMAIN-REGEX,a++",
        r"DOMAIN-REGEX,a{1001}",
        r"DOMAIN-REGEX,(?#comment)example",
        r"DOMAIN-REGEX,(?ix)example",
        r"DOMAIN-REGEX,example\Z",
        "UNKNOWN-RULE,example.net",
        "DOMAIN-SUFFIX,apd-*.example.net",
        "DOMAIN,*.example.net",
        "IP-ASN,not-a-number",
        "DOMAIN,example.net,DIRECT",
        "DOMAIN-SUFFIX,example.net,no-resolve",
        "IP-CIDR,10.0.0.0/8,no-resolve,other",
    ],
)
def test_classical_parser_refuses_rules_the_output_cannot_use(line: str) -> None:
    with pytest.raises(ParseError):
        parse_classical_line(
            line, source_id="fixture", line=1, sha256="0" * 64, action=Action.MATCH
        )


@pytest.mark.parametrize("value", ["apd-*.example.net", "bad/example.net", "a..example.net"])
def test_invalid_literal_domains_cannot_bypass_parser_via_rule_objects(value: str) -> None:
    with pytest.raises(ParseError):
        render_outputs(
            "fixture",
            [Rule(RuleKind.DOMAIN_SUFFIX, value)],
            Action.MATCH,
            ("mihomo-domain-text",),
            root=Path("."),
            skip_binary=True,
        )


@pytest.mark.parametrize("value", [".example.net", "+.example.net", "*.example.net"])
def test_mihomo_wildcards_keep_semantics_in_adguard_output(value: str) -> None:
    output = render_outputs(
        "fixture",
        [Rule(RuleKind.DOMAIN_WILDCARD, value, Action.BLOCK)],
        Action.BLOCK,
        ("adguard-block",),
        root=Path("."),
        skip_binary=True,
    )["adguard-block"]
    text = output.data.decode()
    pattern = next(line[1:-1] for line in text.splitlines() if line.startswith("/"))
    assert pattern == wildcard_to_regex(value)


@pytest.mark.parametrize("base", ["example.net", "other.invalid", "xn--fsqu00a.test"])
@pytest.mark.parametrize("shape", ["*.", "edge-*.", "*-edge.", "pre*post.", "edge.*.", "*.*."])
@pytest.mark.parametrize("suffix", [False, True])
def test_host_glob_recognition_is_generic(base: str, shape: str, suffix: bool) -> None:
    pattern = shape + base
    rule = parse(("||" if suffix else "|") + pattern + "^").rules[0]
    regex = wildcard_to_regex(rule.value) if rule.kind is RuleKind.DOMAIN_WILDCARD else rule.value
    for replacement in ("alpha", "a.b", ""):
        expanded = pattern.replace("*", replacement)
        for host in (expanded, "child." + expanded, "a.b." + expanded, "control." + base):
            if ".." in host or host.startswith("."):
                continue
            candidates = [host]
            if suffix:
                labels = host.split(".")
                candidates.extend(".".join(labels[i:]) for i in range(1, len(labels)))
            expected = any(fnmatch.fnmatchcase(candidate, pattern) for candidate in candidates)
            assert bool(re.search(regex, host)) == expected, (pattern, host, regex)
