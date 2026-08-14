from __future__ import annotations

from void_rules.model import Action, Provenance, Rule, RuleKind, deduplicate_rules
from void_rules.normalize import classify_mihomo_domain, normalize_domain, normalize_ip_network


def test_deduplicate_merges_provenance_without_losing_protection() -> None:
    first = Rule(
        RuleKind.DOMAIN_SUFFIX,
        "example.com",
        Action.MATCH,
        provenance=(Provenance("one", line=1),),
    )
    second = Rule(
        RuleKind.DOMAIN_SUFFIX,
        "example.com",
        Action.MATCH,
        provenance=(Provenance("two", line=2),),
        protected=True,
    )

    merged = deduplicate_rules([first, second])

    assert len(merged) == 1
    assert merged[0].protected is True
    assert {item.source_id for item in merged[0].provenance} == {"one", "two"}


def test_normalization_handles_idn_cidr_and_mihomo_suffix() -> None:
    assert normalize_domain("BÜCHER.example.") == "xn--bcher-kva.example"
    assert normalize_ip_network("192.0.2.42/24") == "192.0.2.0/24"
    assert classify_mihomo_domain("+.Example.COM") == (
        RuleKind.DOMAIN_SUFFIX,
        "example.com",
    )
