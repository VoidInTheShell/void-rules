from __future__ import annotations

from void_rules.catalog import DomainKeywordFallback
from void_rules.model import Action, Provenance, Rule, RuleKind
from void_rules.transforms import derive_domain_keyword_fallbacks


def test_domain_keyword_fallback_covers_all_eligible_domain_rules() -> None:
    policy = DomainKeywordFallback(
        min_label_length=4,
        always_include=frozenset({"okx"}),
        exclude=frozenset({"home", "cash"}),
    )
    rules = [
        Rule(
            RuleKind.DOMAIN_SUFFIX,
            "bitget.com",
            Action.MATCH,
            provenance=(Provenance("finance", line=1),),
        ),
        Rule(RuleKind.DOMAIN_SUFFIX, "plasma-one.tech", Action.MATCH),
        Rule(RuleKind.DOMAIN_SUFFIX, "okx.com", Action.MATCH),
        Rule(RuleKind.DOMAIN, "home.saxo", Action.MATCH),
        Rule(RuleKind.DOMAIN_SUFFIX, "cash.app", Action.MATCH),
        Rule(RuleKind.IP_CIDR, "192.0.2.0/24", Action.MATCH),
    ]

    derived = derive_domain_keyword_fallbacks(rules, policy)

    assert {(rule.kind, rule.value) for rule in derived} == {
        (RuleKind.DOMAIN_KEYWORD, "bitget"),
        (RuleKind.DOMAIN_KEYWORD, "okx"),
        (RuleKind.DOMAIN_KEYWORD, "plasma-one"),
        (RuleKind.DOMAIN_KEYWORD, "saxo"),
    }
    bitget = next(rule for rule in derived if rule.value == "bitget")
    assert bitget.provenance[0].source_id == "finance"
    assert "domain_suffix:bitget.com" in bitget.provenance[0].evidence


def test_domain_keyword_fallback_preserves_protected_rules() -> None:
    policy = DomainKeywordFallback(4, frozenset(), frozenset())
    source = Rule(RuleKind.DOMAIN_SUFFIX, "bybit.com", protected=True)

    [derived] = derive_domain_keyword_fallbacks([source], policy)

    assert derived.protected is True
