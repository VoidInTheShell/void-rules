from __future__ import annotations

from .catalog import DomainKeywordFallback
from .model import Provenance, Rule, RuleKind


def _keyword_candidate(value: str, policy: DomainKeywordFallback) -> str | None:
    for label in value.casefold().rstrip(".").split("."):
        compact = label.replace("-", "")
        if (
            not compact
            or label.startswith("xn--")
            or label in policy.exclude
            or not compact.isascii()
            or not compact.isalnum()
        ):
            continue
        if len(compact) >= policy.min_label_length or label in policy.always_include:
            return label
    return None


def _derived_provenance(rule: Rule) -> tuple[Provenance, ...]:
    marker = f"Derived domain-keyword fallback from {rule.kind.value}:{rule.value}"
    return tuple(
        Provenance(
            source_id=item.source_id,
            line=item.line,
            sha256=item.sha256,
            evidence=f"{item.evidence}; {marker}" if item.evidence else marker,
            raw=item.raw,
        )
        for item in rule.provenance
    )


def derive_domain_keyword_fallbacks(rules: list[Rule], policy: DomainKeywordFallback) -> list[Rule]:
    derived: list[Rule] = []
    for rule in rules:
        if rule.kind not in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
            continue
        keyword = _keyword_candidate(rule.value, policy)
        if keyword is None:
            continue
        derived.append(
            Rule(
                kind=RuleKind.DOMAIN_KEYWORD,
                value=keyword,
                action=rule.action,
                provenance=_derived_provenance(rule),
                protected=rule.protected,
            )
        )
    return derived
