from __future__ import annotations

from dataclasses import replace

from .model import Action, Rule, RuleKind, deduplicate_rules
from .normalize import wildcard_to_regex

DOMAIN_PATTERNS = {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX, RuleKind.DOMAIN_WILDCARD}


def _domain_pattern(rule: Rule) -> tuple[tuple[str, ...], int, int | None]:
    value = rule.value
    prefix_minimum = 0
    any_depth = rule.kind is RuleKind.DOMAIN_SUFFIX
    if rule.kind is RuleKind.DOMAIN_WILDCARD:
        # Reuse the parser's whole-label wildcard validation.
        wildcard_to_regex(value)
        any_depth = value.startswith(("+.", "."))
        prefix_minimum = int(value.startswith("."))
        value = value.removeprefix("+.").removeprefix(".")
    labels = tuple(value.split("."))
    return labels, len(labels) + prefix_minimum, None if any_depth else len(labels)


def _domain_intersection(left: Rule, right: Rule) -> Rule | None:
    left_labels, left_minimum, left_maximum = _domain_pattern(left)
    right_labels, right_minimum, right_maximum = _domain_pattern(right)
    minimum = max(left_minimum, right_minimum)
    maxima = [value for value in (left_maximum, right_maximum) if value is not None]
    maximum = min(maxima) if maxima else None
    if maximum is not None and minimum > maximum:
        return None

    # Align from the DNS root. Only '*' matches an arbitrary whole label;
    # fixed-label conflicts and differing exact lengths have no intersection.
    labels: list[str] = []
    for offset in range(1, max(len(left_labels), len(right_labels)) + 1):
        a = left_labels[-offset] if offset <= len(left_labels) else "*"
        b = right_labels[-offset] if offset <= len(right_labels) else "*"
        if a != b and a != "*" and b != "*":
            return None
        labels.append(b if a == "*" else a)
    value = ".".join(reversed(labels))
    if maximum is not None:
        kind = RuleKind.DOMAIN_WILDCARD if "*" in value else RuleKind.DOMAIN
    elif minimum > len(labels):
        kind = RuleKind.DOMAIN_WILDCARD
        value = "." + value
    elif "*" in value:
        kind = RuleKind.DOMAIN_WILDCARD
        value = "+." + value
    else:
        kind = RuleKind.DOMAIN_SUFFIX
    return replace(left, kind=kind, value=value)


def intersect_ruleset_members(left: list[Rule], right: list[Rule], action: Action) -> list[Rule]:
    """Intersect domain coverage; other kinds require identical content.

    Domain, suffix and Mihomo whole-label wildcard intersections remain exactly
    representable. Keep the narrower coverage and both sources' provenance,
    without expanding a child domain to its parent's unrelated siblings.
    """
    intersections: list[Rule] = []
    for a in left:
        for b in right:
            if a.attributes != b.attributes:
                continue
            if a.kind in DOMAIN_PATTERNS and b.kind in DOMAIN_PATTERNS:
                shared = _domain_intersection(a, b)
            else:
                shared = a if a.content_key == b.content_key else None
            if shared is not None:
                intersections.append(
                    replace(
                        shared,
                        action=action,
                        provenance=tuple(sorted(set(a.provenance + b.provenance))),
                        protected=a.protected or b.protected,
                    )
                )
    return deduplicate_rules(intersections)
