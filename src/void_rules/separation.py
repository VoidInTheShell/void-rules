from __future__ import annotations

import re

from .errors import BuildError
from .model import Rule, RuleKind
from .normalize import wildcard_to_regex


def is_stun_turn_rule(rule: Rule) -> bool:
    """Identify explicit STUN/TURN labels without matching words like return.

    This selects existing upstream rules; it never synthesizes broad wildcard
    rules. Unnamed relay endpoints are identified by the category source.
    """
    if rule.kind in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX, RuleKind.DOMAIN_WILDCARD}:
        return any(
            re.fullmatch(r"(?:stun|turn)(?:[0-9]+)?(?:-[a-z0-9-]+)?", label)
            for label in rule.value.lower().split(".")
        )
    if rule.kind is RuleKind.DOMAIN_KEYWORD:
        return rule.value.lower() in {"stun", "turn"}
    if rule.kind is RuleKind.DOMAIN_REGEX:
        # Only the historical anchored label patterns are known to require
        # STUN/TURN on every match. An arbitrary regex may also match NTP.
        return any(
            rule.value == r"^.*\." + label + r"\.[^.]+" * depth + "$"
            for label in ("stun", "turn")
            for depth in range(2, 6)
        )
    return False


def exclude_ruleset_members(
    rules: list[Rule], exclusions: list[Rule]
) -> tuple[list[Rule], list[Rule]]:
    """Remove members independently of their source or action.

    Exact kind/value matches and names wholly covered by an excluded suffix
    are removed. Wildcard, keyword and regex exclusions also match exact domain
    entries. Broader parent rules remain: positive lists cannot express holes
    under a suffix, and removing the whole parent would change unrelated names.
    """
    keys = {(rule.kind, rule.value) for rule in exclusions}
    suffixes = {rule.value for rule in exclusions if rule.kind is RuleKind.DOMAIN_SUFFIX}
    patterns = [
        re.compile(wildcard_to_regex(rule.value))
        for rule in exclusions
        if rule.kind is RuleKind.DOMAIN_WILDCARD
    ]
    suffix_patterns = [
        re.compile(wildcard_to_regex(rule.value))
        for rule in exclusions
        if rule.kind is RuleKind.DOMAIN_WILDCARD and rule.value.startswith(("+.", "."))
    ]
    for rule in exclusions:
        if rule.kind is RuleKind.DOMAIN_REGEX:
            try:
                patterns.append(re.compile(rule.value))
            except re.error as exc:
                raise BuildError(
                    f"cannot safely evaluate exclusion regex {rule.value!r}: {exc}"
                ) from exc
    keywords = [rule.value for rule in exclusions if rule.kind is RuleKind.DOMAIN_KEYWORD]
    kept: list[Rule] = []
    removed: list[Rule] = []
    for rule in rules:
        excluded = (rule.kind, rule.value) in keys
        if not excluded and rule.kind in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
            labels = rule.value.split(".")
            excluded = any(".".join(labels[offset:]) in suffixes for offset in range(len(labels)))
        if not excluded and rule.kind is RuleKind.DOMAIN_WILDCARD:
            # A fixed trailing suffix proves that every wildcard match belongs
            # to the excluded suffix. Never delete a broader/partial overlap.
            labels = rule.value.removeprefix("+.").split(".")
            for offset in range(len(labels)):
                tail = ".".join(labels[offset:])
                if not any(char in tail for char in "*?+") and tail in suffixes:
                    excluded = True
                    break
        if not excluded and rule.kind is RuleKind.DOMAIN:
            excluded = any(pattern.search(rule.value) for pattern in patterns) or any(
                keyword in rule.value for keyword in keywords
            )
        if not excluded and rule.kind is RuleKind.DOMAIN_SUFFIX:
            excluded = any(pattern.search(rule.value) for pattern in suffix_patterns) or any(
                keyword in rule.value for keyword in keywords
            )
        (removed if excluded else kept).append(rule)
    return kept, removed
