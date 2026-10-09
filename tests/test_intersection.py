from __future__ import annotations

import pytest

from void_rules.intersection import intersect_ruleset_members
from void_rules.model import Action, Provenance, Rule, RuleKind


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (("domain", "a.example"), ("domain_suffix", "example"), ("domain", "a.example")),
        (
            ("domain_suffix", "a.example"),
            ("domain_suffix", "example"),
            ("domain_suffix", "a.example"),
        ),
        (("domain_suffix", "example"), ("domain_suffix", "notexample"), None),
        (("domain", "example"), ("domain_wildcard", ".example"), None),
        (("domain", "example"), ("domain_wildcard", "+.example"), ("domain", "example")),
        (("domain", "a.b.example"), ("domain_wildcard", "*.example"), None),
        (("domain", "a.example"), ("domain_wildcard", "*.example"), ("domain", "a.example")),
        (("domain_suffix", "a.example"), ("domain_wildcard", "*.example"), ("domain", "a.example")),
        (
            ("domain_suffix", "example"),
            ("domain_wildcard", "*.example"),
            ("domain_wildcard", "*.example"),
        ),
        (
            ("domain_suffix", "a.example"),
            ("domain_wildcard", ".example"),
            ("domain_suffix", "a.example"),
        ),
        (
            ("domain_suffix", "example"),
            ("domain_wildcard", ".example"),
            ("domain_wildcard", ".example"),
        ),
        (
            ("domain_wildcard", "+.*.example"),
            ("domain_suffix", "a.example"),
            ("domain_suffix", "a.example"),
        ),
        (
            ("domain_wildcard", ".*.example"),
            ("domain_suffix", "a.example"),
            ("domain_wildcard", ".a.example"),
        ),
        (
            ("domain_wildcard", "*.api.example"),
            ("domain_wildcard", "a.*.example"),
            ("domain", "a.api.example"),
        ),
        (
            ("domain_wildcard", "+.*.api.example"),
            ("domain_wildcard", "+.a.*.example"),
            ("domain_suffix", "a.api.example"),
        ),
    ],
)
def test_domain_intersections_keep_exact_coverage_in_both_orders(
    left: tuple[str, str], right: tuple[str, str], expected: tuple[str, str] | None
) -> None:
    a = Rule(RuleKind(left[0]), left[1])
    b = Rule(RuleKind(right[0]), right[1])
    want = [] if expected is None else [Rule(RuleKind(expected[0]), expected[1])]
    assert intersect_ruleset_members([a], [b], Action.MATCH) == want
    assert intersect_ruleset_members([b], [a], Action.MATCH) == want


def test_intersection_merges_provenance_and_recasts_actions_without_parent_expansion() -> None:
    a = Rule(RuleKind.DOMAIN_SUFFIX, "example", Action.ALLOW, provenance=(Provenance("ai"),))
    b = Rule(
        RuleKind.DOMAIN,
        "claude.example",
        Action.BLOCK,
        provenance=(Provenance("claude"),),
        protected=True,
    )
    shared = intersect_ruleset_members([a, a], [b, b], Action.MATCH)
    assert len(shared) == 1
    assert shared[0].content_key == b.content_key
    assert shared[0].action is Action.MATCH
    assert shared[0].protected
    assert {p.source_id for p in shared[0].provenance} == {"ai", "claude"}
