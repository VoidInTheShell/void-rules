from __future__ import annotations

from pathlib import Path

from void_rules.model import Action, Rule, RuleKind
from void_rules.render import render_outputs


def test_adguard_allow_and_block_outputs_are_separate() -> None:
    rules = [
        Rule(RuleKind.DOMAIN_SUFFIX, "blocked.example", Action.BLOCK),
        Rule(RuleKind.DOMAIN_SUFFIX, "allowed.example", Action.ALLOW),
    ]

    rendered = render_outputs(
        "fixture",
        rules,
        Action.BLOCK,
        ("adguard-block", "adguard-allow", "mihomo-classical-text"),
        root=Path("."),
        skip_binary=True,
    )

    assert rendered["adguard-block"].data.decode().endswith("||blocked.example^\n")
    assert rendered["adguard-allow"].data.decode().endswith("@@||allowed.example^\n")
    assert "allowed.example" not in rendered["mihomo-classical-text"].data.decode()
