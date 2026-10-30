from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from _native_mihomo import validate_native

from void_rules.codecs import MihomoCodec
from void_rules.model import Action
from void_rules.parsers import parse_adguard
from void_rules.render import render_outputs

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.integration
@pytest.mark.parametrize(
    "output,behavior,fmt",
    [
        ("mihomo-classical-yaml", "classical", "yaml"),
        ("mihomo-domain-yaml", "domain", "yaml"),
        ("mihomo-domain-mrs", "domain", "mrs"),
    ],
)
def test_native_fixture_matching_and_no_silent_invalid_entries(
    tmp_path: Path,
    output: str,
    behavior: str,
    fmt: str,
) -> None:
    rules = parse_adguard(
        "|exact.fixture.invalid^\n||suffix.fixture.invalid^\n"
        "||*.wild.fixture.invalid^\n||apd-*.partial.fixture.invalid^\n"
        "||conditional.fixture.invalid^$dnstype=AAAA\n",
        source_id="fixture",
        sha256="0" * 64,
        default_action=Action.BLOCK,
        strict=True,
    ).rules
    rendered = render_outputs("fixture", rules, Action.BLOCK, (output,), root=ROOT)[output]
    path = tmp_path / rendered.name
    path.write_bytes(rendered.data)
    cases = [
        ("exact.fixture.invalid", "hit_fixture"),
        ("child.exact.fixture.invalid", "miss"),
        ("suffix.fixture.invalid", "hit_fixture"),
        ("child.suffix.fixture.invalid", "hit_fixture"),
        ("wild.fixture.invalid", "miss"),
        ("a.wild.fixture.invalid", "hit_fixture"),
        ("a.b.wild.fixture.invalid", "hit_fixture"),
        ("apd-demo.partial.fixture.invalid", "hit_fixture" if behavior == "classical" else "miss"),
        (
            "child.apd-demo.partial.fixture.invalid",
            "hit_fixture" if behavior == "classical" else "miss",
        ),
        ("other.partial.fixture.invalid", "miss"),
        ("conditional.fixture.invalid", "miss"),
        ("control.example.invalid", "miss"),
    ]
    validate_native(
        MihomoCodec(ROOT).executable(),
        {
            "fixture": (path, behavior, fmt, rendered.represented - rendered.compacted),
        },
        cases,
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    "name,behavior,fmt",
    [
        ("mihomo-classical.yaml", "classical", "yaml"),
        ("mihomo-domain.yaml", "domain", "yaml"),
        ("mihomo-domain.mrs", "domain", "mrs"),
    ],
)
def test_published_pcdn_native_matching_and_documented_regex_gap(
    name: str,
    behavior: str,
    fmt: str,
) -> None:
    path = ROOT / "dist/pcdn" / name
    expected = len(yaml.safe_load(path.read_text())["payload"]) if fmt == "yaml" else None
    cases = [
        ("bsccdn.net", "hit_pcdn"),
        ("edge.p2p.qq.com", "hit_pcdn"),
        ("a.b.gslb.ubeethiesemo.com", "hit_pcdn"),
        ("apd-demo.teg.tencent-cloud.net", "hit_pcdn" if behavior == "classical" else "miss"),
        ("child.apd-demo.teg.tencent-cloud.net", "hit_pcdn" if behavior == "classical" else "miss"),
        ("abc-pcdn-def.biliapi.net", "hit_pcdn" if behavior == "classical" else "miss"),
        ("control.example.invalid", "miss"),
    ]
    validate_native(
        MihomoCodec(ROOT).executable(),
        {
            "pcdn": (path, behavior, fmt, expected),
        },
        cases,
    )
