from __future__ import annotations

import gzip
import os
import subprocess
import sys
from pathlib import Path

from void_rules.artifacts import deterministic_gzip
from void_rules.render import (
    RenderedFile,
    _compact_mrs_domain_source,
    _compact_mrs_ipcidr_source,
)

ROOT = Path(__file__).resolve().parents[1]


def test_jsonl_gzip_is_reproducible_and_has_zero_mtime() -> None:
    raw = b'{"kind":"domain","value":"example.com"}\n'

    first = deterministic_gzip(raw, ROOT)
    second = deterministic_gzip(raw, ROOT)

    assert first == second
    assert first[4:8] == b"\x00\x00\x00\x00"
    assert gzip.decompress(first) == raw


def test_mrs_domain_compaction_removes_only_same_root_exact_duplicates() -> None:
    source = RenderedFile(
        "mihomo-domain.list",
        (b"+.example.com\napi.example.com\nexample.com\n*.wild.example\n+.stun.*.*\nstun.*.*\n"),
        6,
        (),
    )

    data, compacted = _compact_mrs_domain_source(source)

    assert data.decode().splitlines() == [
        "*.wild.example",
        "+.example.com",
        "+.stun.*.*",
        "api.example.com",
    ]
    assert compacted == 2


def test_mrs_domain_compaction_keeps_exact_without_same_root_suffix() -> None:
    source = RenderedFile("mihomo-domain.list", b"+.example.com\nother.example.com\n", 2, ())

    data, compacted = _compact_mrs_domain_source(source)

    assert set(data.decode().splitlines()) == {"+.example.com", "other.example.com"}
    assert compacted == 0


def test_process_name_output_is_stable_across_hash_seeds() -> None:
    script = """from pathlib import Path
from void_rules.model import Action, Rule, RuleKind
from void_rules.render import render_outputs
rules = [Rule(RuleKind.PROCESS_NAME, n) for n in
         ("Claude", "claude", "Claude.exe", "claude.exe")]
output = render_outputs("fixture", rules, Action.MATCH,
                        ("mihomo-classical-text",), root=Path("."))
print(output["mihomo-classical-text"].data.decode(), end="")
"""
    outputs = [
        subprocess.run(
            [sys.executable, "-c", script],
            env={**os.environ, "PYTHONHASHSEED": str(seed)},
            check=True,
            capture_output=True,
        ).stdout
        for seed in (1, 2, 3, 4)
    ]

    assert len(set(outputs)) == 1
    assert set(outputs[0].decode().splitlines()) == {
        "PROCESS-NAME,Claude",
        "PROCESS-NAME,claude",
        "PROCESS-NAME,Claude.exe",
        "PROCESS-NAME,claude.exe",
    }


def test_mrs_ipcidr_compaction_keeps_exact_union_of_both_address_families() -> None:
    source = RenderedFile(
        "mihomo-ipcidr.list",
        b"192.0.2.0/25\n192.0.2.128/25\n198.51.100.0/24\n2001:db8::/32\n2001:db8:1::/48\n",
        5,
        (),
    )

    data, compacted = _compact_mrs_ipcidr_source(source)

    assert set(data.decode().splitlines()) == {"192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"}
    assert compacted == 2
