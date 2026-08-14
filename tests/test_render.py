from __future__ import annotations

import gzip

from void_rules.artifacts import deterministic_gzip
from void_rules.render import RenderedFile, _compact_mrs_domain_source


def test_jsonl_gzip_is_reproducible_and_has_zero_mtime() -> None:
    raw = b'{"kind":"domain","value":"example.com"}\n'

    first = deterministic_gzip(raw)
    second = deterministic_gzip(raw)

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
