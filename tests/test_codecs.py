from __future__ import annotations

from pathlib import Path

import pytest

from void_rules.codecs import GeodataCodec, MihomoCodec

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.integration
def test_mihomo_mrs_domain_round_trip_with_pinned_cli() -> None:
    codec = MihomoCodec(ROOT)
    if not codec.executable().is_file():
        pytest.skip("pinned Mihomo CLI is not installed")
    source = b"+.example.com\napi.example.net\n"

    encoded = codec.encode(source, "domain")
    decoded = codec.decode(encoded, "domain")

    assert encoded.startswith(b"\x28\xb5\x2f\xfd")
    assert set(decoded.decode().splitlines()) == set(source.decode().splitlines())


@pytest.mark.integration
def test_v2ray_geosite_and_geoip_round_trip() -> None:
    codec = GeodataCodec(ROOT)
    geosite = [
        {
            "tag": "fixture",
            "kind": "domain_suffix",
            "value": "example.com",
            "attributes": ["test"],
        },
        {"tag": "fixture", "kind": "domain_regex", "value": r"^api\..+$"},
    ]
    geoip = [
        {"tag": "fixture", "kind": "ip_cidr", "value": "192.0.2.0/24"},
        {"tag": "fixture", "kind": "ip_cidr", "value": "2001:db8::/32"},
    ]

    geosite_data = codec.encode(geosite, "geosite")
    geoip_data = codec.encode(geoip, "geoip")

    assert codec.encode(geosite, "geosite") == geosite_data
    assert codec.encode(geoip, "geoip") == geoip_data

    def record_key(item: dict[str, object]) -> tuple[str, str, str]:
        return (str(item["tag"]), str(item["kind"]), str(item["value"]))

    assert codec.decode(geosite_data, "geosite", ("fixture",)) == sorted(
        geosite,
        key=record_key,
    )
    assert codec.decode(geoip_data, "geoip", ("fixture",)) == sorted(
        geoip,
        key=record_key,
    )
