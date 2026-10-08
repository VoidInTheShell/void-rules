from __future__ import annotations

import gzip
import ipaddress
import json
import socket
import socketserver
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from void_rules.codecs import MihomoCodec
from void_rules.model import Action, Rule, RuleKind
from void_rules.normalize import classify_mihomo_domain
from void_rules.render import render_outputs
from void_rules.separation import exclude_ruleset_members

ROOT = Path(__file__).resolve().parents[1]
REAL_IP = ipaddress.IPv4Address("192.0.2.10")
FAKE_RANGE = ipaddress.IPv4Network("198.18.0.0/16")


class _Nameserver(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        query, sock = self.request
        # The test sends one uncompressed A question without EDNS.
        answer = struct.pack("!HHHLH", 0xC00C, 1, 1, 60, 4) + REAL_IP.packed
        header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        sock.sendto(header + query[12:] + answer, self.client_address)


def _skip_name(packet: bytes, offset: int) -> int:
    while packet[offset]:
        if packet[offset] & 0xC0 == 0xC0:
            return offset + 2
        offset += packet[offset] + 1
    return offset + 1


def _query_a(port: int, host: str) -> ipaddress.IPv4Address:
    name = b"".join(bytes([len(label)]) + label.encode() for label in host.split(".")) + b"\0"
    query = struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.25)
        sock.sendto(query, ("127.0.0.1", port))
        packet = sock.recv(4096)
    transaction, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", packet[:12])
    assert transaction == 1234 and flags & 0xF == 0
    offset = 12
    for _ in range(questions):
        offset = _skip_name(packet, offset) + 4
    for _ in range(answers):
        offset = _skip_name(packet, offset)
        kind, _, _, length = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        if kind == 1:
            return ipaddress.IPv4Address(packet[offset : offset + length])
        offset += length
    raise AssertionError(f"no A answer for {host}")


@pytest.mark.integration
def test_rule_mode_dns_preserves_children_without_disabling_force_parents(tmp_path: Path) -> None:
    codec = MihomoCodec(ROOT)
    reviewed = yaml.safe_load((ROOT / "overlays/fake-ip/conflicts.yaml").read_text())["allow"]
    exceptions = [
        item
        for item in reviewed
        if item["winner"] == "fake-ip-bypass"
        and (
            item["reason"].startswith("Reviewed NTP")
            or item["value"] == "firefox-portal-detection.com"
        )
    ]
    assert len(exceptions) == 93
    bypass = "".join(
        ("+." if item["kind"] == "domain_suffix" else "") + item["value"] + "\n"
        for item in exceptions
    )
    # Keep the exact conflicts and broad force parents: DNS precedence must work
    # even when upstream provider versions update at different times.
    force = bypass + "+.google.com\n+.apple.com\n+.nist.gov\n+.openai.com\n"
    for name, data in (("bypass", bypass), ("force", force)):
        (tmp_path / f"{name}.mrs").write_bytes(codec.encode(data.encode(), "domain"))

    config: dict[str, Any] = yaml.safe_load((ROOT / "examples/mihomo-dns.yaml").read_text())
    for name, filename in (("VoidFakeIPBypass", "bypass"), ("VoidFakeIPForce", "force")):
        config["rule-providers"][name] = {
            "type": "file",
            "behavior": "domain",
            "format": "mrs",
            "path": str(tmp_path / f"{filename}.mrs"),
        }
    cases = {"unlisted.example": False, "child.time.google.com": True}
    for item in exceptions:
        cases[item["value"]] = False
        if item["kind"] == "domain_suffix":
            cases["child." + item["value"]] = False
    for host in ("www.google.com", "www.apple.com", "www.nist.gov", "api.openai.com"):
        cases[host] = True
    _assert_dns_cases(tmp_path, config, cases)


def _assert_dns_cases(tmp_path: Path, config: dict[str, Any], cases: dict[str, bool]) -> None:
    codec = MihomoCodec(ROOT)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        dns_port = sock.getsockname()[1]
    with socketserver.UDPServer(("127.0.0.1", 0), _Nameserver) as upstream:
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        config["dns"].update(
            {
                "listen": f"127.0.0.1:{dns_port}",
                "nameserver": [f"udp://127.0.0.1:{upstream.server_address[1]}"],
                "use-hosts": False,
                "use-system-hosts": False,
            }
        )
        config.update({"ipv6": False, "geo-auto-update": False, "rules": ["MATCH,DIRECT"]})
        config_path = tmp_path / "mihomo.yaml"
        config_path.write_text(yaml.safe_dump(config))
        try:
            with (tmp_path / "mihomo.log").open("w+") as log:
                process = subprocess.Popen(
                    [str(codec.executable()), "-d", str(tmp_path), "-f", str(config_path)],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        assert process.poll() is None, (tmp_path / "mihomo.log").read_text()
                        try:
                            assert _query_a(dns_port, "ready.example") == REAL_IP
                            break
                        except (TimeoutError, ConnectionError):
                            if time.monotonic() >= deadline:
                                pytest.fail((tmp_path / "mihomo.log").read_text())
                            time.sleep(0.05)
                    for host, fake in cases.items():
                        answer = _query_a(dns_port, host)
                        assert answer in FAKE_RANGE if fake else answer == REAL_IP, host
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
        finally:
            upstream.shutdown()
            thread.join(timeout=5)


@pytest.mark.integration
@pytest.mark.parametrize(
    "behavior,format_", [("domain", "mrs"), ("domain", "yaml"), ("classical", "yaml")]
)
def test_stun_matching_agrees_with_actual_mihomo(
    tmp_path: Path, behavior: str, format_: str
) -> None:
    patterns = ["+.stun.example", "*.turn.example", ".relay.example", "stun.*"]
    cases = {
        "stun.example": True,
        "a.stun.example": True,
        "a.b.stun.example": True,
        "notstun.example": False,
        "a.turn.example": True,
        "turn.example": False,
        "a.b.turn.example": False,
        "relay.example": False,
        "a.relay.example": True,
        "a.b.relay.example": True,
        "stun.media.example": False,
        "stun.test": True,
        "stun.a.test": False,
        "time.google.com": False,
        "return.example": False,
    }
    rules = [Rule(*classify_mihomo_domain(pattern)) for pattern in patterns]
    for host, matched in cases.items():
        assert bool(exclude_ruleset_members([Rule(RuleKind.DOMAIN, host)], rules)[1]) is matched
    output = f"mihomo-{behavior}-{format_}"
    rendered = render_outputs("stun-fixture", rules, Action.MATCH, (output,), root=ROOT)[output]
    provider = tmp_path / rendered.name
    provider.write_bytes(rendered.data)
    config = {
        "dns": {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter-mode": "rule",
            "fake-ip-filter": ["RULE-SET,STUN,fake-ip", "MATCH,real-ip"],
        },
        "rule-providers": {
            "STUN": {"type": "file", "behavior": behavior, "format": format_, "path": str(provider)}
        },
    }
    _assert_dns_cases(tmp_path, config, cases)


@pytest.mark.integration
def test_published_gfw_ntp_and_claude_dns_results(tmp_path: Path) -> None:
    def read(name: str) -> list[Rule]:
        with gzip.open(ROOT / "dist" / name / "rules.jsonl.gz", "rt") as handle:
            return [Rule.from_dict(json.loads(line)) for line in handle]

    bypass = read("fake-ip-bypass")
    # Follow upstream changes: choose a current GFW-only domain, not a hostname
    # whose legitimate removal would otherwise block every future sync.
    gfw_host = next(
        rule.value
        for rule in read("fake-ip-force")
        if rule.kind is RuleKind.DOMAIN_SUFFIX
        and {p.source_id for p in rule.provenance} == {"loyalsoldier-gfw"}
        and not exclude_ruleset_members(
            [Rule(RuleKind.DOMAIN, rule.value), Rule(RuleKind.DOMAIN, "child." + rule.value)],
            bypass,
        )[1]
    )
    config = yaml.safe_load((ROOT / "examples/mihomo-dns.yaml").read_text())
    for provider, name in (
        ("VoidFakeIPBypass", "fake-ip-bypass"),
        ("VoidFakeIPForce", "fake-ip-force"),
    ):
        local = tmp_path / f"{name}.mrs"
        local.write_bytes((ROOT / "dist" / name / "mihomo-domain.mrs").read_bytes())
        config["rule-providers"][provider] = {
            "type": "file",
            "behavior": "domain",
            "format": "mrs",
            "path": str(local),
        }
    _assert_dns_cases(
        tmp_path,
        config,
        {
            gfw_host: True,
            "child." + gfw_host: True,
            "claude.ai": True,
            "api.anthropic.com": True,
            "time.google.com": False,
            "pool.ntp.org": False,
            "nflxvideo.net": False,
            "stun.qq.com": False,
            "numb.viagenie.ca": False,
        },
    )
