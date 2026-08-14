from __future__ import annotations

import json
from typing import Any

import yaml

from .catalog import SourceSpec
from .codecs import GeodataCodec, MihomoCodec
from .errors import ParseError
from .model import Action, ParseResult, Provenance, RejectedLine, Rule, RuleKind
from .normalize import normalize_domain, normalize_ip_network
from .parsers import (
    parse_adguard,
    parse_classical,
    parse_mihomo_domain,
    parse_mihomo_ipcidr,
    parse_plain,
    parse_xray_domain_list,
    parse_xray_json,
)


def _decode_text(data: bytes, source_id: str) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParseError(f"{source_id}: input is not valid UTF-8") from exc


def _parse_geodata_records(
    records: list[dict[str, Any]],
    *,
    source_id: str,
    sha256: str,
    action: Action,
    strict: bool,
) -> ParseResult:
    rules: list[Rule] = []
    rejected: list[RejectedLine] = []
    for line_number, item in enumerate(records, start=1):
        raw = json.dumps(item, ensure_ascii=False, sort_keys=True)
        try:
            kind = RuleKind(str(item["kind"]))
            value = str(item["value"])
            if kind in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
                value = normalize_domain(value)
            elif kind in {RuleKind.IP_CIDR, RuleKind.SRC_IP_CIDR}:
                value = normalize_ip_network(value)
            attributes = tuple(sorted(str(value) for value in item.get("attributes", [])))
            rules.append(
                Rule(
                    kind=kind,
                    value=value,
                    action=action,
                    attributes=attributes,
                    provenance=(
                        Provenance(source_id=source_id, line=line_number, sha256=sha256, raw=raw),
                    ),
                )
            )
        except (KeyError, TypeError, ValueError, ParseError) as exc:
            rejected.append(RejectedLine(source_id, line_number, raw, str(exc)))
    if strict and rejected:
        raise ParseError(f"{source_id}: {len(rejected)} invalid DAT records")
    return ParseResult(rules, rejected, len(records))


def _detect_format(data: bytes) -> str:
    if data.startswith(b"\x28\xb5\x2f\xfd"):
        return "mrs"
    text = _decode_text(data[: min(len(data), 64 * 1024)], "auto-detect")
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return "xray-json"
    if "payload:" in text[:4096]:
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ParseError(f"auto-detected YAML is invalid: {exc}") from exc
        payload = document.get("payload") if isinstance(document, dict) else None
        if not isinstance(payload, list):
            raise ParseError("auto-detected YAML has no payload list")
        values = [str(value).strip() for value in payload]
        classical_prefixes = tuple(
            f"{name},"
            for name in (
                "DOMAIN",
                "DOMAIN-SUFFIX",
                "DOMAIN-KEYWORD",
                "DOMAIN-REGEX",
                "IP-CIDR",
                "IP-CIDR6",
                "SRC-IP-CIDR",
                "GEOIP",
                "GEOSITE",
            )
        )
        if any(value.upper().startswith(classical_prefixes) for value in values):
            return "clash-classical-yaml"
        ip_values = 0
        for value in values:
            try:
                normalize_ip_network(value)
            except ParseError:
                continue
            ip_values += 1
        if values and ip_values == len(values):
            return "mihomo-ipcidr-yaml"
        return "mihomo-domain-yaml"
    lines = [line.strip() for line in text.splitlines() if line.strip()][:50]
    if any(line.startswith(("||", "@@||", "/")) for line in lines):
        return "adguard"
    classical_prefixes = (
        "DOMAIN,",
        "DOMAIN-SUFFIX,",
        "DOMAIN-KEYWORD,",
        "DOMAIN-REGEX,",
        "IP-CIDR,",
        "IP-CIDR6,",
    )
    if any(line.upper().startswith(classical_prefixes) for line in lines):
        return "clash-classical-text"
    return "plain"


def parse_source(
    spec: SourceSpec,
    data: bytes,
    sha256: str,
    *,
    root: Any,
    mihomo: MihomoCodec | None = None,
    geodata: GeodataCodec | None = None,
) -> ParseResult:
    source_format = spec.format
    if source_format == "auto":
        source_format = _detect_format(data)
    action = Action.ALLOW if spec.whole_source_allowlist else spec.polarity

    if source_format == "mrs":
        if not spec.behavior:
            raise ParseError(f"{spec.id}: MRS source requires behavior")
        mihomo_codec = mihomo or MihomoCodec(root)
        decoded = mihomo_codec.decode(data, spec.behavior)
        if spec.behavior == "domain":
            return parse_mihomo_domain(
                _decode_text(decoded, spec.id),
                source_id=spec.id,
                sha256=sha256,
                action=action,
                strict=spec.strict,
                yaml_container=False,
            )
        return parse_mihomo_ipcidr(
            _decode_text(decoded, spec.id),
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
            yaml_container=False,
        )

    if source_format in {"geosite-dat", "geoip-dat"}:
        geodata_codec = geodata or GeodataCodec(root)
        kind = "geosite" if source_format == "geosite-dat" else "geoip"
        records = geodata_codec.decode(data, kind, spec.select_tags)
        return _parse_geodata_records(
            records,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
        )

    text = _decode_text(data, spec.id)
    if source_format == "clash-classical-text":
        return parse_classical(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
            yaml_container=False,
        )
    if source_format == "clash-classical-yaml":
        return parse_classical(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
            yaml_container=True,
        )
    if source_format == "mihomo-domain-text":
        return parse_mihomo_domain(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
            yaml_container=False,
        )
    if source_format == "mihomo-domain-yaml":
        return parse_mihomo_domain(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
            yaml_container=True,
        )
    if source_format == "mihomo-ipcidr-text":
        return parse_mihomo_ipcidr(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
            yaml_container=False,
        )
    if source_format == "mihomo-ipcidr-yaml":
        return parse_mihomo_ipcidr(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
            yaml_container=True,
        )
    if source_format == "adguard":
        return parse_adguard(
            text,
            source_id=spec.id,
            sha256=sha256,
            default_action=action,
            strict=spec.strict,
            whole_source_allowlist=spec.whole_source_allowlist,
        )
    if source_format == "xray-json":
        return parse_xray_json(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
        )
    if source_format == "xray-domain-list":
        return parse_xray_domain_list(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
        )
    if source_format in {"plain", "plain-domain", "plain-ip", "hosts"}:
        mode = (
            "domain"
            if source_format == "plain-domain"
            else "ip"
            if source_format == "plain-ip"
            else "auto"
        )
        return parse_plain(
            text,
            source_id=spec.id,
            sha256=sha256,
            action=action,
            strict=spec.strict,
            mode=mode,
        )
    raise ParseError(f"{spec.id}: unsupported source format {source_format!r}")
