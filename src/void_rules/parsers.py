from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from typing import Any

import yaml

from .errors import ParseError
from .model import Action, ParseResult, Provenance, RejectedLine, Rule, RuleKind
from .normalize import classify_mihomo_domain, normalize_domain, normalize_ip_network

CLASSICAL_KIND_MAP: dict[str, RuleKind] = {
    "DOMAIN": RuleKind.DOMAIN,
    "HOST": RuleKind.DOMAIN,
    "DOMAIN-SUFFIX": RuleKind.DOMAIN_SUFFIX,
    "HOST-SUFFIX": RuleKind.DOMAIN_SUFFIX,
    "DOMAIN-KEYWORD": RuleKind.DOMAIN_KEYWORD,
    "HOST-KEYWORD": RuleKind.DOMAIN_KEYWORD,
    "DOMAIN-REGEX": RuleKind.DOMAIN_REGEX,
    "HOST-REGEX": RuleKind.DOMAIN_REGEX,
    "IP-CIDR": RuleKind.IP_CIDR,
    "IP-CIDR6": RuleKind.IP_CIDR,
    "SRC-IP-CIDR": RuleKind.SRC_IP_CIDR,
    "SRC-IP-CIDR6": RuleKind.SRC_IP_CIDR,
    "GEOIP": RuleKind.GEOIP,
    "GEOSITE": RuleKind.GEOSITE,
    "DST-PORT": RuleKind.DST_PORT,
    "SRC-PORT": RuleKind.SRC_PORT,
    "PROCESS-NAME": RuleKind.PROCESS_NAME,
    "PROCESS-PATH": RuleKind.PROCESS_PATH,
    "NETWORK": RuleKind.NETWORK,
}

SUPPORTED_ADGUARD_MODIFIERS = {
    "badfilter",
    "client",
    "denyallow",
    "dnsrewrite",
    "dnstype",
    "important",
}


def _provenance(source_id: str, line: int, raw: str, sha256: str) -> tuple[Provenance, ...]:
    return (Provenance(source_id=source_id, line=line, raw=raw, sha256=sha256),)


def _rule(
    kind: RuleKind,
    value: str,
    action: Action,
    source_id: str,
    line: int,
    raw: str,
    sha256: str,
    *,
    attributes: Iterable[str] = (),
    protected: bool = False,
) -> Rule:
    return Rule(
        kind=kind,
        value=value,
        action=action,
        attributes=tuple(sorted(set(attributes))),
        provenance=_provenance(source_id, line, raw, sha256),
        protected=protected,
    )


def parse_classical_line(
    raw: str,
    *,
    source_id: str,
    line: int,
    sha256: str,
    action: Action,
    protected: bool = False,
) -> Rule:
    if "," not in raw:
        raise ParseError("classical rule has no comma")
    kind_raw, remainder = raw.split(",", 1)
    kind_name = kind_raw.strip().upper()
    kind = CLASSICAL_KIND_MAP.get(kind_name)
    if kind is None:
        if kind_name in {"MATCH", "FINAL", "RULE-SET", "SUB-RULE"}:
            raise ParseError(f"{kind_name} is not valid inside a standalone rule provider")
        return _rule(
            RuleKind.OPAQUE_CLASSICAL,
            raw.strip(),
            action,
            source_id,
            line,
            raw,
            sha256,
            protected=protected,
        )

    attributes: list[str] = []
    if kind is RuleKind.DOMAIN_REGEX:
        value = remainder.strip()
        if value.lower().endswith(",no-resolve"):
            value = value[: -len(",no-resolve")]
            attributes.append("no-resolve")
    else:
        parts = [part.strip() for part in remainder.split(",")]
        value = parts[0]
        attributes.extend(part for part in parts[1:] if part)
    if not value:
        raise ParseError("classical rule has an empty value")

    if kind in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
        value = normalize_domain(value)
    elif kind in {RuleKind.IP_CIDR, RuleKind.SRC_IP_CIDR}:
        value = normalize_ip_network(value)
    elif kind in {RuleKind.GEOIP, RuleKind.GEOSITE}:
        value = value.lower()
    return _rule(
        kind,
        value,
        action,
        source_id,
        line,
        raw,
        sha256,
        attributes=attributes,
        protected=protected,
    )


def parse_mihomo_domain_line(
    raw: str,
    *,
    source_id: str,
    line: int,
    sha256: str,
    action: Action,
    protected: bool = False,
) -> Rule:
    kind, value = classify_mihomo_domain(raw)
    return _rule(kind, value, action, source_id, line, raw, sha256, protected=protected)


def _meaningful_lines(text: str) -> Iterable[tuple[int, str]]:
    for line_number, raw_line in enumerate(text.replace("\r\n", "\n").split("\n"), start=1):
        stripped = raw_line.strip().lstrip("\ufeff")
        if not stripped or stripped.startswith(("#", ";")):
            continue
        yield line_number, stripped


def _yaml_payload(text: str) -> list[Any]:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ParseError(f"invalid YAML: {exc}") from exc
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("payload", "rules"):
            value = document.get(key)
            if isinstance(value, list):
                return value
    raise ParseError("YAML source must be a list or contain a payload/rules list")


def _parse_lines(
    lines: Iterable[tuple[int, str]],
    parser: Any,
    *,
    source_id: str,
    sha256: str,
    action: Action,
    strict: bool,
    protected: bool,
) -> ParseResult:
    rules: list[Rule] = []
    rejected: list[RejectedLine] = []
    meaningful = 0
    for line_number, raw in lines:
        meaningful += 1
        if raw in {"payload:", "rules:", "[Adblock Plus]"}:
            continue
        try:
            rules.append(
                parser(
                    raw,
                    source_id=source_id,
                    line=line_number,
                    sha256=sha256,
                    action=action,
                    protected=protected,
                )
            )
        except ParseError as exc:
            rejected.append(RejectedLine(source_id, line_number, raw, str(exc)))
    if strict and rejected:
        preview = "; ".join(f"L{item.line}: {item.reason}" for item in rejected[:5])
        raise ParseError(f"{source_id}: {len(rejected)} unsupported lines ({preview})")
    return ParseResult(rules=rules, rejected=rejected, meaningful_lines=meaningful)


def parse_classical(
    text: str,
    *,
    source_id: str,
    sha256: str,
    action: Action,
    strict: bool,
    yaml_container: bool,
    protected: bool = False,
) -> ParseResult:
    lines: Iterable[tuple[int, str]]
    if yaml_container:
        payload = _yaml_payload(text)
        lines = ((index, str(value).strip()) for index, value in enumerate(payload, start=1))
    else:
        lines = _meaningful_lines(text)
    return _parse_lines(
        lines,
        parse_classical_line,
        source_id=source_id,
        sha256=sha256,
        action=action,
        strict=strict,
        protected=protected,
    )


def parse_mihomo_domain(
    text: str,
    *,
    source_id: str,
    sha256: str,
    action: Action,
    strict: bool,
    yaml_container: bool,
    protected: bool = False,
) -> ParseResult:
    lines: Iterable[tuple[int, str]]
    if yaml_container:
        payload = _yaml_payload(text)
        lines = ((index, str(value).strip()) for index, value in enumerate(payload, start=1))
    else:
        lines = _meaningful_lines(text)
    return _parse_lines(
        lines,
        parse_mihomo_domain_line,
        source_id=source_id,
        sha256=sha256,
        action=action,
        strict=strict,
        protected=protected,
    )


def parse_mihomo_ipcidr(
    text: str,
    *,
    source_id: str,
    sha256: str,
    action: Action,
    strict: bool,
    yaml_container: bool,
    protected: bool = False,
) -> ParseResult:
    payload = _yaml_payload(text) if yaml_container else None
    lines = (
        ((index, str(value).strip()) for index, value in enumerate(payload, start=1))
        if payload is not None
        else _meaningful_lines(text)
    )
    rules: list[Rule] = []
    rejected: list[RejectedLine] = []
    meaningful = 0
    for line_number, raw in lines:
        meaningful += 1
        try:
            value = normalize_ip_network(raw)
            rules.append(
                _rule(
                    RuleKind.IP_CIDR,
                    value,
                    action,
                    source_id,
                    line_number,
                    raw,
                    sha256,
                    protected=protected,
                )
            )
        except ParseError as exc:
            rejected.append(RejectedLine(source_id, line_number, raw, str(exc)))
    if strict and rejected:
        raise ParseError(f"{source_id}: {len(rejected)} invalid IP/CIDR lines")
    return ParseResult(rules, rejected, meaningful)


def _split_adguard_modifiers(raw: str) -> tuple[str, tuple[str, ...]]:
    pattern = raw
    modifier_text = ""
    if raw.startswith("/"):
        closing = raw.rfind("/")
        if closing > 0 and closing + 1 < len(raw) and raw[closing + 1] == "$":
            pattern, modifier_text = raw[: closing + 1], raw[closing + 2 :]
    elif "$" in raw:
        pattern, modifier_text = raw.split("$", 1)
    modifiers = tuple(item.strip() for item in modifier_text.split(",") if item.strip())
    unknown = {
        item.split("=", 1)[0].removeprefix("~").lower()
        for item in modifiers
        if item.split("=", 1)[0].removeprefix("~").lower() not in SUPPORTED_ADGUARD_MODIFIERS
    }
    if unknown:
        raise ParseError(f"unsupported AdGuard modifiers: {', '.join(sorted(unknown))}")
    return pattern, tuple(f"adguard:{item}" for item in modifiers)


def _normalize_adguard_regex(pattern: str) -> str:
    """Return a validated regex body from standard or legacy AdGuard syntax.

    A small number of long-lived PCDN lists use ``/pattern^`` instead of the
    standard ``/pattern/`` delimiter pair.  In that legacy form the trailing
    unescaped caret is a delimiter typo, not a useful end-of-line assertion.
    Accept it explicitly so the source remains auditable without weakening the
    strict handling of any other unknown line shape.
    """

    standard_delimiters = pattern.startswith("/") and pattern.endswith("/")
    legacy_delimiters = (
        pattern.startswith("/") and pattern.endswith("^") and not pattern.endswith(r"\^")
    )
    if standard_delimiters or legacy_delimiters:
        value = pattern[1:-1]
    else:
        raise ParseError("invalid AdGuard regular expression delimiters")
    if not value:
        raise ParseError("empty AdGuard regular expression")
    try:
        re.compile(value)
    except re.error as exc:
        raise ParseError(f"invalid AdGuard regular expression {value!r}: {exc}") from exc
    return value


def parse_adguard(
    text: str,
    *,
    source_id: str,
    sha256: str,
    default_action: Action,
    strict: bool,
    whole_source_allowlist: bool = False,
) -> ParseResult:
    rules: list[Rule] = []
    rejected: list[RejectedLine] = []
    meaningful = 0
    for line_number, raw in _meaningful_lines(text):
        if raw.startswith("!") or raw == "[Adblock Plus]":
            continue
        meaningful += 1
        action = Action.ALLOW if whole_source_allowlist else default_action
        candidate = raw
        if candidate.startswith("@@"):
            action = Action.ALLOW
            candidate = candidate[2:]
        try:
            pattern, attributes = _split_adguard_modifiers(candidate)
            if pattern.startswith("||"):
                body = pattern[2:-1] if pattern.endswith("^") else pattern[2:]
                value = normalize_domain(body)
                kind = RuleKind.DOMAIN_SUFFIX
            elif pattern.startswith("|"):
                body = pattern[1:-1] if pattern.endswith("^") else pattern[1:]
                value = normalize_domain(body)
                kind = RuleKind.DOMAIN
            elif pattern.startswith("/"):
                value = _normalize_adguard_regex(pattern)
                kind = RuleKind.DOMAIN_REGEX
            else:
                host_parts = pattern.split()
                if len(host_parts) >= 2:
                    ipaddress.ip_address(host_parts[0])
                    for host in host_parts[1:]:
                        rules.append(
                            _rule(
                                RuleKind.DOMAIN,
                                normalize_domain(host),
                                action,
                                source_id,
                                line_number,
                                raw,
                                sha256,
                                attributes=attributes,
                            )
                        )
                    continue
                kind, value = classify_mihomo_domain(pattern)
            rules.append(
                _rule(
                    kind,
                    value,
                    action,
                    source_id,
                    line_number,
                    raw,
                    sha256,
                    attributes=attributes,
                )
            )
        except (ParseError, ValueError) as exc:
            reason = str(exc)
            ignored = reason.startswith("unsupported AdGuard modifiers")
            rejected.append(RejectedLine(source_id, line_number, raw, reason, ignored))
    fatal = [item for item in rejected if not item.ignored_by_spec]
    if strict and fatal:
        raise ParseError(f"{source_id}: {len(fatal)} unknown AdGuard lines")
    return ParseResult(rules, rejected, meaningful)


def parse_plain(
    text: str,
    *,
    source_id: str,
    sha256: str,
    action: Action,
    strict: bool,
    mode: str = "auto",
) -> ParseResult:
    rules: list[Rule] = []
    rejected: list[RejectedLine] = []
    meaningful = 0
    for line_number, raw in _meaningful_lines(text):
        meaningful += 1
        try:
            if mode == "ip":
                rules.append(
                    _rule(
                        RuleKind.IP_CIDR,
                        normalize_ip_network(raw),
                        action,
                        source_id,
                        line_number,
                        raw,
                        sha256,
                    )
                )
                continue
            if "," in raw and raw.split(",", 1)[0].strip().upper() in CLASSICAL_KIND_MAP:
                rules.append(
                    parse_classical_line(
                        raw,
                        source_id=source_id,
                        line=line_number,
                        sha256=sha256,
                        action=action,
                    )
                )
                continue
            fields = raw.split()
            if len(fields) >= 2:
                try:
                    ipaddress.ip_address(fields[0])
                except ValueError:
                    pass
                else:
                    for host in fields[1:]:
                        rules.append(
                            _rule(
                                RuleKind.DOMAIN,
                                normalize_domain(host),
                                action,
                                source_id,
                                line_number,
                                raw,
                                sha256,
                            )
                        )
                    continue
            if mode != "domain":
                try:
                    network = normalize_ip_network(raw)
                except ParseError:
                    pass
                else:
                    rules.append(
                        _rule(
                            RuleKind.IP_CIDR,
                            network,
                            action,
                            source_id,
                            line_number,
                            raw,
                            sha256,
                        )
                    )
                    continue
            rules.append(
                parse_mihomo_domain_line(
                    raw,
                    source_id=source_id,
                    line=line_number,
                    sha256=sha256,
                    action=action,
                )
            )
        except ParseError as exc:
            rejected.append(RejectedLine(source_id, line_number, raw, str(exc)))
    if strict and rejected:
        raise ParseError(f"{source_id}: {len(rejected)} unknown plain-list lines")
    return ParseResult(rules, rejected, meaningful)


def _walk_xray_rules(document: Any) -> Iterable[dict[str, Any]]:
    if isinstance(document, dict):
        routing = document.get("routing")
        if isinstance(routing, dict) and isinstance(routing.get("rules"), list):
            yield from (item for item in routing["rules"] if isinstance(item, dict))
        if isinstance(document.get("rules"), list):
            yield from (item for item in document["rules"] if isinstance(item, dict))
    elif isinstance(document, list):
        yield from (item for item in document if isinstance(item, dict))


def parse_xray_json(
    text: str,
    *,
    source_id: str,
    sha256: str,
    action: Action,
    strict: bool,
) -> ParseResult:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid Xray JSON: {exc}") from exc
    rules: list[Rule] = []
    rejected: list[RejectedLine] = []
    line = 0
    for route_rule in _walk_xray_rules(document):
        for raw_domain in route_rule.get("domain", []):
            line += 1
            raw = str(raw_domain)
            lower = raw.lower()
            try:
                if lower.startswith("geosite:"):
                    kind, value = RuleKind.GEOSITE, raw.split(":", 1)[1].lower()
                elif lower.startswith("ext:"):
                    kind, value = RuleKind.OPAQUE_DOMAIN, raw
                else:
                    kind, value = classify_mihomo_domain(raw)
                    if not any(
                        lower.startswith(prefix)
                        for prefix in ("full:", "domain:", "keyword:", "regexp:")
                    ):
                        kind = RuleKind.DOMAIN_KEYWORD
                rules.append(_rule(kind, value, action, source_id, line, raw, sha256))
            except ParseError as exc:
                rejected.append(RejectedLine(source_id, line, raw, str(exc)))
        for raw_ip in route_rule.get("ip", []):
            line += 1
            raw = str(raw_ip)
            try:
                if raw.lower().startswith("geoip:"):
                    rules.append(
                        _rule(
                            RuleKind.GEOIP,
                            raw.split(":", 1)[1].lower(),
                            action,
                            source_id,
                            line,
                            raw,
                            sha256,
                        )
                    )
                else:
                    rules.append(
                        _rule(
                            RuleKind.IP_CIDR,
                            normalize_ip_network(raw),
                            action,
                            source_id,
                            line,
                            raw,
                            sha256,
                        )
                    )
            except ParseError as exc:
                rejected.append(RejectedLine(source_id, line, raw, str(exc)))
    if strict and rejected:
        raise ParseError(f"{source_id}: {len(rejected)} invalid Xray rules")
    return ParseResult(rules, rejected, line)


def parse_xray_domain_list(
    text: str,
    *,
    source_id: str,
    sha256: str,
    action: Action,
    strict: bool,
) -> ParseResult:
    return parse_mihomo_domain(
        text,
        source_id=source_id,
        sha256=sha256,
        action=action,
        strict=strict,
        yaml_container=False,
    )
