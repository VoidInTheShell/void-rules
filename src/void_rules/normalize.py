from __future__ import annotations

import ipaddress
import re

import idna

from .errors import ParseError
from .model import RuleKind

ASCII_DOMAINISH = re.compile(r"^[A-Za-z0-9_.*+?\-]+(?:\.[A-Za-z0-9_.*+?\-]+)*$")


def _idna_label(label: str) -> str:
    if label in {"*", "+", "?"} or any(char in label for char in "*+?"):
        return label.lower()
    if label.startswith("_"):
        return label.lower()
    return idna.encode(label, uts46=True).decode("ascii").lower()


def normalize_domain(value: str, *, allow_special: bool = False) -> str:
    value = value.strip().rstrip(".")
    if not value:
        raise ParseError("empty domain value")
    if allow_special and any(char.isspace() for char in value):
        return value
    prefix = ""
    body = value
    if value.startswith("+."):
        prefix, body = "+.", value[2:]
    elif value.startswith("."):
        prefix, body = ".", value[1:]
    try:
        normalized = ".".join(_idna_label(label) for label in body.split("."))
    except idna.IDNAError as exc:
        if ASCII_DOMAINISH.fullmatch(body):
            normalized = body.lower()
        else:
            raise ParseError(f"invalid domain {value!r}: {exc}") from exc
    if (
        not ASCII_DOMAINISH.fullmatch(normalized)
        or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in normalized.split(".")
        )
        or len(normalized) > 253
    ):
        raise ParseError(f"invalid domain {value!r}")
    return prefix + normalized


def normalize_literal_domain(value: str) -> str:
    """An exact/suffix rule is a hostname, not a wildcard expression."""
    normalized = normalize_domain(value)
    if normalized.startswith(".") or any(char in normalized for char in "*+?"):
        raise ParseError(f"wildcards are not valid in a literal domain: {value!r}")
    return normalized


def normalize_domain_regex(value: str) -> str:
    """Validate the portable RE2 subset used by the supported DNS/routing cores."""
    if not value or "\n" in value or "\r" in value:
        raise ParseError("empty or multiline domain regular expression")
    if (
        re.search(r"\(\?(?:[=!#]|<[=!]|>|\(|[aLuxt])|\\[1-9ZNuU]|\(\?P=", value)
        or re.search(r"(?<!\\)(?:[*+?]|\{\d+(?:,\d*)?\})\+", value)
        or any(
            any(flag in flags for flag in "aLux")
            for flags in re.findall(r"\(\?([aiLmsux-]+)(?:\)|:)", value)
        )
        or any(
            int(number) > 1000
            for repeat in re.findall(r"(?<!\\)\{(\d+)(?:,(\d*))?\}", value)
            for number in repeat
            if number
        )
    ):
        raise ParseError("domain regex uses unsupported RE2 features")
    try:
        re.compile(value)
    except re.error as exc:
        raise ParseError(f"invalid domain regular expression: {exc}") from exc
    return value


def adguard_host_pattern(value: str, *, suffix: bool) -> tuple[RuleKind, str]:
    """Preserve host-glob semantics; AdGuard * can span characters and labels."""
    normalized = normalize_domain(value)
    if normalized.startswith(".") or any(char in normalized for char in "+?"):
        raise ParseError(f"invalid AdGuard host pattern: {value!r}")
    if "*" not in normalized:
        return (RuleKind.DOMAIN_SUFFIX if suffix else RuleKind.DOMAIN), normalized
    if normalized.startswith("*.") and normalized.count("*") == 1:
        # Any nonempty subdomain depth, never the apex. This is losslessly
        # expressible in Mihomo as a leading-dot domain wildcard.
        return RuleKind.DOMAIN_WILDCARD, "." + normalized[2:]
    prefix = r"(?:[^.]+\.)*" if suffix else ""
    body = ".*".join(re.escape(part) for part in normalized.split("*"))
    return RuleKind.DOMAIN_REGEX, normalize_domain_regex(f"^{prefix}{body}$")


def normalize_ip_network(value: str) -> str:
    raw = value.strip()
    try:
        if "/" not in raw:
            address = ipaddress.ip_address(raw)
            raw = f"{address}/{address.max_prefixlen}"
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError as exc:
        raise ParseError(f"invalid IP/CIDR {value!r}") from exc


def classify_mihomo_domain(value: str) -> tuple[RuleKind, str]:
    raw = value.strip().strip("'\"")
    lower = raw.lower()
    prefixes: tuple[tuple[str, RuleKind], ...] = (
        ("full:", RuleKind.DOMAIN),
        ("domain:", RuleKind.DOMAIN_SUFFIX),
        ("keyword:", RuleKind.DOMAIN_KEYWORD),
        ("regexp:", RuleKind.DOMAIN_REGEX),
        ("regex:", RuleKind.DOMAIN_REGEX),
    )
    for prefix, kind in prefixes:
        if lower.startswith(prefix):
            value = raw[len(prefix) :].strip()
            if not value:
                raise ParseError(f"empty {prefix} rule")
            if kind in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
                value = normalize_literal_domain(value)
            elif kind is RuleKind.DOMAIN_REGEX:
                value = normalize_domain_regex(value)
            return kind, value
    if any(char.isspace() for char in raw):
        return RuleKind.OPAQUE_DOMAIN, normalize_domain(raw, allow_special=True)
    _validate_mihomo_wildcard(raw)
    if raw.startswith("+.") and not any(char in raw[2:] for char in "*?"):
        return RuleKind.DOMAIN_SUFFIX, normalize_domain(raw[2:])
    if "*" in raw or raw.startswith(("+.", ".")):
        return RuleKind.DOMAIN_WILDCARD, normalize_domain(raw)
    return RuleKind.DOMAIN, normalize_domain(raw)


def _validate_mihomo_wildcard(pattern: str) -> None:
    body = pattern.removeprefix("+.").removeprefix(".")
    if (
        "?" in body
        or "+" in body
        or any("*" in label and label != "*" for label in body.split("."))
    ):
        raise ParseError(
            f"unsupported Mihomo domain wildcard {pattern!r}: "
            "use whole-label * and leading . or +.; use regex for character patterns"
        )


def wildcard_to_regex(pattern: str) -> str:
    """Match Mihomo's label trie: . excludes the apex, +. includes it."""
    _validate_mihomo_wildcard(pattern)
    raw = normalize_domain(pattern)
    suffix_any_depth = raw.startswith("+.")
    subdomains_only = raw.startswith(".")
    if suffix_any_depth:
        raw = raw[2:]
    elif subdomains_only:
        raw = raw[1:]
    body = r"\.".join(r"[^.]+" if label == "*" else re.escape(label) for label in raw.split("."))
    prefix = r"(?:[^.]+\.)*" if suffix_any_depth else r"(?:[^.]+\.)+" if subdomains_only else ""
    return f"^{prefix}{body}$"
