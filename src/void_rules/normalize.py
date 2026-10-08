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
    return prefix + normalized


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
                value = normalize_domain(value)
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
    raw = pattern.lower()
    suffix_any_depth = raw.startswith("+.")
    subdomains_only = raw.startswith(".")
    if suffix_any_depth:
        raw = raw[2:]
    elif subdomains_only:
        raw = raw[1:]
    body = r"\.".join(r"[^.]+" if label == "*" else re.escape(label) for label in raw.split("."))
    prefix = r"(?:[^.]+\.)*" if suffix_any_depth else r"(?:[^.]+\.)+" if subdomains_only else ""
    return f"^{prefix}{body}$"
