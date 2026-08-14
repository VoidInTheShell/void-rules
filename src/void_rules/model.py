from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any


class RuleKind(StrEnum):
    DOMAIN = "domain"
    DOMAIN_SUFFIX = "domain_suffix"
    DOMAIN_KEYWORD = "domain_keyword"
    DOMAIN_REGEX = "domain_regex"
    DOMAIN_WILDCARD = "domain_wildcard"
    OPAQUE_DOMAIN = "opaque_domain"
    IP_CIDR = "ip_cidr"
    SRC_IP_CIDR = "src_ip_cidr"
    GEOIP = "geoip"
    GEOSITE = "geosite"
    DST_PORT = "dst_port"
    SRC_PORT = "src_port"
    PROCESS_NAME = "process_name"
    PROCESS_PATH = "process_path"
    NETWORK = "network"
    OPAQUE_CLASSICAL = "opaque_classical"


class Action(StrEnum):
    MATCH = "match"
    BLOCK = "block"
    ALLOW = "allow"
    FAKE_IP_FORCE = "fake_ip_force"
    FAKE_IP_BYPASS = "fake_ip_bypass"


DOMAIN_KINDS = frozenset(
    {
        RuleKind.DOMAIN,
        RuleKind.DOMAIN_SUFFIX,
        RuleKind.DOMAIN_KEYWORD,
        RuleKind.DOMAIN_REGEX,
        RuleKind.DOMAIN_WILDCARD,
        RuleKind.OPAQUE_DOMAIN,
    }
)
IP_KINDS = frozenset({RuleKind.IP_CIDR, RuleKind.SRC_IP_CIDR})


@dataclass(frozen=True, slots=True, order=True)
class Provenance:
    source_id: str
    line: int = 0
    sha256: str = ""
    evidence: str = ""
    raw: str = ""

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"source_id": self.source_id}
        if self.line:
            data["line"] = self.line
        if self.sha256:
            data["sha256"] = self.sha256
        if self.evidence:
            data["evidence"] = self.evidence
        if self.raw:
            data["raw"] = self.raw
        return data


@dataclass(frozen=True, slots=True)
class Rule:
    kind: RuleKind
    value: str
    action: Action = Action.MATCH
    attributes: tuple[str, ...] = ()
    provenance: tuple[Provenance, ...] = ()
    protected: bool = False

    @property
    def semantic_key(self) -> tuple[str, str, str, tuple[str, ...]]:
        return (self.kind.value, self.value, self.action.value, self.attributes)

    @property
    def content_key(self) -> tuple[str, str, tuple[str, ...]]:
        return (self.kind.value, self.value, self.attributes)

    def with_action(self, action: Action) -> Rule:
        return replace(self, action=action)

    def with_protected(self, protected: bool = True) -> Rule:
        return replace(self, protected=protected)

    def merge_provenance(self, other: Rule) -> Rule:
        if self.semantic_key != other.semantic_key:
            raise ValueError("cannot merge rules with different semantic identities")
        provenance = tuple(sorted(set(self.provenance + other.provenance)))
        return replace(self, provenance=provenance, protected=self.protected or other.protected)

    def as_dict(self, *, include_provenance: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "kind": self.kind.value,
            "value": self.value,
            "action": self.action.value,
        }
        if self.attributes:
            data["attributes"] = list(self.attributes)
        if self.protected:
            data["protected"] = True
        if include_provenance and self.provenance:
            data["provenance"] = [item.as_dict() for item in self.provenance]
        return data


@dataclass(frozen=True, slots=True)
class RejectedLine:
    source_id: str
    line: int
    raw: str
    reason: str
    ignored_by_spec: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "line": self.line,
            "raw": self.raw,
            "reason": self.reason,
            "ignored_by_spec": self.ignored_by_spec,
        }


@dataclass(slots=True)
class ParseResult:
    rules: list[Rule]
    rejected: list[RejectedLine]
    meaningful_lines: int = 0


def deduplicate_rules(rules: list[Rule]) -> list[Rule]:
    merged: dict[tuple[str, str, str, tuple[str, ...]], Rule] = {}
    for rule in rules:
        key = rule.semantic_key
        existing = merged.get(key)
        merged[key] = rule if existing is None else existing.merge_provenance(rule)
    return sorted(
        merged.values(),
        key=lambda item: (item.kind.value, item.value, item.action.value, item.attributes),
    )
