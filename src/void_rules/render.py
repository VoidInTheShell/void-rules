from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

import yaml

from .artifacts import deterministic_gzip
from .codecs import GeodataCodec, MihomoCodec
from .errors import CodecError
from .model import DOMAIN_KINDS, IP_KINDS, Action, Rule, RuleKind
from .normalize import wildcard_to_regex


@dataclass(frozen=True, slots=True)
class RenderedFile:
    name: str
    data: bytes
    represented: int
    skipped: tuple[dict[str, str], ...]
    compacted: int = 0

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def _yaml_payload(values: list[str]) -> bytes:
    rendered = yaml.safe_dump(
        {"payload": values},
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=4096,
    )
    if not isinstance(rendered, str):
        raise CodecError("YAML renderer returned non-text output")
    return rendered.encode()


def _text(values: list[str], header: list[str] | None = None) -> bytes:
    lines = [*(header or []), *values]
    return (("\n".join(lines) + "\n") if lines else "").encode()


def _main_rules(rules: list[Rule], recipe_action: Action) -> list[Rule]:
    if recipe_action is Action.BLOCK:
        return [rule for rule in rules if rule.action is Action.BLOCK]
    if recipe_action is Action.ALLOW:
        return [rule for rule in rules if rule.action is Action.ALLOW]
    return [rule for rule in rules if rule.action not in {Action.BLOCK, Action.ALLOW}]


def _classical_value(rule: Rule) -> str | None:
    mapping = {
        RuleKind.DOMAIN: "DOMAIN",
        RuleKind.DOMAIN_SUFFIX: "DOMAIN-SUFFIX",
        RuleKind.DOMAIN_KEYWORD: "DOMAIN-KEYWORD",
        RuleKind.DOMAIN_REGEX: "DOMAIN-REGEX",
        RuleKind.IP_CIDR: "IP-CIDR6" if ":" in rule.value else "IP-CIDR",
        RuleKind.SRC_IP_CIDR: "SRC-IP-CIDR6" if ":" in rule.value else "SRC-IP-CIDR",
        RuleKind.GEOIP: "GEOIP",
        RuleKind.GEOSITE: "GEOSITE",
        RuleKind.DST_PORT: "DST-PORT",
        RuleKind.SRC_PORT: "SRC-PORT",
        RuleKind.PROCESS_NAME: "PROCESS-NAME",
        RuleKind.PROCESS_PATH: "PROCESS-PATH",
        RuleKind.NETWORK: "NETWORK",
    }
    if rule.kind is RuleKind.DOMAIN_WILDCARD:
        base = f"DOMAIN-REGEX,{wildcard_to_regex(rule.value)}"
    elif rule.kind is RuleKind.OPAQUE_CLASSICAL:
        return rule.value
    elif rule.kind is RuleKind.OPAQUE_DOMAIN:
        return None
    else:
        prefix = mapping.get(rule.kind)
        if prefix is None:
            return None
        base = f"{prefix},{rule.value}"
    if "no-resolve" in rule.attributes and rule.kind in IP_KINDS:
        base += ",no-resolve"
    return base


def _domain_value(rule: Rule) -> str | None:
    if rule.kind is RuleKind.DOMAIN:
        return rule.value
    if rule.kind is RuleKind.DOMAIN_SUFFIX:
        return "+." + rule.value
    if rule.kind is RuleKind.DOMAIN_WILDCARD:
        return rule.value
    return None


def _ip_value(rule: Rule) -> str | None:
    return rule.value if rule.kind is RuleKind.IP_CIDR else None


def _xray_domain_value(rule: Rule) -> str | None:
    if rule.kind is RuleKind.DOMAIN:
        return "full:" + rule.value
    if rule.kind is RuleKind.DOMAIN_SUFFIX:
        return "domain:" + rule.value
    if rule.kind is RuleKind.DOMAIN_KEYWORD:
        return "keyword:" + rule.value
    if rule.kind is RuleKind.DOMAIN_REGEX:
        return "regexp:" + rule.value
    if rule.kind is RuleKind.DOMAIN_WILDCARD:
        return "regexp:" + wildcard_to_regex(rule.value)
    return None


def _adguard_value(rule: Rule, *, allow: bool) -> str | None:
    if rule.kind is RuleKind.DOMAIN:
        value = "|" + rule.value + "^"
    elif rule.kind is RuleKind.DOMAIN_SUFFIX:
        value = "||" + rule.value + "^"
    elif rule.kind is RuleKind.DOMAIN_KEYWORD:
        value = "*" + rule.value + "*"
    elif rule.kind is RuleKind.DOMAIN_REGEX:
        value = "/" + rule.value + "/"
    elif rule.kind is RuleKind.DOMAIN_WILDCARD:
        value = rule.value.removeprefix("+.")
    else:
        return None
    modifiers = [
        item.removeprefix("adguard:") for item in rule.attributes if item.startswith("adguard:")
    ]
    if modifiers:
        value += "$" + ",".join(modifiers)
    return ("@@" if allow else "") + value


def _render_mapped(
    name: str,
    rules: list[Rule],
    mapper: Any,
    *,
    yaml_output: bool,
) -> RenderedFile:
    values: list[str] = []
    skipped: list[dict[str, str]] = []
    for rule in rules:
        value = mapper(rule)
        if value is None:
            skipped.append(
                {"kind": rule.kind.value, "value": rule.value, "reason": "not representable"}
            )
        else:
            values.append(value)
    values = sorted(set(values), key=lambda value: value.casefold())
    data = _yaml_payload(values) if yaml_output else _text(values)
    return RenderedFile(name, data, len(values), tuple(skipped))


def _compact_mrs_domain_source(source: RenderedFile) -> tuple[bytes, int]:
    """Remove only exact names proven redundant with the same ``+.`` suffix.

    Mihomo's domain trie performs this lossless compaction internally.  Doing
    it before encoding lets the subsequent decode comparison remain strict:
    every physical MRS entry must round-trip exactly, while the manifest still
    reports the full number of semantically represented input rules.
    """

    values = set(source.data.decode().splitlines())
    suffix_roots = {value[2:] for value in values if value.startswith("+.")}
    redundant_exact = {
        value for value in values if value in suffix_roots and not value.startswith("+.")
    }
    compacted = values - redundant_exact
    ordered = sorted(compacted, key=lambda value: value.casefold())
    return _text(ordered), len(redundant_exact)


def render_outputs(
    ruleset_id: str,
    rules: list[Rule],
    recipe_action: Action,
    outputs: tuple[str, ...],
    *,
    root: Any,
    skip_binary: bool = False,
) -> dict[str, RenderedFile]:
    rendered: dict[str, RenderedFile] = {}
    main = _main_rules(rules, recipe_action)

    for output in outputs:
        if output == "jsonl":
            lines = [
                json.dumps(
                    rule.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                for rule in rules
            ]
            rendered[output] = RenderedFile(
                "rules.jsonl.gz",
                deterministic_gzip(_text(lines)),
                len(lines),
                (),
            )
        elif output == "plain-domain":
            rendered[output] = _render_mapped(
                "plain-domain.txt", main, _domain_value, yaml_output=False
            )
        elif output == "plain-ip":
            rendered[output] = _render_mapped("plain-ip.txt", main, _ip_value, yaml_output=False)
        elif output == "mihomo-classical-yaml":
            rendered[output] = _render_mapped(
                "mihomo-classical.yaml", main, _classical_value, yaml_output=True
            )
        elif output == "mihomo-classical-text":
            rendered[output] = _render_mapped(
                "mihomo-classical.list", main, _classical_value, yaml_output=False
            )
        elif output == "mihomo-domain-yaml":
            rendered[output] = _render_mapped(
                "mihomo-domain.yaml", main, _domain_value, yaml_output=True
            )
        elif output == "mihomo-domain-text":
            rendered[output] = _render_mapped(
                "mihomo-domain.list", main, _domain_value, yaml_output=False
            )
        elif output == "mihomo-ipcidr-yaml":
            rendered[output] = _render_mapped(
                "mihomo-ipcidr.yaml", main, _ip_value, yaml_output=True
            )
        elif output == "mihomo-ipcidr-text":
            rendered[output] = _render_mapped(
                "mihomo-ipcidr.list", main, _ip_value, yaml_output=False
            )
        elif output == "adguard-block":
            block = [rule for rule in rules if rule.action is Action.BLOCK]
            mapped = _render_mapped(
                "adguard-block.txt",
                block,
                lambda item: _adguard_value(item, allow=False),
                yaml_output=False,
            )
            header = ["! Generated by void-rules", f"! Ruleset: {ruleset_id}"]
            rendered[output] = RenderedFile(
                mapped.name,
                _text(mapped.data.decode().splitlines(), header),
                mapped.represented,
                mapped.skipped,
            )
        elif output == "adguard-allow":
            allow_rules = [rule for rule in rules if rule.action is Action.ALLOW]
            mapped = _render_mapped(
                "adguard-allow.txt",
                allow_rules,
                lambda item: _adguard_value(item, allow=True),
                yaml_output=False,
            )
            header = ["! Generated by void-rules", f"! Ruleset: {ruleset_id}"]
            rendered[output] = RenderedFile(
                mapped.name,
                _text(mapped.data.decode().splitlines(), header),
                mapped.represented,
                mapped.skipped,
            )
        elif output == "xray-domain-list":
            rendered[output] = _render_mapped(
                "xray-domain-list.txt", main, _xray_domain_value, yaml_output=False
            )

    if not skip_binary:
        mihomo = MihomoCodec(root)
        if "mihomo-domain-mrs" in outputs:
            source = rendered.get("mihomo-domain-text") or _render_mapped(
                "mihomo-domain.list", main, _domain_value, yaml_output=False
            )
            if source.represented:
                mrs_source, compacted = _compact_mrs_domain_source(source)
                data = mihomo.encode(mrs_source, "domain")
                domain_decoded = mihomo.decode(data, "domain")
                if set(domain_decoded.decode().splitlines()) != set(
                    mrs_source.decode().splitlines()
                ):
                    raise CodecError(f"{ruleset_id}: MRS domain round-trip mismatch")
                rendered["mihomo-domain-mrs"] = RenderedFile(
                    "mihomo-domain.mrs",
                    data,
                    source.represented,
                    source.skipped,
                    compacted,
                )
        if "mihomo-ipcidr-mrs" in outputs:
            source = rendered.get("mihomo-ipcidr-text") or _render_mapped(
                "mihomo-ipcidr.list", main, _ip_value, yaml_output=False
            )
            if source.represented:
                data = mihomo.encode(source.data, "ipcidr")
                ipcidr_decoded = mihomo.decode(data, "ipcidr")
                if set(ipcidr_decoded.decode().splitlines()) != set(
                    source.data.decode().splitlines()
                ):
                    raise CodecError(f"{ruleset_id}: MRS ipcidr round-trip mismatch")
                rendered["mihomo-ipcidr-mrs"] = RenderedFile(
                    "mihomo-ipcidr.mrs", data, source.represented, source.skipped
                )

        geodata = GeodataCodec(root)
        if "xray-geosite-dat" in outputs:
            geosite_records: list[dict[str, Any]] = []
            skipped: list[dict[str, str]] = []
            for rule in main:
                xray = _xray_domain_value(rule)
                if xray is None:
                    if rule.kind in DOMAIN_KINDS:
                        skipped.append(
                            {
                                "kind": rule.kind.value,
                                "value": rule.value,
                                "reason": "not representable",
                            }
                        )
                    continue
                prefix, value = xray.split(":", 1)
                kind_map = {
                    "full": "domain",
                    "domain": "domain_suffix",
                    "keyword": "domain_keyword",
                    "regexp": "domain_regex",
                }
                geosite_records.append(
                    {"tag": ruleset_id, "kind": kind_map[prefix], "value": value}
                )
            if geosite_records:
                geosite_data = geodata.encode(geosite_records, "geosite")
                geosite_decoded = geodata.decode(
                    geosite_data,
                    "geosite",
                    (ruleset_id,),
                )
                geosite_expected = {
                    (str(item["kind"]), str(item["value"])) for item in geosite_records
                }
                geosite_actual = {
                    (str(item["kind"]), str(item["value"])) for item in geosite_decoded
                }
                if geosite_expected != geosite_actual:
                    raise CodecError(f"{ruleset_id}: geosite DAT round-trip mismatch")
                rendered["xray-geosite-dat"] = RenderedFile(
                    "xray-geosite.dat",
                    geosite_data,
                    len(geosite_records),
                    tuple(skipped),
                )
        if "xray-geoip-dat" in outputs:
            geoip_records: list[dict[str, Any]] = [
                {"tag": ruleset_id, "kind": "ip_cidr", "value": rule.value}
                for rule in main
                if rule.kind is RuleKind.IP_CIDR
            ]
            if geoip_records:
                geoip_data = geodata.encode(geoip_records, "geoip")
                geoip_decoded = geodata.decode(geoip_data, "geoip", (ruleset_id,))
                geoip_expected = {str(item["value"]) for item in geoip_records}
                geoip_actual = {str(item["value"]) for item in geoip_decoded}
                if geoip_expected != geoip_actual:
                    raise CodecError(f"{ruleset_id}: geoip DAT round-trip mismatch")
                rendered["xray-geoip-dat"] = RenderedFile(
                    "xray-geoip.dat",
                    geoip_data,
                    len(geoip_records),
                    (),
                )

    return rendered


def output_manifest(rendered: dict[str, RenderedFile]) -> dict[str, Any]:
    manifest: dict[str, Any] = {}
    for key, item in sorted(rendered.items()):
        record = {
            "path": item.name,
            "size": len(item.data),
            "sha256": item.sha256,
            "represented_rules": item.represented,
            "skipped_rules": len(item.skipped),
        }
        if item.compacted:
            record["compacted_rules"] = item.compacted
        manifest[key] = record
    return manifest


def rule_counts(rules: list[Rule]) -> dict[str, Any]:
    return {
        "total": len(rules),
        "by_kind": dict(sorted(Counter(rule.kind.value for rule in rules).items())),
        "by_action": dict(sorted(Counter(rule.action.value for rule in rules).items())),
        "protected": sum(1 for rule in rules if rule.protected),
    }
