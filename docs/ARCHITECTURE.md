# Architecture

## Pipeline

```text
registered sources
       |
       v
download + content guards ----> source lock + immutable cache
       |
       v
format adapters (strict) -----> normalized rules + provenance
       |
       v
recipe union -> include -> exclude -> conflict policy -> assertions
       |
       v
render capability filter -----> outputs + compatibility report
       |
       v
round-trip validation --------> dist + manifest + delta gate
```

## Canonical rule model

Each normalized rule carries:

- `kind`: domain, domain_suffix, domain_keyword, domain_regex, domain_wildcard, ip_cidr, source_ip_cidr, geoip, geosite, process, port or opaque classical.
- `value`: normalized semantic value, never a rendered client string.
- `action`: match, block, allow, fake_ip_force or fake_ip_bypass.
- `attributes`: source-specific flags such as AdGuard modifiers or V2Ray geosite attributes.
- `source_id`, source line, source digest and discovery evidence.
- `protected`: whether the rule came from a local overlay/assertion.

Identity is based on semantic kind, normalized value, action and relevant attributes. A suffix does not automatically delete covered exact domains: coverage compression is an explicit renderer option because provenance, exceptions and client semantics can differ.

## Ordering and precedence

1. Registered upstream rules are unioned.
2. Local `include` rules are added and marked protected.
3. Local `exclude` selectors remove matching upstream rules. Removing a protected include requires an explicit protected exclusion.
4. Cross-ruleset policies run. Fake-IP bypass wins over force for effective output, but an unresolved overlap is still a build error unless listed in the conflict-resolution overlay.
5. Required/forbidden assertions run against the effective set.
6. Renderers select only representable kinds and report every omission.

## Source adapters

Auto-detection is conservative. Strong signatures such as MRS magic, protobuf DAT selected by catalog, JSON/YAML roots and AdGuard markers are evaluated before plain-line heuristics. Ambiguous sources require an explicit format.

Binary MRS is decoded by a pinned official Mihomo release. DAT is decoded by the repository Go codec using the V2Ray protobuf messages. Archive extraction is optional and restricted to catalog-declared members with size/path guards.

## Discovery

Discovery produces candidates with evidence; it does not edit recipes or overlays. Candidate identity is stable so rejected items remain rejected across future runs. Policies can auto-promote only when all configured gates pass, for example:

- the candidate is inside an approved official registrable domain;
- the same normalized rule appears in at least two independent vetted sources; or
- a reviewed source adapter marks a JSON/API field authoritative.

New repositories, new executable code, redirects to a new host, HTML selector changes and large source deltas always require review.

## Reproducibility

The lock records final URL, ETag/Last-Modified when present, byte size, SHA-256, parser, parsed/rejected counts and upstream commit/release metadata when available. Given the same locked blobs, catalog, recipes, overlays and tool versions, `sync --offline` must reproduce `dist/` byte for byte. Generated files use LF, stable sorting and no wall-clock timestamp in content hashes.

## Automation boundary

Scheduled synchronization runs strict parsing, assertions, native MRS/DAT round trips and all tests before publication. `ci-decision` permits a direct update only when the build has no review flag, discovery candidates are unchanged and no more than 40 generated files changed. Candidate changes, anomaly gates and broad updates use the `automation/rules-sync` review pull request.

Both publication paths stage only `dist/` and `generated/`. Changes to `catalog/`, `recipes/`, `overlays/`, `schemas/`, source code or tests fail the automation job instead of being committed.
