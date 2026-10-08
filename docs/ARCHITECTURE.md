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

1. Registered upstream rules are unioned. A recipe's `filtered_sources` are first restricted to members matched by its unfiltered sources, local include rules or an explicit `source_filter`. The `stun-turn` filter selects existing rules with explicit STUN/TURN domain labels and recognized historical regex shapes; it does not synthesize wildcard rules or identify services by probing. This splits DustinWin, RFM, QuixoticHeart and ShellCrash into STUN while retaining their provenance, then deduplicates with MetaCubeX's category. Selection requires fresh inputs and reports selected/omitted counts. `review_unmatched_sources` stores unmatched items as a classification baseline and blocks new unmatched items before writing any artifacts. The count-only legacy baseline is migrated from checksum-verified bypass provenance. Unknown DustinWin additions cannot silently enter bypass or become accepted by rerunning a failed build.
2. Local `include` rules are added and marked protected.
3. Local `exclude` selectors remove matching upstream rules. `exclude_rulesets` adds exclusion-only dependencies: build them first, then remove matching members across all input sources. Exact kind/value matches, names under an excluded suffix and exact domains matched by excluded wildcard/regex/keyword rules are removed. This explicit exclusion also applies to protected entries and is reported. Broader parents remain; positive sets cannot encode a child exception. Exclusion dependencies require fresh sources, including their transitive dependencies.
4. Cross-ruleset policies run. Exact Fake-IP overlaps use the conflict-resolution overlay; an unreviewed overlap defaults to bypass and blocks publication. Domain/suffix coverage is reported separately in `fake_ip_conflicts.coverage_overlaps`, with both rules retained. Consumers apply bypass before force using the ordered DNS rules in [MIHOMO.md](MIHOMO.md); removing an exact child cannot override a force parent suffix.
5. Required/forbidden assertions run against the effective set.
6. Renderers select only representable kinds and report every omission.

## Source adapters

Auto-detection is conservative. Strong signatures such as MRS magic, protobuf DAT selected by catalog, JSON/YAML roots and AdGuard markers are evaluated before plain-line heuristics. Ambiguous sources require an explicit format. YAML containers are parsed in full rather than truncating their documents; entries must be nonempty strings. A YAML payload passed to the domain-text adapter is a fatal format error, including GFW-style list markers. Empty domain/keyword/regex expressions are rejected. Native Mihomo DNS tests check suffix, wildcard and single-label matching against the separation logic.

Binary MRS is decoded by a pinned official Mihomo release. DAT is decoded by the repository Go codec using the V2Ray protobuf messages. Archive extraction is optional and restricted to catalog-declared members with size/path guards.

Mihomo domain wildcards match whole labels: `*` matches one label, `.example.com` excludes the apex, and `+.example.com` includes it. Character globs such as `stun?.example` or `stun*.example` are rejected instead of inventing matching behavior. Classical/Xray regex conversions preserve these boundaries. For MRS round trips, `.example.com` is encoded as equivalent `+.*.example.com`, because the native text decoder otherwise prints a misleading `+.` prefix for a subdomains-only node. See the [pinned Mihomo trie implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.28/component/trie/domain.go).

## Discovery

Discovery produces candidates with evidence; it does not edit recipes or overlays. Candidate identity is stable so rejected items remain rejected across future runs. Policies can auto-promote only when all configured gates pass, for example:

- the candidate is inside an approved official registrable domain;
- the same normalized rule appears in at least two independent vetted sources; or
- a reviewed source adapter marks a JSON/API field authoritative.

New repositories, new executable code, redirects to a new host, HTML selector changes and large source deltas always require review.

## Reproducibility

The lock records final URL, ETag/Last-Modified when present, byte size, SHA-256, parser, parsed/rejected counts and upstream commit/release metadata when available. Given the same locked blobs, catalog, recipes, overlays and tool versions, `sync --offline` must reproduce `dist/` byte for byte. Generated files use LF, stable sorting and no wall-clock timestamp in content hashes.

## Automation boundary

Scheduled synchronization runs daily at 00:17 UTC and supports manual dispatch. It discovers sources and builds every recipe, including `void-claude-rules`, then verifies offline reproducibility, strict parsing, assertions, native MRS/DAT round trips and tests. `ci-decision` allows a direct commit to `main` when generated files changed and the build has no review flag; review-required builds stop without publication.

The publication step stages only `dist/` and `generated/`. Changes to `catalog/`, `recipes/`, `overlays/`, `schemas/`, source code or tests fail the automation job instead of being committed.
