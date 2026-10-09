# Architecture

## Pipeline

```text
registered sources
       |
       v
download + content guards ----> mutable .work cache
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
round-trip validation + delta gate
       |
       v
staged publication -----------> dist + reports + lock + committed inputs
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

Discovery produces candidates with evidence; it does not edit recipes or overlays. Candidate identity is stable so rejected items remain rejected across future runs. All current discoverers use `candidate-only`. The `policy` setting records a review candidate; automatic promotion is not implemented. The declared policy gates document prerequisites for a future reviewed promotion path.

JSON APIs can declare offset pagination. Every page is captured, and changing totals, duplicate IDs, missing IDs, incomplete results, non-progressing offsets and excessive page counts fail closed. GitHub tree traversal pins recursive requests to the resolved tree SHA and handles truncated recursive listings by walking subtrees.

New repositories, new executable code, redirects to a new host, HTML selector changes and large source deltas always require review.

## Reproducibility

`generated/inputs/sources/` and `generated/inputs/discovery/` contain compressed original inputs and indexes of raw SHA-256, size and metadata. Compression uses the pinned Go codec. Snapshots contain the original source bytes, not reconstructed normalized rules, so replay exercises the real parsers. Source metadata includes the accepted change time and fetch metadata; equivalent content keeps that metadata stable even if a release asset URL or ETag changes. Fresh fetch observations remain in `.work`.

`discover --locked --check` and `sync --locked --check` require those committed inputs and never fetch upstream data or depend on the download cache. They validate input integrity and compare discovery output, all rule outputs, manifests, global reports, source locks and snapshot files. `--offline` instead reads the mutable `.work` cache and is intended for development and migration. A check never writes accepted artifacts; attempt diagnostics live in `.work/reports/`. Missing or corrupt locked inputs fail rather than falling back to another revision.

A partial build expands through dependencies, consumers, shared sources and the Fake-IP pair. It updates the entire affected component and preserves unrelated global source entries and report sections. Without a complete published baseline it bootstraps a full build. Partial checks cover the affected component; full replay is mandatory before publication.

All rendering and safety gates finish before publication. A review-required attempt leaves accepted artifacts and baselines untouched, so rerunning cannot reset the growth/conflict gate. Files are staged together and replacement errors roll back files already applied. This guards application errors, not abrupt machine loss; CI runs in a disposable checkout and publishes only after all checks pass.

## Automation boundary

Scheduled synchronization runs daily at 00:17 UTC and supports manual dispatch. It fetches live discovery/source inputs, builds every recipe, including `void-claude-rules`, and then checks committed-input replay, strict parsing, assertions, native MRS/DAT round trips and tests. PR/push/manual validation only replays committed inputs; it does not float to new upstream revisions.

`ci-decision` requires explicit successful discovery and full-build attempt reports, locked replay, binary outputs and an unchanged digest of all generated files. It inspects staged, unstaged and untracked changes, and blocks review-required builds even if no output was written. Failure artifacts include `.work/reports/` so the current failure is distinguishable from the last accepted report. Exit codes are 1 for errors, 2 for check differences and 3 for required review.

The publication step stages only `dist/` and `generated/`. Changes outside them fail the automation job instead of being committed. The remote head is checked before commit; a concurrent update requires a new synchronization from that head. Pushes are never forced. A bot push using `GITHUB_TOKEN` does not start another push workflow, so synchronization itself runs the full gates; the validation workflow also supports manual dispatch for an explicit check on the published commit.
