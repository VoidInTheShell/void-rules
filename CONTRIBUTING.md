# Contributing

Rule changes belong in one of three places:

1. `catalog/sources.yaml` for a reviewed upstream source.
2. `overlays/<ruleset>/include.yaml` or `exclude.yaml` for a durable local requirement.
3. `generated/discovery/candidates.json` for an automatically observed but not yet approved candidate.

Do not edit `dist/` by hand. Run the synchronizer and commit the regenerated artifacts together with the lock and reports.

Every new source must declare its parser format, behavior/polarity, allowed hosts, license status, minimum expected rules and change limits. Every durable rule should include a short reason and, when practical, an official evidence URL.

Before submitting a change, run:

```text
python -m void_rules validate-catalog
python -m void_rules sync --offline
python -m pytest
```

MRS and DAT integration tests additionally require the pinned Mihomo CLI and Go toolchain described in `docs/CODECS.md`.
