# Security policy

## Trust model

All remote rule files are untrusted input. The build downloads data only from HTTPS origins explicitly registered in `catalog/sources.yaml`; it never runs scripts obtained from a rule source.

The synchronizer rejects redirects to unapproved hosts, HTML/error pages, oversized responses, unexpectedly small rule counts, unknown syntax in strict sources, path traversal and archive members outside the build directory. Downloads are written atomically and identified by SHA-256 in the source lock.

## Protected paths

Automation may update only these paths:

- `dist/`
- `generated/sources.lock.json`
- `generated/reports/`
- `generated/discovery/`

Automation must not modify `catalog/`, `recipes/`, `overlays/`, `schemas/`, source code, workflows or documentation. CI verifies this boundary before an automated commit.

## Reporting

Please open a private GitHub security advisory for a parser escape, path traversal, workflow-token issue, malicious source bypass or other vulnerability. Ordinary false positives and missing domains belong in a normal issue.
