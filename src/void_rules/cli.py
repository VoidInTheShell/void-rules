from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import load_catalog
from .ci import evaluate_repository, write_github_output
from .discovery import discover
from .errors import VoidRulesError
from .pipeline import build
from .tools import install_mihomo


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="void-rules")
    parser.add_argument("--root", type=Path, default=repository_root(), help="repository root")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate-catalog", help="validate schemas and semantic references")
    install = subparsers.add_parser("install-tools", help="install pinned binary codecs")
    install.add_argument("--force", action="store_true", help="replace an existing pinned tool")

    discovery = subparsers.add_parser(
        "discover",
        help="refresh constrained discovery candidates without changing overlays",
    )
    discovery.add_argument("--offline", action="store_true", help="read only discovery cache")
    discovery.add_argument("--check", action="store_true", help="compare without writing")

    ci = subparsers.add_parser(
        "ci-decision",
        help="classify generated changes as none, direct or review",
    )
    ci.add_argument("--github-output", type=Path, help="append GitHub Actions outputs")

    sync = subparsers.add_parser("sync", help="fetch, merge, validate and render rulesets")
    sync.add_argument("--offline", action="store_true", help="read only the local .work cache")
    sync.add_argument(
        "--check", action="store_true", help="compare generated files without writing"
    )
    sync.add_argument(
        "--skip-binary",
        action="store_true",
        help="skip MRS/DAT outputs (intended only for parser/unit-test development)",
    )
    sync.add_argument("--ruleset", action="append", default=[], help="build only this ruleset")
    sync.add_argument("--workers", type=int, default=8, help="parallel source fetch workers")

    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "validate-catalog":
            catalog = load_catalog(root)
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "sources": len(catalog.sources),
                        "recipes": list(catalog.recipe_order),
                        "discoverers": len(catalog.discovery["discoverers"]),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return
        if args.command == "discover":
            discovery_result = discover(
                root,
                offline=bool(args.offline),
                check=bool(args.check),
            )
            summary = {
                "status": "ok",
                "changed": discovery_result.changed,
                "counts": discovery_result.document["counts"],
                "stale_rejections": discovery_result.document["stale_rejections"],
            }
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            if args.check and discovery_result.changed:
                raise SystemExit(2)
            return
        if args.command == "install-tools":
            path = install_mihomo(root, force=bool(args.force))
            print(json.dumps({"status": "ok", "mihomo": str(path)}, ensure_ascii=False, indent=2))
            return
        if args.command == "ci-decision":
            decision = evaluate_repository(root)
            if args.github_output:
                write_github_output(args.github_output, decision)
            print(json.dumps(decision.as_dict(), ensure_ascii=False, indent=2))
            return
        if args.command == "sync":
            build_result = build(
                root,
                offline=bool(args.offline),
                check=bool(args.check),
                skip_binary=bool(args.skip_binary),
                selected_rulesets=set(args.ruleset) if args.ruleset else None,
                workers=max(1, int(args.workers)),
            )
            summary = {
                "status": "review" if build_result.review_required else "ok",
                "changed": build_result.changed,
                "review_required": build_result.review_required,
                "rulesets": {key: len(value) for key, value in sorted(build_result.rules.items())},
                "review_reasons": build_result.report["review_reasons"],
            }
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            if args.check and build_result.changed:
                raise SystemExit(2)
            return
        raise AssertionError(f"unhandled command: {args.command}")
    except VoidRulesError as exc:
        print(f"void-rules: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
