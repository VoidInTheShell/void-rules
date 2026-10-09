from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .catalog import load_catalog
from .errors import BuildError
from .publication import publication_digest


@dataclass(frozen=True, slots=True)
class UpdateDecision:
    changed: bool
    mode: str
    changed_files: int
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "changed": self.changed,
            "mode": self.mode,
            "changed_files": self.changed_files,
            "reasons": list(self.reasons),
        }


def decide_update(
    changed_paths: set[str],
    *,
    build_review_required: bool,
) -> UpdateDecision:
    reasons: list[str] = []
    if build_review_required:
        reasons.append("build report requires review")
    if any(not path.startswith(("dist/", "generated/")) for path in changed_paths):
        reasons.append("protected inputs were modified")
    mode = "blocked" if reasons else "direct" if changed_paths else "none"
    return UpdateDecision(bool(changed_paths), mode, len(changed_paths), tuple(reasons))


def _git_paths(root: Path, arguments: list[str]) -> set[str]:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BuildError(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return {path for path in result.stdout.split("\0") if path}


def evaluate_repository(root: Path) -> UpdateDecision:
    root = root.resolve()
    changed = _git_paths(root, ["diff", "--name-only", "-z"])
    changed.update(_git_paths(root, ["diff", "--cached", "--name-only", "-z"]))
    changed.update(_git_paths(root, ["ls-files", "--others", "--exclude-standard", "-z"]))
    report_path = root / "generated" / "reports" / "build.json"
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        attempt = json.loads((root / ".work/reports/sync-attempt.json").read_bytes())
        discovery = json.loads((root / ".work/reports/discovery-attempt.json").read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read build report for CI decision: {exc}") from exc
    if (
        not isinstance(report, dict)
        or report.get("version") != 1
        or type(report.get("review_required")) is not bool
        or not isinstance(attempt, dict)
        or not isinstance(discovery, dict)
    ):
        raise BuildError("CI decision requires valid build and attempt reports")
    recipes = sorted(load_catalog(root).recipes)
    reasons: list[str] = []
    if report.get("selected_rulesets") != recipes or attempt.get("rulesets") != recipes:
        reasons.append("a full build is required for publication")
    if report.get("binary_outputs") is not True or attempt.get("binary_outputs") is not True:
        reasons.append("binary outputs were not validated")
    if attempt.get("status") != "ok" or discovery.get("status") != "ok":
        reasons.append("the latest synchronization/discovery attempt did not succeed")
    if attempt.get("locked_check") is not True or discovery.get("locked_check") is not True:
        reasons.append("locked input replay checks are required")
    if attempt.get("publication_sha256") != publication_digest(root):
        reasons.append("published files changed after validation")
    if reasons:
        return UpdateDecision(bool(changed), "blocked", len(changed), tuple(reasons))
    return decide_update(
        changed,
        build_review_required=report["review_required"],
    )


def write_github_output(path: Path, decision: UpdateDecision) -> None:
    reason = "; ".join(decision.reasons) if decision.reasons else "safety checks passed"
    values = {
        "changed": str(decision.changed).lower(),
        "mode": decision.mode,
        "changed_files": str(decision.changed_files),
        "reason": reason.replace("\r", " ").replace("\n", " "),
    }
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")
