from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import BuildError


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
    max_direct_files: int = 40,
) -> UpdateDecision:
    if not changed_paths:
        return UpdateDecision(False, "none", 0, ())
    reasons: list[str] = []
    if build_review_required:
        reasons.append("build report requires review")
    if "generated/discovery/candidates.json.gz" in changed_paths:
        reasons.append("discovery candidates changed")
    if len(changed_paths) > max_direct_files:
        reasons.append(f"{len(changed_paths)} generated files changed (limit {max_direct_files})")
    mode = "review" if reasons else "direct"
    return UpdateDecision(True, mode, len(changed_paths), tuple(reasons))


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
    return {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


def evaluate_repository(root: Path) -> UpdateDecision:
    root = root.resolve()
    changed = _git_paths(root, ["diff", "--name-only", "--", "dist", "generated"])
    changed.update(
        _git_paths(
            root,
            [
                "ls-files",
                "--others",
                "--exclude-standard",
                "--",
                "dist",
                "generated",
            ],
        )
    )
    report_path = root / "generated" / "reports" / "build.json"
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read build report for CI decision: {exc}") from exc
    return decide_update(
        changed,
        build_review_required=bool(report.get("review_required", False)),
    )


def write_github_output(path: Path, decision: UpdateDecision) -> None:
    reason = "; ".join(decision.reasons) if decision.reasons else "thresholds passed"
    values = {
        "changed": str(decision.changed).lower(),
        "mode": decision.mode,
        "changed_files": str(decision.changed_files),
        "reason": reason.replace("\r", " ").replace("\n", " "),
    }
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")
