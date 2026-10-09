from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from void_rules import ci
from void_rules.ci import decide_update, evaluate_repository
from void_rules.errors import BuildError
from void_rules.publication import json_bytes, publication_digest


def test_ci_decision_reports_no_update_when_outputs_are_unchanged() -> None:
    decision = decide_update(set(), build_review_required=False)

    assert decision.changed is False
    assert decision.mode == "none"
    assert decision.changed_files == 0
    assert decision.reasons == ()


def test_ci_decision_allows_generated_update() -> None:
    decision = decide_update(
        {"dist/ai/mihomo-domain.mrs", "generated/sources.lock.json"},
        build_review_required=False,
    )

    assert decision.changed is True
    assert decision.mode == "direct"
    assert decision.reasons == ()


def test_ci_decision_allows_discovery_candidates_but_blocks_build_warning() -> None:
    discovery = decide_update(
        {"generated/discovery/candidates.json.gz"},
        build_review_required=False,
    )
    build_warning = decide_update(
        {"dist/ads/mihomo-domain.mrs"},
        build_review_required=True,
    )

    assert discovery.mode == "direct"
    assert discovery.reasons == ()
    assert build_warning.mode == "blocked"
    assert build_warning.reasons == ("build report requires review",)


def test_ci_decision_allows_discovery_snapshot_metadata_only_update() -> None:
    decision = decide_update(
        {"generated/discovery/summary.json"},
        build_review_required=False,
    )

    assert decision.mode == "direct"
    assert decision.reasons == ()


def test_ci_decision_allows_large_generated_fanout_after_safety_checks() -> None:
    paths = {f"dist/example/file-{index}.txt" for index in range(100)}

    decision = decide_update(paths, build_review_required=False)

    assert decision.mode == "direct"
    assert decision.changed_files == 100
    assert decision.reasons == ()


def test_review_blocks_even_when_no_output_was_written() -> None:
    assert decide_update(set(), build_review_required=True).mode == "blocked"


@pytest.fixture
def ci_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(ci, "load_catalog", lambda root: SimpleNamespace(recipes={"a": None}))
    (tmp_path / ".gitignore").write_text(".work/\n")
    (tmp_path / "generated/reports").mkdir(parents=True)
    (tmp_path / "generated/reports/build.json").write_bytes(
        json_bytes(
            {
                "version": 1,
                "review_required": False,
                "selected_rulesets": ["a"],
                "binary_outputs": True,
            }
        )
    )
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "baseline",
        ],
        cwd=tmp_path,
        check=True,
    )
    refresh_receipts(tmp_path)
    return tmp_path


def refresh_receipts(root: Path, **overrides: Any) -> None:
    reports = root / ".work/reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "sync-attempt.json").write_bytes(
        json_bytes(
            {
                "status": "ok",
                "rulesets": ["a"],
                "binary_outputs": True,
                "locked_check": True,
                "publication_sha256": publication_digest(root),
                **overrides,
            }
        )
    )
    (reports / "discovery-attempt.json").write_bytes(
        json_bytes(
            {
                "status": "ok",
                "locked_check": True,
            }
        )
    )


def test_ci_sees_staged_generated_changes(ci_repo: Path) -> None:
    (ci_repo / "generated/example.txt").write_text("new")
    refresh_receipts(ci_repo)
    subprocess.run(["git", "add", "generated"], cwd=ci_repo, check=True)
    decision = evaluate_repository(ci_repo)
    assert decision.mode == "direct"
    assert decision.changed_files == 1


@pytest.mark.parametrize("staged", [False, True])
def test_ci_blocks_untracked_and_staged_protected_files(ci_repo: Path, staged: bool) -> None:
    (ci_repo / "unapproved.py").write_text("changed")
    if staged:
        subprocess.run(["git", "add", "unapproved.py"], cwd=ci_repo, check=True)
    assert evaluate_repository(ci_repo).mode == "blocked"


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "failed"},
        {"rulesets": []},
        {"binary_outputs": False},
        {"locked_check": False},
    ],
)
def test_ci_rejects_failed_partial_or_unverified_attempts(
    ci_repo: Path,
    overrides: dict[str, Any],
) -> None:
    refresh_receipts(ci_repo, **overrides)
    assert evaluate_repository(ci_repo).mode == "blocked"


def test_ci_rejects_changes_after_verification(ci_repo: Path) -> None:
    (ci_repo / "generated/example.txt").write_text("post-validation change")
    assert evaluate_repository(ci_repo).mode == "blocked"


def test_ci_requires_explicit_review_status(ci_repo: Path) -> None:
    path = ci_repo / "generated/reports/build.json"
    document = json.loads(path.read_bytes())
    del document["review_required"]
    path.write_text(json.dumps(document))
    refresh_receipts(ci_repo)
    with pytest.raises(BuildError, match="valid build"):
        evaluate_repository(ci_repo)
