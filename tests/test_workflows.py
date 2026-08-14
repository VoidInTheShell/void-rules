from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def load_workflow(name: str) -> dict[str, object]:
    path = ROOT / ".github" / "workflows" / name
    document = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(document, dict)
    return document


def test_all_external_actions_are_pinned_to_full_commit_sha() -> None:
    for name in ("validate.yml", "sync.yml"):
        workflow = load_workflow(name)
        jobs = workflow["jobs"]
        assert isinstance(jobs, dict)
        for job in jobs.values():
            assert isinstance(job, dict)
            steps = job["steps"]
            assert isinstance(steps, list)
            for step in steps:
                assert isinstance(step, dict)
                if "uses" in step:
                    assert PINNED_ACTION.fullmatch(str(step["uses"]))


def test_workflows_use_minimum_expected_permissions_and_concurrency() -> None:
    validate = load_workflow("validate.yml")
    synchronize = load_workflow("sync.yml")

    assert validate["permissions"] == {"contents": "read"}
    assert synchronize["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
    }
    assert "concurrency" in validate
    assert "concurrency" in synchronize


def test_sync_schedule_is_every_six_hours_at_nonzero_minute() -> None:
    synchronize = load_workflow("sync.yml")
    triggers = synchronize["on"]
    assert isinstance(triggers, dict)
    assert triggers["schedule"] == [{"cron": "17 */6 * * *"}]
