from __future__ import annotations

from void_rules.ci import decide_update


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
