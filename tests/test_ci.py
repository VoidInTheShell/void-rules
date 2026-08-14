from __future__ import annotations

from void_rules.ci import decide_update


def test_ci_decision_allows_small_generated_update() -> None:
    decision = decide_update(
        {"dist/ai/mihomo-domain.mrs", "generated/sources.lock.json"},
        build_review_required=False,
    )

    assert decision.changed is True
    assert decision.mode == "direct"
    assert decision.reasons == ()


def test_ci_decision_routes_discovery_or_build_warning_to_review() -> None:
    discovery = decide_update(
        {"generated/discovery/candidates.json.gz"},
        build_review_required=False,
    )
    build_warning = decide_update(
        {"dist/ads/mihomo-domain.mrs"},
        build_review_required=True,
    )

    assert discovery.mode == "review"
    assert "discovery candidates changed" in discovery.reasons
    assert build_warning.mode == "review"
    assert "build report requires review" in build_warning.reasons


def test_ci_decision_allows_discovery_snapshot_metadata_only_update() -> None:
    decision = decide_update(
        {"generated/discovery/summary.json"},
        build_review_required=False,
    )

    assert decision.mode == "direct"
    assert decision.reasons == ()


def test_ci_decision_routes_large_fanout_to_review() -> None:
    paths = {f"dist/example/file-{index}.txt" for index in range(41)}

    decision = decide_update(paths, build_review_required=False)

    assert decision.mode == "review"
    assert decision.changed_files == 41
