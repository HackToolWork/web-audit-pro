import pytest

from web_audit.identity import build_finding_identity
from web_audit.lifecycle import (
    FindingHistory,
    FindingObservation,
    FindingState,
    classify_history,
    classify_transition,
)
from web_audit.models import Finding


def make_finding(
    rule_id: str = "headers.csp",
    *,
    severity: str = "low",
    evidence: str = "evidence",
) -> Finding:
    return Finding(
        rule_id,
        "Test finding",
        severity,
        "test",
        evidence,
        "fix",
    )


def observation(
    *,
    rule_id: str = "headers.csp",
    severity: str = "low",
    evidence: str = "evidence",
) -> FindingObservation:
    finding = make_finding(
        rule_id,
        severity=severity,
        evidence=evidence,
    )
    identity = build_finding_identity(
        finding,
        target="https://example.com",
        location="https://example.com/",
    )
    return FindingObservation(identity=identity, finding=finding)


def test_missing_previous_observation_is_new():
    current = observation()

    result = classify_transition(None, current)

    assert result.state == "new"
    assert result.previous is None
    assert result.current == current


def test_same_observation_is_present():
    previous = observation()
    current = observation()

    result = classify_transition(previous, current)

    assert result.state == "present"
    assert result.previous == previous
    assert result.current == current


def test_evidence_change_is_still_present():
    previous = observation(evidence="old evidence")
    current = observation(evidence="new evidence")

    result = classify_transition(previous, current)

    assert result.state == "present"


def test_severity_change_is_changed():
    previous = observation(severity="low")
    current = observation(severity="medium")

    result = classify_transition(previous, current)

    assert result.state == "changed"


def test_removed_observation_is_fixed():
    previous = observation()

    result = classify_transition(previous, None)

    assert result.state == "fixed"
    assert result.previous == previous
    assert result.current is None


def test_different_identity_is_not_a_transition():
    previous = observation(rule_id="headers.csp")
    current_finding = make_finding("headers.hsts")
    current_identity = build_finding_identity(
        current_finding,
        target="https://example.com",
        location="https://example.com/",
    )
    current = FindingObservation(
        identity=current_identity,
        finding=current_finding,
    )

    result = classify_transition(previous, current)

    assert result.state == "new"


def test_missing_both_observations_is_invalid():
    with pytest.raises(ValueError, match="at least one observation is required"):
        classify_transition(None, None)


def test_history_detects_fixed_then_regressed():
    current = observation()

    history = FindingHistory(
        states=(
            FindingState(observation=current),
            FindingState(observation=None),
        )
    )

    result = classify_history(history, current)

    assert result.state == "regressed"
    assert result.previous == current
    assert result.current == current


def test_history_treats_repeated_absence_as_no_transition():
    previous = observation()

    history = FindingHistory(
        states=(
            FindingState(observation=previous),
            FindingState(observation=None),
        )
    )

    result = classify_history(history, None)

    assert result.state is None
    assert result.previous == previous
    assert result.current is None


def test_history_treats_return_after_multiple_absences_as_regressed():
    previous = observation()

    history = FindingHistory(
        states=(
            FindingState(observation=previous),
            FindingState(observation=None),
            FindingState(observation=None),
        )
    )

    result = classify_history(history, previous)

    assert result.state == "regressed"


def test_history_severity_change_without_absence_is_changed():
    previous = observation(severity="low")
    current = observation(severity="medium")

    history = FindingHistory(states=(FindingState(observation=previous),))

    result = classify_history(history, current)

    assert result.state == "changed"
    assert result.previous == previous
    assert result.current == current
