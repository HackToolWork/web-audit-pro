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

    result = classify_transition(previous, None, absence_verified=True)

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
            FindingState(observation=None, absence_verified=True),
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
            FindingState(observation=None, absence_verified=True),
        )
    )

    result = classify_history(history, None, absence_verified=True)

    assert result.state is None
    assert result.previous == previous
    assert result.current is None


def test_history_treats_return_after_multiple_absences_as_regressed():
    previous = observation()

    history = FindingHistory(
        states=(
            FindingState(observation=previous),
            FindingState(observation=None, absence_verified=True),
            FindingState(observation=None, absence_verified=True),
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


def test_absence_requires_explicit_verification():
    previous = observation()

    assert classify_transition(previous, None).state == "unverified"
    history = FindingHistory(states=(FindingState(previous),))
    assert classify_history(history, None).state == "unverified"
    assert classify_history(history, None, absence_verified=True).state == "fixed"


@pytest.mark.parametrize(("severity", "expected"), [("low", "present"), ("medium", "changed")])
def test_unknown_history_gap_does_not_establish_regression(severity, expected):
    previous = observation()
    history = FindingHistory(states=(FindingState(previous), FindingState(None)))

    assert classify_history(history, observation(severity=severity)).state == expected


def test_unknown_gap_after_verified_absence_preserves_regression():
    previous = observation()
    history = FindingHistory(
        states=(
            FindingState(previous),
            FindingState(None, absence_verified=True),
            FindingState(None),
        )
    )

    assert classify_history(history, previous).state == "regressed"
    assert classify_history(history, None).state == "unverified"
    assert classify_history(history, None, absence_verified=True).state is None


def test_verified_absence_after_unknown_gap_is_fixed():
    previous = observation()
    history = FindingHistory(states=(FindingState(previous), FindingState(None)))

    assert classify_history(history, None, absence_verified=True).state == "fixed"
