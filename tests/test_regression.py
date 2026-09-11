from web_audit.identity import build_finding_identity
from web_audit.lifecycle import (
    FindingHistory,
    FindingObservation,
    FindingState,
    FindingTransition,
    classify_history,
)
from web_audit.models import Finding


def make_finding(severity: str = "low") -> Finding:
    return Finding(
        "headers.csp",
        "Test finding",
        severity,
        "test",
        "evidence",
        "fix",
    )


def observation(severity: str = "low") -> FindingObservation:
    finding = make_finding(severity)
    identity = build_finding_identity(
        finding,
        target="https://example.com",
        location="https://example.com/",
    )
    return FindingObservation(identity=identity, finding=finding)


def state(
    observation: FindingObservation | None,
) -> FindingState:
    return FindingState(observation=observation)


def test_present_absent_is_fixed():
    first = observation()

    history = FindingHistory(
        states=(state(first),),
    )

    result = classify_history(history, current=None)

    assert result == FindingTransition(
        state="fixed",
        previous=first,
        current=None,
    )


def test_present_absent_present_is_regressed():
    first = observation()
    current = observation()

    history = FindingHistory(
        states=(state(first), state(None)),
    )

    result = classify_history(history, current)

    assert result == FindingTransition(
        state="regressed",
        previous=first,
        current=current,
    )


def test_present_absent_absent_has_no_transition():
    first = observation()

    history = FindingHistory(
        states=(state(first), state(None)),
    )

    result = classify_history(history, current=None)

    assert result == FindingTransition(
        state=None,
        previous=first,
        current=None,
    )


def test_present_absent_absent_present_is_regressed():
    first = observation()
    current = observation()

    history = FindingHistory(
        states=(
            state(first),
            state(None),
            state(None),
        ),
    )

    result = classify_history(history, current)

    assert result == FindingTransition(
        state="regressed",
        previous=first,
        current=current,
    )


def test_present_with_same_severity_is_present():
    first = observation()

    history = FindingHistory(
        states=(state(first),),
    )

    current = observation()

    result = classify_history(history, current)

    assert result == FindingTransition(
        state="present",
        previous=first,
        current=current,
    )


def test_present_with_changed_severity_is_changed():
    first = observation("low")

    history = FindingHistory(
        states=(state(first),),
    )

    current = observation("medium")

    result = classify_history(history, current)

    assert result == FindingTransition(
        state="changed",
        previous=first,
        current=current,
    )


def test_empty_history_with_current_finding_is_new():
    history = FindingHistory(states=())
    current = observation()

    result = classify_history(history, current)

    assert result == FindingTransition(
        state="new",
        previous=None,
        current=current,
    )


def test_empty_history_without_current_finding_is_invalid():
    history = FindingHistory(states=())

    try:
        classify_history(history, current=None)
    except ValueError as exc:
        assert str(exc) == "history has no observations"
    else:
        raise AssertionError("expected ValueError")
