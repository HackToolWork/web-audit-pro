from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .identity import FindingIdentity
from .models import Finding

LifecycleState = Literal["new", "present", "fixed", "changed", "regressed", "unverified"]


@dataclass(frozen=True, slots=True)
class FindingObservation:
    """A finding observed during a single audit."""

    identity: FindingIdentity
    finding: Finding


@dataclass(frozen=True, slots=True)
class TransitionResult:
    """The lifecycle transition between two observations."""

    state: LifecycleState
    previous: FindingObservation | None
    current: FindingObservation | None


@dataclass(frozen=True, slots=True)
class FindingState:
    """An observation or a recheck of a previously observed finding.

    An absent observation is unknown unless ``absence_verified`` is true.
    Unknown checks do not establish either a fix or a regression.
    """

    observation: FindingObservation | None
    absence_verified: bool = False


@dataclass(frozen=True, slots=True)
class FindingHistory:
    """Immutable historical states of one logical finding."""

    states: tuple[FindingState, ...]


@dataclass(frozen=True, slots=True)
class FindingTransition:
    """The transition produced by comparing history with the current audit."""

    state: LifecycleState | None
    previous: FindingObservation | None
    current: FindingObservation | None


def classify_transition(
    previous: FindingObservation | None,
    current: FindingObservation | None,
    *,
    absence_verified: bool = False,
) -> TransitionResult:
    """Classify two observations; absent findings require an explicit verified recheck."""
    if previous is None and current is None:
        raise ValueError("at least one observation is required")

    if previous is None:
        return TransitionResult("new", None, current)

    if current is None:
        return TransitionResult("fixed" if absence_verified else "unverified", previous, None)

    if previous.identity != current.identity:
        return TransitionResult("new", None, current)

    if previous.finding.severity != current.finding.severity:
        return TransitionResult("changed", previous, current)

    return TransitionResult("present", previous, current)


def classify_history(
    history: FindingHistory,
    current: FindingObservation | None,
    *,
    absence_verified: bool = False,
) -> FindingTransition:
    """Classify against the latest known state, skipping inconclusive historical checks.

    Only verified absence establishes FIXED or makes a returning finding REGRESSED.
    An inconclusive current check is UNVERIFIED even after an earlier verified fix.
    """
    if not history.states:
        if current is None:
            raise ValueError("history has no observations")
        return FindingTransition("new", None, current)

    previous = next(
        (state.observation for state in reversed(history.states) if state.observation is not None),
        None,
    )
    last_known = next(
        (
            state
            for state in reversed(history.states)
            if state.observation is not None or state.absence_verified
        ),
        None,
    )
    was_absent = last_known is not None and last_known.observation is None

    if current is None:
        if previous is None:
            return FindingTransition(None, None, None)
        if not absence_verified:
            return FindingTransition("unverified", previous, None)
        if was_absent:
            return FindingTransition(None, previous, None)
        return FindingTransition("fixed", previous, None)

    if previous is None or previous.identity != current.identity:
        return FindingTransition("new", None, current)

    if was_absent:
        return FindingTransition("regressed", previous, current)

    if previous.finding.severity != current.finding.severity:
        return FindingTransition("changed", previous, current)

    return FindingTransition("present", previous, current)
