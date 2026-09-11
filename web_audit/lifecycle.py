from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .identity import FindingIdentity
from .models import Finding

LifecycleState = Literal["new", "present", "fixed", "changed", "regressed"]


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
    """The state of one logical finding during an audit.

    ``observation=None`` represents an audit in which the finding
    was not observed.
    """

    observation: FindingObservation | None


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
) -> TransitionResult:
    """Classify the transition between two observations."""
    if previous is None and current is None:
        raise ValueError("at least one observation is required")

    if previous is None:
        return TransitionResult("new", None, current)

    if current is None:
        return TransitionResult("fixed", previous, None)

    if previous.identity != current.identity:
        return TransitionResult("new", None, current)

    if previous.finding.severity != current.finding.severity:
        return TransitionResult("changed", previous, current)

    return TransitionResult("present", previous, current)


def _last_observed(
    history: FindingHistory,
) -> FindingObservation | None:
    """Return the most recent observed finding from history."""
    return next(
        (state.observation for state in reversed(history.states) if state.observation is not None),
        None,
    )


def classify_history(
    history: FindingHistory,
    current: FindingObservation | None,
) -> FindingTransition:
    """Classify the current audit state against finding history.

    ``FIXED`` represents a transition from an observed finding to an
    absent state. Repeated absence produces no transition. A finding
    returning after one or more absent states is ``REGRESSED``.
    """
    if not history.states:
        if current is None:
            raise ValueError("history has no observations")
        return FindingTransition("new", None, current)

    previous = _last_observed(history)
    was_absent = history.states[-1].observation is None

    if current is None:
        if was_absent:
            return FindingTransition(None, previous, None)

        return FindingTransition("fixed", previous, None)

    if previous is None:
        return FindingTransition("new", None, current)

    if previous.identity != current.identity:
        return FindingTransition("new", None, current)

    if was_absent:
        return FindingTransition("regressed", previous, current)

    if previous.finding.severity != current.finding.severity:
        return FindingTransition("changed", previous, current)

    return FindingTransition("present", previous, current)
