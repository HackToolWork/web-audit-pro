from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .identity import FindingIdentity
from .models import Finding

LifecycleState = Literal["new", "present", "fixed", "changed"]


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


def classify_transition(
    previous: FindingObservation | None,
    current: FindingObservation | None,
) -> TransitionResult:
    """Classify the lifecycle transition between two observations.

    Severity changes are treated as material changes. Evidence and other
    presentation details intentionally do not change lifecycle state.
    """
    if previous is None and current is None:
        raise ValueError("at least one observation is required")

    if previous is None:
        return TransitionResult(
            state="new",
            previous=None,
            current=current,
        )

    if current is None:
        return TransitionResult(
            state="fixed",
            previous=previous,
            current=None,
        )

    if previous.identity != current.identity:
        return TransitionResult(
            state="new",
            previous=None,
            current=current,
        )

    if previous.finding.severity != current.finding.severity:
        return TransitionResult(
            state="changed",
            previous=previous,
            current=current,
        )

    return TransitionResult(
        state="present",
        previous=previous,
        current=current,
    )
