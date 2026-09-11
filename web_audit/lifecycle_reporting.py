from __future__ import annotations

from .identity import build_finding_identity
from .lifecycle import (
    FindingHistory,
    FindingObservation,
    FindingState,
    classify_history,
)
from .models import Finding


def _finding_from_payload(payload: dict) -> Finding:
    return Finding(
        rule_id=str(payload.get("rule_id", "")),
        title=str(payload.get("title", "")),
        severity=payload.get("severity", "info"),
        category=str(payload.get("category", "")),
        evidence=str(payload.get("evidence", "")),
        recommendation=str(payload.get("recommendation", "")),
        confidence=payload.get("confidence", "high"),
    )


def _observations(report: dict) -> dict[str, FindingObservation]:
    target = str(report.get("target", ""))
    observations: dict[str, FindingObservation] = {}

    for result in report.get("results", []):
        if not isinstance(result, dict):
            continue

        url = str(result.get("url", ""))

        for payload in result.get("findings", []):
            if not isinstance(payload, dict):
                continue

            finding = _finding_from_payload(payload)
            identity = build_finding_identity(
                finding,
                target=target,
                location=url,
            )

            observation = FindingObservation(
                identity=identity,
                finding=finding,
            )
            observations[identity.key] = observation

    return observations


def _empty_summary(previous_target: str = "", current_target: str = "") -> dict:
    summary = {
        "previous_target": previous_target,
        "current_target": current_target,
        "new": [],
        "present": [],
        "fixed": [],
        "changed": [],
        "regressed": [],
    }

    for state in ("new", "present", "fixed", "changed", "regressed"):
        summary[f"{state}_count"] = 0

    return summary


def _append_transition(summary: dict, state: str, result) -> None:
    previous = result.previous
    current = result.current

    if state == "new" and current is not None:
        summary["new"].append(
            {
                "url": current.identity.location,
                "rule_id": current.finding.rule_id,
                "severity": current.finding.severity,
            }
        )
    elif state == "present" and current is not None:
        summary["present"].append(
            {
                "url": current.identity.location,
                "rule_id": current.finding.rule_id,
                "severity": current.finding.severity,
            }
        )
    elif state == "fixed" and previous is not None:
        summary["fixed"].append(
            {
                "url": previous.identity.location,
                "rule_id": previous.finding.rule_id,
                "severity": previous.finding.severity,
            }
        )
    elif state == "changed" and previous is not None and current is not None:
        summary["changed"].append(
            {
                "url": current.identity.location,
                "rule_id": current.finding.rule_id,
                "previous_severity": previous.finding.severity,
                "severity": current.finding.severity,
            }
        )
    elif state == "regressed" and previous is not None and current is not None:
        summary["regressed"].append(
            {
                "url": current.identity.location,
                "rule_id": current.finding.rule_id,
                "severity": current.finding.severity,
            }
        )


def summarize_lifecycle(previous: dict, current: dict) -> dict:
    """Summarize lifecycle changes between two audit reports."""
    previous_observations = _observations(previous)
    current_observations = _observations(current)

    keys = sorted(set(previous_observations) | set(current_observations))

    summary = _empty_summary(
        previous_target=str(previous.get("target", "")),
        current_target=str(current.get("target", "")),
    )

    for key in keys:
        previous_observation = previous_observations.get(key)
        current_observation = current_observations.get(key)

        if previous_observation is None:
            result = classify_history(
                FindingHistory(states=()),
                current_observation,
            )
        else:
            history = FindingHistory(
                states=(FindingState(observation=previous_observation),),
            )
            result = classify_history(history, current_observation)

        if result.state is not None:
            _append_transition(summary, result.state, result)

    for state in ("new", "present", "fixed", "changed", "regressed"):
        summary[f"{state}_count"] = len(summary[state])

    return summary


def summarize_lifecycle_history(history: list[dict]) -> dict:
    """Summarize the latest lifecycle state of each finding in audit history."""
    if not history:
        raise ValueError("lifecycle history must contain at least one audit")

    current_report = history[-1]
    current_observations = _observations(current_report)

    snapshots = [_observations(report) for report in history]
    keys = sorted(set().union(*(observations.keys() for observations in snapshots)))

    summary = _empty_summary(
        current_target=str(current_report.get("target", "")),
    )

    for key in keys:
        current_observation = current_observations.get(key)

        previous_states = tuple(
            FindingState(observation=snapshot.get(key)) for snapshot in snapshots[:-1]
        )

        if not previous_states:
            result = classify_history(
                FindingHistory(states=()),
                current_observation,
            )
        else:
            result = classify_history(
                FindingHistory(states=previous_states),
                current_observation,
            )

        if result.state is not None:
            _append_transition(summary, result.state, result)

    for state in ("new", "present", "fixed", "changed", "regressed"):
        summary[f"{state}_count"] = len(summary[state])

    return summary
