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


def summarize_lifecycle(previous: dict, current: dict) -> dict:
    """Summarize lifecycle changes between two audit reports."""
    previous_observations = _observations(previous)
    current_observations = _observations(current)

    keys = sorted(set(previous_observations) | set(current_observations))

    summary = {
        "previous_target": previous.get("target", ""),
        "current_target": current.get("target", ""),
        "new": [],
        "present": [],
        "fixed": [],
        "changed": [],
        "regressed": [],
    }

    for key in keys:
        previous_observation = previous_observations.get(key)
        current_observation = current_observations.get(key)

        if previous_observation is None:
            result = classify_history(
                FindingHistory(states=()),
                current_observation,
            )
        else:
            previous_state = FindingState(observation=previous_observation)

            if current_observation is None:
                history = FindingHistory(
                    states=(previous_state,),
                )
            else:
                history = FindingHistory(
                    states=(previous_state,),
                )

            result = classify_history(history, current_observation)

        if result.state == "new" and current_observation is not None:
            summary["new"].append(
                {
                    "url": current_observation.identity.location,
                    "rule_id": current_observation.finding.rule_id,
                    "severity": current_observation.finding.severity,
                }
            )
        elif result.state == "present" and current_observation is not None:
            summary["present"].append(
                {
                    "url": current_observation.identity.location,
                    "rule_id": current_observation.finding.rule_id,
                    "severity": current_observation.finding.severity,
                }
            )
        elif result.state == "fixed" and previous_observation is not None:
            summary["fixed"].append(
                {
                    "url": previous_observation.identity.location,
                    "rule_id": previous_observation.finding.rule_id,
                    "severity": previous_observation.finding.severity,
                }
            )
        elif (
            result.state == "changed"
            and previous_observation is not None
            and current_observation is not None
        ):
            summary["changed"].append(
                {
                    "url": current_observation.identity.location,
                    "rule_id": current_observation.finding.rule_id,
                    "previous_severity": previous_observation.finding.severity,
                    "severity": current_observation.finding.severity,
                }
            )

    for state in ("new", "present", "fixed", "changed", "regressed"):
        summary[f"{state}_count"] = len(summary[state])

    return summary
