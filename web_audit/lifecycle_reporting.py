from __future__ import annotations

from .identity import build_finding_identity
from .lifecycle import (
    FindingHistory,
    FindingObservation,
    FindingState,
    classify_history,
)
from .models import Finding
from .security import SUPPORTED_VERIFICATION_RULES

_STATES = ("new", "present", "fixed", "changed", "regressed", "unverified")


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
            identity = build_finding_identity(finding, target=target, location=url)
            observations[identity.key] = FindingObservation(identity=identity, finding=finding)

    return observations


def _same_target(report: dict, observation: FindingObservation) -> bool:
    target = build_finding_identity(
        observation.finding, target=str(report.get("target", ""))
    ).target
    return bool(target) and target == observation.identity.target


def _verify_absence(report: dict, observation: FindingObservation) -> tuple[bool, str]:
    """Require a passed recheck in every result for this normalized URL."""
    if not _same_target(report, observation):
        return False, "The audit target does not match the original finding."

    matches = [
        result
        for result in report.get("results", [])
        if isinstance(result, dict)
        and build_finding_identity(
            observation.finding,
            target=str(report.get("target", "")),
            location=str(result.get("url", "")),
        ).location
        == observation.identity.location
    ]
    if not matches:
        return False, "This URL was not checked in the current audit."

    rule_id = observation.identity.rule_id
    for result in matches:
        if result.get("error"):
            return False, "The recheck returned an error."
        status = result.get("status")
        if type(status) is not int or not 200 <= status < 300:
            return False, "The recheck did not return a successful 2xx HTTP response."
        if result.get("truncated") is not False:
            return False, "The response was truncated or its completeness is unknown."
        version = result.get("verification_version")
        if type(version) is not int or version != 1:
            return False, "Verification metadata is missing or unsupported."
        if rule_id not in SUPPORTED_VERIFICATION_RULES:
            return False, "Verified rechecks are not yet supported for this rule."
        verified_rules = result.get("verified_rules")
        if (
            not isinstance(verified_rules, (list, tuple))
            or any(not isinstance(rule, str) for rule in verified_rules)
            or rule_id not in verified_rules
        ):
            return False, "This rule was not verified as passed in the current audit."

    return True, ""


def _empty_summary(previous_target: str = "", current_target: str = "") -> dict:
    summary = {"previous_target": previous_target, "current_target": current_target}
    for state in _STATES:
        summary[state] = []
        summary[f"{state}_count"] = 0
    return summary


def _append_transition(summary: dict, transition, *, reason: str = "") -> None:
    state = transition.state
    observation = transition.current or transition.previous
    if state is None or observation is None:
        return
    item = {
        "url": observation.identity.location,
        "rule_id": observation.finding.rule_id,
        "severity": observation.finding.severity,
    }
    if state == "changed":
        item["previous_severity"] = transition.previous.finding.severity
    if state == "unverified":
        item["reason"] = reason
    summary[state].append(item)


def summarize_lifecycle(previous: dict, current: dict) -> dict:
    """Summarize changes for the current target, requiring verified absence for FIXED."""
    previous_observations = {
        key: observation
        for key, observation in _observations(previous).items()
        if _same_target(current, observation)
    }
    current_observations = _observations(current)
    keys = sorted(set(previous_observations) | set(current_observations))
    summary = _empty_summary(
        previous_target=str(previous.get("target", "")),
        current_target=str(current.get("target", "")),
    )

    for key in keys:
        previous_observation = previous_observations.get(key)
        current_observation = current_observations.get(key)
        absence_verified, reason = False, ""
        if previous_observation is None:
            states = ()
        else:
            states = (FindingState(observation=previous_observation),)
            if current_observation is None:
                absence_verified, reason = _verify_absence(current, previous_observation)

        transition = classify_history(
            FindingHistory(states=states),
            current_observation,
            absence_verified=absence_verified,
        )
        _append_transition(summary, transition, reason=reason)

    for state in _STATES:
        summary[f"{state}_count"] = len(summary[state])
    return summary


def summarize_lifecycle_history(history: list[dict]) -> dict:
    """Summarize the latest state; inconclusive historical checks remain unknown gaps."""
    if not history:
        raise ValueError("lifecycle history must contain at least one audit")

    current_report = history[-1]
    snapshots = [_observations(report) for report in history]
    references = {
        key: observation
        for snapshot in snapshots
        for key, observation in snapshot.items()
        if _same_target(current_report, observation)
    }
    summary = _empty_summary(current_target=str(current_report.get("target", "")))

    for key, reference in sorted(references.items()):
        previous_states = []
        for report, snapshot in zip(history[:-1], snapshots[:-1], strict=True):
            observation = snapshot.get(key)
            absence_verified = False
            if observation is None:
                absence_verified, _ = _verify_absence(report, reference)
            previous_states.append(FindingState(observation, absence_verified=absence_verified))

        current_observation = snapshots[-1].get(key)
        absence_verified, reason = False, ""
        if current_observation is None:
            absence_verified, reason = _verify_absence(current_report, reference)
        transition = classify_history(
            FindingHistory(states=tuple(previous_states)),
            current_observation,
            absence_verified=absence_verified,
        )
        _append_transition(summary, transition, reason=reason)

    for state in _STATES:
        summary[f"{state}_count"] = len(summary[state])
    return summary
