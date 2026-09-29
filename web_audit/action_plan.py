from __future__ import annotations

from collections import defaultdict

from .models import CheckResult, Finding
from .security import SUPPORTED_VERIFICATION_RULES

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
_AUTOMATIC_RECHECK = (
    "Repeat an authorized scan of the same URL with the same settings. "
    "Automatic verification requires a complete 2xx response without errors or truncation. "
)
_HSTS_RECHECK = (
    "On HTTPS, Strict-Transport-Security must contain one supported positive max-age value. "
    "Missing, disabled or ambiguous HSTS does not pass. This does not verify HTTPS coverage "
    "across the host."
)
_CSP_RECHECK = (
    "On an HTML response, a nonempty enforcing Content-Security-Policy header must be present. "
    "A report-only policy does not pass. This is a header-presence check, not a check of the "
    "policy's safety or effectiveness."
)
_RECHECK_CONDITIONS = {
    "headers.hsts": _HSTS_RECHECK,
    "headers.hsts_disabled": _HSTS_RECHECK,
    "headers.content_type_options": "X-Content-Type-Options must have the value nosniff.",
    "headers.csp": _CSP_RECHECK,
    "headers.csp_report_only": _CSP_RECHECK,
    "headers.referrer_policy": (
        "A nonempty Referrer-Policy header must be present. This is a header-presence check, "
        "not a check of the policy's safety or suitability."
    ),
    "headers.clickjacking": (
        "On an HTML response, an enforcing CSP frame-ancestors directive must use the "
        "supported restrictive sources, such as 'none', 'self' or an explicit HTTP(S) "
        "ancestor allowlist. If that directive is absent, X-Frame-Options must be DENY or "
        "SAMEORIGIN. The CSP directive takes precedence. This checks the declaration only."
    ),
    "cors.wildcard_credentials": (
        "The response must not combine Access-Control-Allow-Origin: * with "
        "Access-Control-Allow-Credentials: true. This checks that combination only, "
        "not the full CORS policy or which origins are trusted."
    ),
    "info.stack_headers": (
        "Neither Server nor X-Powered-By may disclose a nonempty value. "
        "This checks those response headers only."
    ),
}
_MANUAL_RECHECK = (
    "Repeat an authorized scan of the same URL with the same settings and relevant checks "
    "enabled, then manually review the original evidence and the changed behavior. "
    "This rule has no automatic verification; an absent finding alone does not confirm a fix."
)


def _incomplete_reasons(result: CheckResult) -> list[str]:
    reasons = []
    if result.status is None:
        reasons.append("No HTTP response")
    elif not 200 <= result.status < 300:
        reasons.append(f"HTTP status {result.status} is not 2xx")
    if result.error:
        reasons.append("Request error")
    if result.truncated:
        reasons.append("Response truncated")
    return reasons


def _task(rule_id: str, entries: list[tuple[CheckResult, Finding]]) -> dict[str, object]:
    findings = [finding for _, finding in entries]
    representative = min(
        findings, key=lambda finding: (-_SEVERITY_ORDER[finding.severity], finding.title)
    )
    severity = representative.severity
    urls = sorted({result.url for result, _ in entries})
    confidences = sorted(
        {finding.confidence for finding in findings}, key=_CONFIDENCE_ORDER.__getitem__
    )
    observations = {
        (result.url, finding.severity, finding.confidence, finding.evidence, finding.recommendation)
        for result, finding in entries
    }
    ordered_observations = sorted(
        observations,
        key=lambda observation: (
            observation[0],
            -_SEVERITY_ORDER[observation[1]],
            _CONFIDENCE_ORDER[observation[2]],
            observation[3],
            observation[4],
        ),
    )
    next_step = (
        "review"
        if severity == "info"
        else "validate"
        if any(
            finding.confidence != "high" or _incomplete_reasons(result)
            for result, finding in entries
        )
        else "fix"
    )
    automatic = rule_id in SUPPORTED_VERIFICATION_RULES
    recheck = _AUTOMATIC_RECHECK + _RECHECK_CONDITIONS[rule_id] if automatic else _MANUAL_RECHECK
    return {
        "rule_id": rule_id,
        "title": representative.title,
        "severity": severity,
        "confidences": confidences,
        "urls": urls,
        "observations": [
            {
                "url": url,
                "severity": observation_severity,
                "confidence": confidence,
                "evidence": evidence,
                "recommendation": recommendation,
            }
            for (
                url,
                observation_severity,
                confidence,
                evidence,
                recommendation,
            ) in ordered_observations
        ],
        "recommendations": sorted(
            {finding.recommendation for finding in findings if finding.recommendation.strip()}
        ),
        "next_step": next_step,
        "priority_reason": (
            f"Highest observed severity: {severity}; {len(urls)} distinct affected "
            f"{'URL' if len(urls) == 1 else 'URLs'}. "
            "Ordered by severity, then affected URL count, then rule ID."
        ),
        "recheck_mode": "automatic" if automatic else "manual",
        "recheck": recheck,
    }


def build_action_plan(results: list[CheckResult]) -> dict[str, object]:
    """Group findings into deterministic next steps without asserting site safety.

    Coverage describes successful, complete HTTP responses only. It does not
    establish that optional checks ran or that any security condition passed.
    Recheck instructions describe future verification, not an existing fix.
    """
    grouped: dict[str, list[tuple[CheckResult, Finding]]] = defaultdict(list)
    incomplete: dict[str, set[str]] = defaultdict(set)
    for result in results:
        reasons = _incomplete_reasons(result)
        if reasons:
            incomplete[result.url].update(reasons)
        for finding in result.findings:
            grouped[finding.rule_id].append((result, finding))
    tasks = [_task(rule_id, entries) for rule_id, entries in grouped.items()]
    tasks.sort(
        key=lambda task: (-_SEVERITY_ORDER[task["severity"]], -len(task["urls"]), task["rule_id"])
    )
    return {
        "tasks": tasks,
        "coverage": {
            "total_urls": len({result.url for result in results}),
            "incomplete_urls": [
                {"url": url, "reasons": sorted(reasons)}
                for url, reasons in sorted(incomplete.items())
            ],
        },
    }
