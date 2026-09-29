import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from web_audit.action_plan import build_action_plan
from web_audit.models import CheckResult, Finding


def finding(
    rule_id="headers.hsts",
    severity="medium",
    confidence="high",
    evidence="Observed condition",
    recommendation="Review and correct the condition.",
    title="Observed issue",
):
    return Finding(rule_id, title, severity, "test", evidence, recommendation, confidence)


def response(url="https://example.com/", findings=(), **changes):
    return replace(
        CheckResult(
            url=url,
            status=200,
            size=100,
            elapsed_ms=2,
            scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
            findings=tuple(findings),
        ),
        **changes,
    )


def test_priority_uses_maximum_severity_then_distinct_urls_then_rule_id():
    results = [
        response(
            findings=(
                finding("b.high", "high"),
                finding("a.high", "high"),
                finding("z.widespread", "low"),
                finding("z.medium", "medium"),
            )
        ),
        response("https://example.com/login", [finding("z.widespread", "high")]),
        response("https://example.com/health", [finding("z.medium", "medium")]),
        response(findings=(finding("b.high", "high"),)),
    ]
    plan = build_action_plan(results)

    assert [task["rule_id"] for task in plan["tasks"]] == [
        "z.widespread",
        "a.high",
        "b.high",
        "z.medium",
    ]
    assert plan["tasks"][0]["severity"] == "high"
    assert len(plan["tasks"][2]["urls"]) == 1
    assert "2 distinct affected URLs" in plan["tasks"][0]["priority_reason"]
    assert "severity, then affected URL count, then rule ID" in plan["tasks"][0]["priority_reason"]
    assert plan["coverage"]["total_urls"] == 3


def test_same_rule_and_url_preserve_evidence_recommendation_confidence_and_severity_variations():
    first = finding("cookies.secure", evidence="Cookie session lacks Secure.")
    variants = [
        first,
        replace(first, evidence="Cookie preferences lacks Secure."),
        replace(first, recommendation="Set Secure after HTTPS migration."),
        replace(first, confidence="medium"),
        replace(first, confidence="low"),
        replace(first, severity="high"),
    ]
    results = [response(findings=variants), response(findings=(first,))]
    task = build_action_plan(results)["tasks"][0]

    assert len(task["observations"]) == 6
    assert task["urls"] == ["https://example.com/"]
    assert task["confidences"] == ["low", "medium", "high"]
    assert {tuple(sorted(observation.items())) for observation in task["observations"]} == {
        tuple(
            sorted(
                {
                    "url": "https://example.com/",
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "evidence": item.evidence,
                    "recommendation": item.recommendation,
                }.items()
            )
        )
        for item in variants
    }
    assert task["next_step"] == "validate"
    assert task["recommendations"] == [
        "Review and correct the condition.",
        "Set Secure after HTTPS migration.",
    ]


def test_plan_is_deterministic_serializable_and_does_not_mutate_inputs():
    observations = [
        finding(title="Z issue", severity="high", evidence="B"),
        finding(title="A issue", severity="high", evidence="A"),
        finding(title="A lower-severity title", severity="low", evidence="C"),
    ]
    results = [
        response("https://example.com/z", observations, status=503),
        response("https://example.com/a", reversed(observations)),
    ]
    original_order = list(results)
    permuted = [
        replace(item, findings=tuple(reversed(item.findings))) for item in reversed(results)
    ]
    plan = build_action_plan(results)

    assert plan == build_action_plan(permuted)
    assert json.loads(json.dumps(plan)) == plan
    assert results == original_order
    assert plan["tasks"][0]["title"] == "A issue"
    assert plan["tasks"][0]["urls"] == ["https://example.com/a", "https://example.com/z"]


@pytest.mark.parametrize("confidence", ["low", "medium"])
def test_any_uncertain_observation_requires_validation(confidence):
    results = [
        response(findings=(finding(confidence="high"),)),
        response("https://example.com/login", [finding(confidence=confidence)]),
    ]
    assert build_action_plan(results)["tasks"][0]["next_step"] == "validate"


@pytest.mark.parametrize(
    "changes",
    [
        {"status": None},
        {"status": 302},
        {"status": 503},
        {"error": "Connection interrupted"},
        {"truncated": True},
    ],
)
def test_any_incomplete_observation_requires_validation_even_if_repeated_successfully(changes):
    item = finding()
    results = [response(findings=(item,)), response(findings=(item,), **changes)]
    assert build_action_plan(results)["tasks"][0]["next_step"] == "validate"


def test_complete_high_confidence_observations_can_proceed_to_fix():
    plan = build_action_plan([response(findings=(finding(),))])
    assert plan["tasks"][0]["next_step"] == "fix"


def test_informational_observations_request_review_even_when_uncertain_or_incomplete():
    plan = build_action_plan(
        [response(findings=(finding("info.stack_headers", "info", "low"),), status=503)]
    )
    assert plan["tasks"][0]["next_step"] == "review"


def test_coverage_counts_distinct_urls_and_preserves_all_incomplete_response_reasons():
    results = [
        response("https://example.com/ok"),
        response("https://example.com/failure", status=None, error="Timeout", truncated=True),
        response("https://example.com/failure", status=503),
        response("https://example.com/failure"),
        response("https://example.com/redirect", status=302),
        response("https://example.com/empty", status=204),
    ]
    plan = build_action_plan(results)

    assert plan["tasks"] == []
    assert plan["coverage"] == {
        "total_urls": 4,
        "incomplete_urls": [
            {
                "url": "https://example.com/failure",
                "reasons": [
                    "HTTP status 503 is not 2xx",
                    "No HTTP response",
                    "Request error",
                    "Response truncated",
                ],
            },
            {
                "url": "https://example.com/redirect",
                "reasons": ["HTTP status 302 is not 2xx"],
            },
        ],
    }


def test_empty_input_has_no_tasks_and_does_not_claim_verification():
    assert build_action_plan([]) == {
        "tasks": [],
        "coverage": {"total_urls": 0, "incomplete_urls": []},
    }


@pytest.mark.parametrize(
    "rule_id", ["headers.csp", "headers.csp_report_only", "headers.referrer_policy"]
)
def test_automatic_policy_rechecks_only_claim_header_presence(rule_id):
    task = build_action_plan([response(findings=(finding(rule_id),))])["tasks"][0]
    assert task["recheck_mode"] == "automatic"
    assert "header-presence check" in task["recheck"]
    assert "not a check of the policy's safety" in task["recheck"]
    assert "complete 2xx response without errors or truncation" in task["recheck"]


@pytest.mark.parametrize(
    "rule_id", ["cookies.secure", "dns.spf_missing", "cms.example", "js.secret", "custom.rule"]
)
def test_unsupported_rules_require_manual_recheck(rule_id):
    task = build_action_plan([response(findings=(finding(rule_id),))])["tasks"][0]
    assert task["recheck_mode"] == "manual"
    assert "same URL with the same settings" in task["recheck"]
    assert "an absent finding alone does not confirm a fix" in task["recheck"]


def test_empty_recommendations_remain_in_observations_but_not_in_action_list():
    task = build_action_plan(
        [response(findings=(finding(recommendation=""), finding(recommendation="   "), finding()))]
    )["tasks"][0]
    assert task["recommendations"] == ["Review and correct the condition."]
    assert len(task["observations"]) == 3
