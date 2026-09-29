import pytest

from web_audit.lifecycle_reporting import (
    summarize_lifecycle,
    summarize_lifecycle_history,
)
from web_audit.security import SUPPORTED_VERIFICATION_RULES


def report(target, results):
    return {
        "target": target,
        "results": results,
    }


def result(url, findings, **overrides):
    return {
        "url": url,
        "findings": findings,
        "status": 200,
        "error": "",
        "truncated": False,
        "verification_version": 1,
        "verified_rules": sorted(
            SUPPORTED_VERIFICATION_RULES - {item["rule_id"] for item in findings}
        ),
        **overrides,
    }


def finding(rule_id, severity):
    return {
        "rule_id": rule_id,
        "severity": severity,
    }


def test_lifecycle_summary_tracks_new_present_fixed_and_changed():
    previous = report(
        "https://example.com",
        [
            result(
                "https://example.com/",
                [
                    finding("headers.csp", "low"),
                    finding("headers.hsts", "low"),
                    finding("headers.referrer_policy", "low"),
                ],
            )
        ],
    )

    current = report(
        "https://example.com",
        [
            result(
                "https://example.com/",
                [
                    finding("headers.csp", "medium"),
                    finding("headers.hsts", "low"),
                    finding("cors.wildcard_credentials", "medium"),
                ],
            )
        ],
    )

    summary = summarize_lifecycle(previous, current)

    assert summary["new_count"] == 1
    assert summary["present_count"] == 1
    assert summary["fixed_count"] == 1
    assert summary["changed_count"] == 1
    assert summary["regressed_count"] == 0

    assert summary["new"] == [
        {
            "url": "https://example.com/",
            "rule_id": "cors.wildcard_credentials",
            "severity": "medium",
        }
    ]

    assert summary["fixed"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.referrer_policy",
            "severity": "low",
        }
    ]

    assert summary["changed"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.csp",
            "previous_severity": "low",
            "severity": "medium",
        }
    ]

    assert summary["present"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.hsts",
            "severity": "low",
        }
    ]


def test_lifecycle_summary_ignores_duplicate_results_for_same_url():
    previous = report(
        "https://example.com",
        [
            result(
                "https://example.com/",
                [finding("headers.csp", "low")],
            ),
            result(
                "https://example.com/",
                [finding("headers.csp", "low")],
            ),
        ],
    )

    current = report(
        "https://example.com",
        [
            result(
                "https://example.com/",
                [finding("headers.csp", "low")],
            )
        ],
    )

    summary = summarize_lifecycle(previous, current)

    assert summary["new_count"] == 0
    assert summary["fixed_count"] == 0
    assert summary["changed_count"] == 0
    assert summary["present_count"] == 1


def test_lifecycle_summary_reports_target_metadata():
    previous = report(
        "https://old.example.com",
        [],
    )
    current = report(
        "https://example.com",
        [],
    )

    summary = summarize_lifecycle(previous, current)

    assert summary["previous_target"] == "https://old.example.com"
    assert summary["current_target"] == "https://example.com"


def test_lifecycle_history_detects_regression():
    history = [
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [finding("headers.csp", "low")],
                )
            ],
        ),
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [],
                )
            ],
        ),
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [finding("headers.csp", "low")],
                )
            ],
        ),
    ]

    summary = summarize_lifecycle_history(history)

    assert summary["new_count"] == 0
    assert summary["present_count"] == 0
    assert summary["fixed_count"] == 0
    assert summary["changed_count"] == 0
    assert summary["regressed_count"] == 1
    assert summary["regressed"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.csp",
            "severity": "low",
        }
    ]


def test_lifecycle_history_handles_multiple_absent_audits():
    history = [
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [finding("headers.csp", "low")],
                )
            ],
        ),
        report("https://example.com", [result("https://example.com/", [])]),
        report("https://example.com", [result("https://example.com/", [])]),
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [finding("headers.csp", "medium")],
                )
            ],
        ),
    ]

    summary = summarize_lifecycle_history(history)

    assert summary["regressed_count"] == 1
    assert summary["regressed"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.csp",
            "severity": "medium",
        }
    ]


def test_lifecycle_history_reports_fixed_on_latest_absence():
    history = [
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [finding("headers.csp", "low")],
                )
            ],
        ),
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [],
                )
            ],
        ),
    ]

    summary = summarize_lifecycle_history(history)

    assert summary["fixed_count"] == 1
    assert summary["fixed"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.csp",
            "severity": "low",
        }
    ]


def test_lifecycle_history_reports_changed_without_absence():
    history = [
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [finding("headers.csp", "low")],
                )
            ],
        ),
        report(
            "https://example.com",
            [
                result(
                    "https://example.com/",
                    [finding("headers.csp", "medium")],
                )
            ],
        ),
    ]

    summary = summarize_lifecycle_history(history)

    assert summary["changed_count"] == 1
    assert summary["changed"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.csp",
            "previous_severity": "low",
            "severity": "medium",
        }
    ]


def test_lifecycle_history_requires_at_least_one_audit():
    with pytest.raises(ValueError, match="at least one audit"):
        summarize_lifecycle_history([])


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"status": None, "error": "Timeout: request timed out"}, "error"),
        ({"status": 404}, "2xx"),
        ({"status": 301}, "2xx"),
        ({"status": 503}, "2xx"),
        ({"status": None}, "2xx"),
        ({"status": "200"}, "2xx"),
        ({"truncated": True}, "truncated"),
        ({"truncated": None}, "completeness"),
        ({"verification_version": None}, "metadata"),
        ({"verification_version": 2}, "metadata"),
        ({"verification_version": True}, "metadata"),
        ({"verified_rules": []}, "not verified as passed"),
        ({"verified_rules": "headers.csp"}, "not verified as passed"),
        ({"verified_rules": ["headers.csp", 42]}, "not verified as passed"),
        ({"verified_rules": ["headers.csp", {}]}, "not verified as passed"),
        ({"verified_rules": ["headers.csp", None]}, "not verified as passed"),
        ({"verified_rules": ("headers.csp", False)}, "not verified as passed"),
    ],
)
def test_unreliable_recheck_never_marks_finding_fixed(overrides, reason):
    previous = report(
        "https://example.com", [result("https://example.com/", [finding("headers.csp", "low")])]
    )
    current = report("https://example.com", [result("https://example.com/", [], **overrides)])

    summary = summarize_lifecycle(previous, current)

    assert summary["fixed_count"] == 0
    assert summary["unverified_count"] == 1
    assert reason in summary["unverified"][0]["reason"]


def test_missing_url_is_unverified():
    previous = report(
        "https://example.com", [result("https://example.com/", [finding("headers.csp", "low")])]
    )
    current = report("https://example.com", [result("https://example.com/other", [])])

    summary = summarize_lifecycle(previous, current)

    assert summary["fixed_count"] == 0
    assert summary["unverified_count"] == 1
    assert "URL was not checked" in summary["unverified"][0]["reason"]


def test_legacy_report_without_verification_metadata_is_unverified():
    previous = report(
        "https://example.com", [result("https://example.com/", [finding("headers.csp", "low")])]
    )
    legacy_result = result("https://example.com/", [])
    del legacy_result["verification_version"]
    del legacy_result["verified_rules"]

    summary = summarize_lifecycle(previous, report("https://example.com", [legacy_result]))

    assert summary["fixed_count"] == 0
    assert summary["unverified_count"] == 1
    assert "metadata" in summary["unverified"][0]["reason"]


@pytest.mark.parametrize(
    "rule_id", ["cms.detected.wordpress", "dns.spf.missing", "secret.jwt", "cookies.secure"]
)
def test_unsupported_rules_cannot_be_verified_by_claimed_metadata(rule_id):
    previous = report(
        "https://example.com", [result("https://example.com/", [finding(rule_id, "medium")])]
    )
    current = report(
        "https://example.com", [result("https://example.com/", [], verified_rules=[rule_id])]
    )

    summary = summarize_lifecycle(previous, current)

    assert summary["fixed_count"] == 0
    assert summary["unverified_count"] == 1
    assert "not yet supported" in summary["unverified"][0]["reason"]


def test_normalized_target_and_url_allow_verified_fix():
    previous = report(
        "https://EXAMPLE.com:443",
        [result("https://EXAMPLE.com:443", [finding("headers.csp", "low")])],
    )
    current = report("https://example.com/", [result("https://example.com/", [])])

    summary = summarize_lifecycle(previous, current)

    assert summary["fixed_count"] == 1
    assert summary["unverified_count"] == 0


@pytest.mark.parametrize("reverse", [False, True])
def test_every_duplicate_url_result_must_verify_absence(reverse):
    previous = report(
        "https://example.com", [result("https://example.com/", [finding("headers.csp", "low")])]
    )
    checks = [
        result("https://example.com/", []),
        result("https://example.com:443", [], error="Timeout", status=None),
    ]
    if reverse:
        checks.reverse()

    summary = summarize_lifecycle(previous, report("https://example.com", checks))

    assert summary["fixed_count"] == 0
    assert summary["unverified_count"] == 1


@pytest.mark.parametrize("reverse", [False, True])
def test_duplicate_present_finding_wins_over_passed_result(reverse):
    previous = report(
        "https://example.com", [result("https://example.com/", [finding("headers.csp", "low")])]
    )
    checks = [
        result("https://example.com/", [finding("headers.csp", "low")]),
        result("https://example.com/", []),
    ]
    if reverse:
        checks.reverse()

    summary = summarize_lifecycle(previous, report("https://example.com", checks))

    assert summary["fixed_count"] == 0
    assert summary["unverified_count"] == 0
    assert summary["present_count"] == 1


@pytest.mark.parametrize(("severity", "expected"), [("low", "present"), ("medium", "changed")])
def test_history_unknown_gap_does_not_create_regression(severity, expected):
    target = "https://example.com"
    history = [
        report(target, [result(target, [finding("headers.csp", "low")])]),
        report(target, [result(target, [], status=None, error="Timeout")]),
        report(target, [result(target, [finding("headers.csp", severity)])]),
    ]

    summary = summarize_lifecycle_history(history)

    assert summary["regressed_count"] == 0
    assert summary[f"{expected}_count"] == 1


def test_history_unknown_gap_preserves_prior_verified_absence():
    target = "https://example.com"
    history = [
        report(target, [result(target, [finding("headers.csp", "low")])]),
        report(target, [result(target, [])]),
        report(target, []),
        report(target, [result(target, [finding("headers.csp", "low")])]),
    ]

    summary = summarize_lifecycle_history(history)

    assert summary["regressed_count"] == 1
    assert summary["unverified_count"] == 0


def test_history_latest_unknown_is_unverified_even_after_a_fix():
    target = "https://example.com"
    history = [
        report(target, [result(target, [finding("headers.csp", "low")])]),
        report(target, [result(target, [])]),
        report(target, []),
    ]

    summary = summarize_lifecycle_history(history)

    assert summary["fixed_count"] == 0
    assert summary["unverified_count"] == 1


def test_history_verified_recheck_after_unknown_is_fixed():
    target = "https://example.com"
    history = [
        report(target, [result(target, [finding("headers.csp", "low")])]),
        report(target, []),
        report(target, [result(target, [])]),
    ]

    assert summarize_lifecycle_history(history)["fixed_count"] == 1


def test_unrelated_target_does_not_emit_fix_or_unknown_findings():
    previous = report(
        "https://other.example", [result("https://other.example/", [finding("headers.csp", "low")])]
    )
    current = report("https://example.com", [result("https://example.com/", [])])

    for summary in (
        summarize_lifecycle(previous, current),
        summarize_lifecycle_history([previous, current]),
    ):
        assert summary["fixed_count"] == 0
        assert summary["unverified_count"] == 0
