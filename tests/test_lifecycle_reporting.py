import pytest

from web_audit.lifecycle_reporting import (
    summarize_lifecycle,
    summarize_lifecycle_history,
)


def report(target, results):
    return {
        "target": target,
        "results": results,
    }


def result(url, findings):
    return {
        "url": url,
        "findings": findings,
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
