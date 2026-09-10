from web_audit.diffing import compare_reports


def test_compare_reports_tracks_added_and_removed_findings():
    previous = {
        "target": "https://example.com",
        "results": [
            {
                "url": "https://example.com/",
                "findings": [{"rule_id": "a", "severity": "low"}],
            }
        ],
    }
    current = {
        "target": "https://example.com",
        "results": [
            {
                "url": "https://example.com/",
                "findings": [{"rule_id": "b", "severity": "medium"}],
            }
        ],
    }
    diff = compare_reports(previous, current)
    assert diff["added"] == [{"url": "https://example.com/", "rule_id": "b", "severity": "medium"}]
    assert diff["removed"] == [{"url": "https://example.com/", "rule_id": "a", "severity": "low"}]


def test_compare_reports_detects_severity_change():
    previous = {
        "target": "https://example.com",
        "results": [
            {
                "url": "https://example.com/",
                "findings": [{"rule_id": "headers.csp", "severity": "low"}],
            }
        ],
    }
    current = {
        "target": "https://example.com",
        "results": [
            {
                "url": "https://example.com/",
                "findings": [{"rule_id": "headers.csp", "severity": "medium"}],
            }
        ],
    }

    diff = compare_reports(previous, current)

    assert diff["added"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.csp",
            "severity": "medium",
        }
    ]
    assert diff["removed"] == [
        {
            "url": "https://example.com/",
            "rule_id": "headers.csp",
            "severity": "low",
        }
    ]


def test_compare_reports_preserves_findings_from_duplicate_results():
    previous = {
        "target": "https://example.com",
        "results": [
            {
                "url": "https://example.com/",
                "findings": [{"rule_id": "a", "severity": "low"}],
            },
            {
                "url": "https://example.com/",
                "findings": [{"rule_id": "b", "severity": "medium"}],
            },
        ],
    }
    current = {
        "target": "https://example.com",
        "results": [
            {
                "url": "https://example.com/",
                "findings": [
                    {"rule_id": "a", "severity": "low"},
                    {"rule_id": "b", "severity": "medium"},
                ],
            }
        ],
    }

    diff = compare_reports(previous, current)

    assert diff["added"] == []
    assert diff["removed"] == []
