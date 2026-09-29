from web_audit.lifecycle_cli import render_lifecycle_summary


def test_render_lifecycle_summary_shows_counts_and_findings():
    summary = {
        "new": [
            {
                "url": "https://example.com/",
                "rule_id": "cors.wildcard_credentials",
                "severity": "medium",
            }
        ],
        "present": [
            {
                "url": "https://example.com/",
                "rule_id": "headers.hsts",
                "severity": "low",
            }
        ],
        "fixed": [
            {
                "url": "https://example.com/",
                "rule_id": "headers.referrer_policy",
                "severity": "low",
            }
        ],
        "changed": [
            {
                "url": "https://example.com/",
                "rule_id": "headers.csp",
                "previous_severity": "low",
                "severity": "medium",
            }
        ],
        "regressed": [],
        "new_count": 1,
        "present_count": 1,
        "fixed_count": 1,
        "changed_count": 1,
        "regressed_count": 0,
    }

    output = render_lifecycle_summary(summary)

    assert "Security changes" in output
    assert "NEW         1" in output
    assert "PRESENT     1" in output
    assert "FIXED       1" in output
    assert "CHANGED     1" in output
    assert "REGRESSED   0" in output

    assert "[NEW] cors.wildcard_credentials" in output
    assert "[FIXED] headers.referrer_policy" in output
    assert "[CHANGED] headers.csp (low -> medium)" in output


def test_render_lifecycle_summary_handles_no_changes():
    summary = {
        "new": [],
        "present": [],
        "fixed": [],
        "changed": [],
        "regressed": [],
        "new_count": 0,
        "present_count": 0,
        "fixed_count": 0,
        "changed_count": 0,
        "regressed_count": 0,
    }

    output = render_lifecycle_summary(summary)

    assert "Security changes" in output
    assert "No lifecycle changes." in output


def test_render_lifecycle_summary_explains_unverified_findings():
    summary = {
        "unverified_count": 1,
        "unverified": [
            {
                "rule_id": "headers.csp",
                "url": "https://example.com/",
                "severity": "low",
                "reason": "This URL was not checked in the current audit.",
            }
        ],
    }

    output = render_lifecycle_summary(summary)

    assert "UNVERIFIED  1" in output
    assert "[UNVERIFIED] headers.csp" in output
    assert "This URL was not checked in the current audit." in output
    assert "No lifecycle changes." not in output
