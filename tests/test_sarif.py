import json
from datetime import UTC, datetime

from web_audit.models import CheckResult, Finding
from web_audit.sarif import save_sarif


def test_sarif_is_valid_shape(tmp_path):
    result = CheckResult(
        "https://example.com/",
        200,
        10,
        2.0,
        datetime.now(UTC),
        findings=(
            Finding(
                "headers.csp",
                "CSP missing",
                "low",
                "security_headers",
                "missing",
                "add CSP",
            ),
        ),
    )
    path = tmp_path / "report.sarif"
    save_sarif([result], path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "headers.csp"


def test_sarif_uses_target_uri_not_host_filesystem_path(tmp_path):
    from datetime import UTC, datetime

    from web_audit.models import CheckResult, Finding

    result = CheckResult(
        "https://example.com/path",
        200,
        1,
        0.1,
        datetime.now(UTC),
        findings=(Finding("headers.csp", "CSP missing", "low", "headers", "missing", "add CSP"),),
    )
    path = tmp_path / "report.sarif"
    save_sarif([result], path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "https://example.com/path"
    assert str(tmp_path) not in uri
