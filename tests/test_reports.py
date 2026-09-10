import json
from datetime import UTC, datetime

from web_audit.models import CheckResult, Finding
from web_audit.reports import save_csv, save_html, save_json, summary


def item(status, findings=()):
    return CheckResult(
        url="https://example.com/",
        status=status,
        size=100,
        elapsed_ms=10.0,
        scanned_at=datetime.now(UTC),
        findings=tuple(findings),
    )


def test_summary():
    finding = Finding("x", "test", "medium", "test", "evidence", "fix")
    stats = summary([item(200, [finding]), item(301), item(404), item(500), item(None)])
    assert stats == {
        "total": 5,
        "2xx": 1,
        "3xx": 1,
        "4xx": 1,
        "5xx": 1,
        "errors": 1,
        "findings": 1,
        "unique_findings": 1,
        "high": 0,
        "medium": 1,
        "low": 0,
        "info": 0,
    }


def test_summary_counts_unique_findings_by_rule_id():
    first = Finding("headers.csp", "CSP missing", "low", "headers", "evidence", "fix")
    same_rule = Finding("headers.csp", "CSP missing", "low", "headers", "different evidence", "fix")
    other = Finding("headers.hsts", "HSTS missing", "medium", "headers", "evidence", "fix")

    stats = summary([item(200, [first, other]), item(404, [same_rule])])

    assert stats["findings"] == 3
    assert stats["unique_findings"] == 2


def test_reports_are_written_and_html_is_escaped(tmp_path):
    finding = Finding("x", "<b>bad</b>", "low", "test", "<script>", "fix")
    results = [item(200, [finding])]
    csv_path = tmp_path / "report.csv"
    html_path = tmp_path / "report.html"
    json_path = tmp_path / "report.json"

    save_csv(results, csv_path)
    save_html("<target&>", results, html_path)
    save_json("<target&>", results, json_path)

    assert "<script>" not in html_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["findings"] == 1
    assert csv_path.read_text(encoding="utf-8").startswith("url,status,")
