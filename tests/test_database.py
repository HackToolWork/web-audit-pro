from datetime import UTC, datetime

from web_audit.database import Database
from web_audit.models import CheckResult, Finding


def test_database_persists_results_and_findings(tmp_path):
    db_path = tmp_path / "audit.db"
    result = CheckResult(
        url="https://example.com/",
        status=200,
        size=10,
        elapsed_ms=2.5,
        scanned_at=datetime.now(UTC),
        findings=(Finding("headers.csp", "CSP", "low", "headers", "missing", "add CSP"),),
    )
    with Database(db_path) as db:
        scan_id = db.save_scan("https://example.com", "a", "b", [result])
        rows = db.conn.execute("SELECT * FROM results WHERE scan_id = ?", (scan_id,)).fetchall()
        findings = db.conn.execute("SELECT * FROM findings").fetchall()
    assert len(rows) == 1
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "headers.csp"
