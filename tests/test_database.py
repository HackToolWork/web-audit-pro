import sqlite3
from datetime import UTC, datetime

import pytest

from web_audit.database import Database
from web_audit.models import CheckResult, Finding


def make_result(
    url: str = "https://example.com/",
    *,
    finding: Finding | None = None,
) -> CheckResult:
    findings = (finding,) if finding is not None else ()
    return CheckResult(
        url=url,
        status=200,
        size=10,
        elapsed_ms=2.5,
        scanned_at=datetime.now(UTC),
        findings=findings,
    )


def test_database_persists_results_and_findings(tmp_path):
    db_path = tmp_path / "audit.db"
    result = make_result(
        finding=Finding(
            "headers.csp",
            "CSP",
            "low",
            "headers",
            "missing",
            "add CSP",
        )
    )

    with Database(db_path) as db:
        scan_id = db.save_scan("https://example.com", "a", "b", [result])
        rows = db.conn.execute("SELECT * FROM results WHERE scan_id = ?", (scan_id,)).fetchall()
        findings = db.conn.execute("SELECT * FROM findings").fetchall()

    assert len(rows) == 1
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "headers.csp"


def test_load_scan_history_returns_scans_oldest_first(tmp_path):
    db_path = tmp_path / "audit.db"

    with Database(db_path) as db:
        db.save_scan(
            "https://example.com",
            "2026-09-10T10:00:00+00:00",
            "2026-09-10T10:01:00+00:00",
            [
                make_result(
                    finding=Finding(
                        "headers.csp",
                        "CSP",
                        "low",
                        "headers",
                        "missing",
                        "add CSP",
                    )
                )
            ],
        )
        db.save_scan(
            "https://example.com",
            "2026-09-10T11:00:00+00:00",
            "2026-09-10T11:01:00+00:00",
            [make_result()],
        )

        history = db.load_scan_history("https://example.com")

    assert len(history) == 2
    assert history[0]["started_at"] == "2026-09-10T10:00:00+00:00"
    assert history[1]["started_at"] == "2026-09-10T11:00:00+00:00"
    assert history[0]["results"][0]["findings"][0]["rule_id"] == "headers.csp"
    assert history[1]["results"][0]["findings"] == []


def test_load_scan_history_groups_findings_by_result(tmp_path):
    db_path = tmp_path / "audit.db"

    first = make_result(
        finding=Finding(
            "headers.csp",
            "CSP",
            "low",
            "headers",
            "missing",
            "add CSP",
        )
    )
    second = make_result(
        url="https://example.com/login",
        finding=Finding(
            "auth.form",
            "Login form",
            "medium",
            "auth",
            "form",
            "review auth",
        ),
    )

    with Database(db_path) as db:
        db.save_scan(
            "https://example.com",
            "2026-09-10T10:00:00+00:00",
            "2026-09-10T10:01:00+00:00",
            [first, second],
        )

        history = db.load_scan_history("https://example.com")

    assert len(history) == 1
    assert len(history[0]["results"]) == 2
    assert history[0]["results"][0]["url"] == "https://example.com/"
    assert history[0]["results"][0]["findings"][0]["rule_id"] == "headers.csp"
    assert history[0]["results"][1]["url"] == "https://example.com/login"
    assert history[0]["results"][1]["findings"][0]["rule_id"] == "auth.form"


def test_load_scan_history_ignores_other_targets(tmp_path):
    db_path = tmp_path / "audit.db"

    with Database(db_path) as db:
        db.save_scan(
            "https://example.com",
            "2026-09-10T10:00:00+00:00",
            "2026-09-10T10:01:00+00:00",
            [make_result()],
        )
        db.save_scan(
            "https://other.example",
            "2026-09-10T11:00:00+00:00",
            "2026-09-10T11:01:00+00:00",
            [make_result("https://other.example/")],
        )

        history = db.load_scan_history("https://example.com")

    assert len(history) == 1
    assert history[0]["target"] == "https://example.com"


def test_legacy_database_migration_preserves_results_as_unverified(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY, target TEXT, started_at TEXT,
                finished_at TEXT, result_count INTEGER
            );
            CREATE TABLE results (
                id INTEGER PRIMARY KEY, scan_id INTEGER, url TEXT, status INTEGER,
                size INTEGER, elapsed_ms REAL, scanned_at TEXT, truncated INTEGER,
                location TEXT, error TEXT
            );
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY, result_id INTEGER, rule_id TEXT, title TEXT,
                severity TEXT, category TEXT, evidence TEXT, recommendation TEXT,
                confidence TEXT
            );
            INSERT INTO scans VALUES (1, 'https://example.com', 'a', 'b', 1);
            INSERT INTO results VALUES (
                1, 1, 'https://example.com/', 200, 10, 1.0, 'a', 0, '', ''
            );
            INSERT INTO findings VALUES (
                1, 1, 'headers.csp', 'CSP', 'low', 'headers', 'missing', 'add CSP', 'high'
            );
        """)

    # Reopening must be safe as well as the initial migration.
    for _ in range(2):
        with Database(path) as db:
            result = db.load_scan_history("https://example.com")[0]["results"][0]
            assert result["url"] == "https://example.com/"
            assert result["findings"][0]["rule_id"] == "headers.csp"
            assert result["verification_version"] == 0
            assert result["verified_rules"] == []


@pytest.mark.parametrize("stored_rules", ["[", '"headers.csp"', "{}", '["headers.csp", 1]'])
def test_damaged_verification_metadata_is_unknown(tmp_path, stored_rules):
    with Database(tmp_path / "audit.db") as db:
        db.save_scan("https://example.com", "a", "b", [make_result()])
        db.conn.execute(
            "UPDATE results SET verified_rules = ?, verification_version = 1", (stored_rules,)
        )
        result = db.load_scan_history("https://example.com")[0]["results"][0]
    assert result["verified_rules"] == []
