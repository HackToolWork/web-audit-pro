from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from .models import CheckResult


def _verified_rules_from_json(value: str) -> list[str]:
    """Treat damaged or unsupported coverage as unknown, never as verified."""
    try:
        rules = json.loads(value)
    except (TypeError, ValueError):
        return []
    if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
        return []
    return rules


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self._create_schema()

    def _create_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                result_count INTEGER NOT NULL CHECK(result_count >= 0)
            );

            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                status INTEGER,
                size INTEGER NOT NULL CHECK(size >= 0),
                elapsed_ms REAL NOT NULL CHECK(elapsed_ms >= 0),
                scanned_at TEXT NOT NULL,
                truncated INTEGER NOT NULL CHECK(truncated IN (0, 1)),
                location TEXT NOT NULL,
                error TEXT NOT NULL,
                verified_rules TEXT NOT NULL DEFAULT '[]',
                verification_version INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                result_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'high')),
                category TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                confidence TEXT NOT NULL CHECK(confidence IN ('low', 'medium', 'high')),
                FOREIGN KEY(result_id) REFERENCES results(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_results_status ON results(status);
            CREATE INDEX IF NOT EXISTS idx_findings_result_id ON findings(result_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            """
        )
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(findings)")}
        if "confidence" not in columns:
            self.conn.execute(
                "ALTER TABLE findings ADD COLUMN confidence TEXT NOT NULL DEFAULT 'medium'"
            )
        result_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(results)")}
        if "verified_rules" not in result_columns:
            self.conn.execute(
                "ALTER TABLE results ADD COLUMN verified_rules TEXT NOT NULL DEFAULT '[]'"
            )
        if "verification_version" not in result_columns:
            self.conn.execute(
                "ALTER TABLE results ADD COLUMN verification_version INTEGER NOT NULL DEFAULT 0"
            )
        self.conn.commit()

    def save_scan(
        self,
        target: str,
        started_at: str,
        finished_at: str,
        results: Iterable[CheckResult],
    ) -> int:
        rows = list(results)
        try:
            with self.conn:
                cur = self.conn.execute(
                    "INSERT INTO scans(target, started_at, finished_at, result_count) "
                    "VALUES (?, ?, ?, ?)",
                    (target, started_at, finished_at, len(rows)),
                )
                scan_id = int(cur.lastrowid)
                for item in rows:
                    result_cur = self.conn.execute(
                        """
                        INSERT INTO results(
                            scan_id, url, status, size, elapsed_ms,
                            scanned_at, truncated, location, error,
                            verified_rules, verification_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            item.url,
                            item.status,
                            item.size,
                            item.elapsed_ms,
                            item.scanned_at.isoformat(),
                            int(item.truncated),
                            item.location,
                            item.error,
                            json.dumps(item.verified_rules),
                            item.verification_version,
                        ),
                    )
                    result_id = int(result_cur.lastrowid)
                    self.conn.executemany(
                        """
                        INSERT INTO findings(
                            result_id, rule_id, title, severity,
                            category, evidence, recommendation, confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                result_id,
                                finding.rule_id,
                                finding.title,
                                finding.severity,
                                finding.category,
                                finding.evidence,
                                finding.recommendation,
                                finding.confidence,
                            )
                            for finding in item.findings
                        ],
                    )
                return scan_id
        except Exception:
            self.conn.rollback()
            raise

    def load_scan_history(self, target: str) -> list[dict]:
        """Load historical audit snapshots for a target, oldest first."""
        scans = self.conn.execute(
            """
            SELECT id, target, started_at, finished_at, result_count
            FROM scans
            WHERE target = ?
            ORDER BY started_at ASC, id ASC
            """,
            (target,),
        ).fetchall()

        history: list[dict] = []

        for scan in scans:
            results_rows = self.conn.execute(
                """
                SELECT
                    r.id,
                    r.url,
                    r.status,
                    r.size,
                    r.elapsed_ms,
                    r.scanned_at,
                    r.truncated,
                    r.location,
                    r.error,
                    r.verified_rules,
                    r.verification_version
                FROM results AS r
                WHERE r.scan_id = ?
                ORDER BY r.id ASC
                """,
                (scan["id"],),
            ).fetchall()

            results: list[dict] = []

            for result in results_rows:
                finding_rows = self.conn.execute(
                    """
                    SELECT
                        rule_id,
                        title,
                        severity,
                        category,
                        evidence,
                        recommendation,
                        confidence
                    FROM findings
                    WHERE result_id = ?
                    ORDER BY id ASC
                    """,
                    (result["id"],),
                ).fetchall()

                results.append(
                    {
                        "url": result["url"],
                        "status": result["status"],
                        "size": result["size"],
                        "elapsed_ms": result["elapsed_ms"],
                        "scanned_at": result["scanned_at"],
                        "truncated": bool(result["truncated"]),
                        "location": result["location"],
                        "error": result["error"],
                        "verified_rules": _verified_rules_from_json(result["verified_rules"]),
                        "verification_version": result["verification_version"],
                        "findings": [dict(row) for row in finding_rows],
                    }
                )

            history.append(
                {
                    "scan_id": int(scan["id"]),
                    "target": scan["target"],
                    "started_at": scan["started_at"],
                    "finished_at": scan["finished_at"],
                    "result_count": int(scan["result_count"]),
                    "results": results,
                }
            )

        return history

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
