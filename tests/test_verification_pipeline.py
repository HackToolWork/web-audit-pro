"""Exercise recheck claims across scanning, persisted reports, and CLI filters."""

from dataclasses import replace

import pytest
import requests

from web_audit import cli
from web_audit.config import Settings
from web_audit.database import Database
from web_audit.diffing import load_report
from web_audit.lifecycle_reporting import (
    summarize_lifecycle,
    summarize_lifecycle_history,
)
from web_audit.reports import save_json
from web_audit.scanner import Scanner

TARGET = "https://example.com"
URL = TARGET + "/"
CSP = "headers.csp"
BASE_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
}


class Response:
    """Only HTTP transport is faked; the scanner and security rules still run."""

    raw = object()

    def __init__(self, *, fixed=False, status=200, content_type=None, oversized=False):
        self.status_code = status
        self.headers = dict(BASE_HEADERS)
        if fixed:
            self.headers["Content-Security-Policy"] = "default-src 'self'"
        if content_type:
            self.headers["Content-Type"] = content_type
        self.chunks = [b"<html></html>"]
        if oversized:
            self.chunks.append(b"x" * 128)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def iter_content(self, chunk_size):
        yield from self.chunks


@pytest.fixture
def scan(monkeypatch):
    scanner = Scanner(
        Settings(
            paths=("/",),
            retries=0,
            requests_per_second=10000,
            max_size=64,
            dns_enabled=False,
            cms_enabled=False,
            scan_js=False,
        )
    )

    def run(response=None, *, url=URL, timeout=False):
        def get(*_args, **_kwargs):
            if timeout:
                raise requests.Timeout("test recheck timed out")
            return response

        monkeypatch.setattr(scanner._session(), "get", get)
        return scanner.check(url)

    return run


@pytest.fixture(params=["json", "sqlite"])
def persist(request, tmp_path):
    """Both supported history sources must preserve the same verification meaning."""

    def save_and_load(audits):
        if request.param == "json":
            reports = []
            for index, results in enumerate(audits):
                path = tmp_path / f"audit-{index}.json"
                save_json(TARGET, results, path)
                reports.append(load_report(path))
            return reports

        path = tmp_path / "history.db"
        with Database(path) as db:
            for index, results in enumerate(audits):
                timestamp = f"2026-09-28T{index:02d}:00:00+00:00"
                db.save_scan(TARGET, timestamp, timestamp, results)
        with Database(path) as db:
            return db.load_scan_history(TARGET)

    return save_and_load


def test_successful_csp_recheck_remains_fixed_after_persistence(scan, persist):
    before = scan(Response())
    after = scan(Response(fixed=True))
    assert any(finding.rule_id == CSP for finding in before.findings)
    assert not any(finding.rule_id == CSP for finding in after.findings)

    reports = persist([[before], [after]])
    stored_after = reports[-1]["results"][0]
    assert stored_after["verification_version"] == 1
    assert CSP in stored_after["verified_rules"]
    summary = summarize_lifecycle(*reports)
    assert summary["fixed"] == [{"url": URL, "rule_id": CSP, "severity": "low"}]
    assert summary["unverified_count"] == 0


@pytest.mark.parametrize(
    "recheck",
    ["timeout", "omitted", "other-url", "legacy", "forbidden", "redirect", "truncated", "json"],
)
def test_inconclusive_recheck_cannot_become_a_fix_after_persistence(scan, persist, recheck):
    before = scan(Response())
    if recheck == "timeout":
        current = [scan(timeout=True)]
    elif recheck == "omitted":
        current = []
    elif recheck == "other-url":
        current = [scan(Response(fixed=True), url=TARGET + "/elsewhere")]
    elif recheck == "legacy":
        # Old results have no proof of which rules actually ran successfully.
        current = [replace(scan(Response(fixed=True)), verification_version=0, verified_rules=())]
    elif recheck == "forbidden":
        current = [scan(Response(fixed=True, status=403))]
    elif recheck == "redirect":
        current = [scan(Response(fixed=True, status=302))]
    elif recheck == "truncated":
        current = [scan(Response(fixed=True, oversized=True))]
    else:
        current = [scan(Response(content_type="application/json"))]

    reports = persist([[before], current])
    summary = summarize_lifecycle(*reports)
    assert summary["fixed_count"] == 0
    assert summary["unverified_count"] == 1
    unverified = summary["unverified"][0]
    assert unverified["url"] == URL
    assert unverified["rule_id"] == CSP
    assert unverified["severity"] == "low"
    assert unverified["reason"]


@pytest.mark.parametrize("actually_fixed", [False, True])
def test_unknown_history_gap_does_not_invent_or_erase_a_verified_fix(scan, persist, actually_fixed):
    observed = scan(Response())
    audits = [[observed]]
    if actually_fixed:
        audits.append([scan(Response(fixed=True))])
    audits.extend([[scan(timeout=True)], [], [scan(Response())]])

    summary = summarize_lifecycle_history(persist(audits))
    expected = "regressed" if actually_fixed else "present"
    other = "present" if actually_fixed else "regressed"
    assert summary[expected] == [{"url": URL, "rule_id": CSP, "severity": "low"}]
    assert summary[f"{other}_count"] == 0
    assert summary["fixed_count"] == 0
    assert summary["new_count"] == 0


@pytest.mark.parametrize("compare_json", [False, True], ids=["db-history", "json-compare"])
@pytest.mark.parametrize("current_fixed", [False, True], ids=["finding-hidden", "pass-hidden"])
def test_cli_ignored_rule_cannot_claim_fix_in_json_or_database(
    monkeypatch, tmp_path, capsys, scan, compare_json, current_fixed
):
    before = scan(Response())
    current = scan(Response(fixed=current_fixed))
    if current_fixed:
        assert CSP in current.verified_rules

    output_dir = tmp_path / "reports"
    previous_path = tmp_path / "previous.json"
    save_json(TARGET, [before], previous_path)
    with Database(output_dir / "audit_results.db") as db:
        db.save_scan(TARGET, "2026-09-27T00:00:00+00:00", "", [before])

    class LocalScanner:
        def __init__(self, settings, proxy=None):
            pass

        def scan_target(self, target):
            return [current]

    monkeypatch.setattr(cli, "Scanner", LocalScanner)
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda _target: set())
    arguments = [
        TARGET,
        "--yes-i-am-authorized",
        "--paths",
        "/",
        "--no-dns",
        "--no-cms",
        "--ignore-rule",
        CSP,
        "--output-dir",
        str(output_dir),
    ]
    if compare_json:
        arguments.extend(["--compare", str(previous_path)])

    assert cli.main(arguments) == 0
    output = capsys.readouterr().out
    assert "[FIXED] headers.csp" not in output
    assert "[UNVERIFIED] headers.csp" in output

    report_paths = list(output_dir.glob("report-*.json"))
    assert len(report_paths) == 1
    current_json = load_report(report_paths[0])
    with Database(output_dir / "audit_results.db") as db:
        history = db.load_scan_history(TARGET)
    assert len(history) == 2
    for saved in (current_json["results"][0], history[-1]["results"][0]):
        assert CSP not in saved["verified_rules"]
        assert all(finding["rule_id"] != CSP for finding in saved["findings"])
    assert summarize_lifecycle(load_report(previous_path), current_json)["fixed_count"] == 0
    assert summarize_lifecycle_history(history)["fixed_count"] == 0
