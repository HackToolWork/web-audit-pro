import pytest
from pathlib import Path

from web_audit.cms import fingerprint, findings as cms_findings
from web_audit.dns_audit import DNSReport, findings as dns_findings
from web_audit.js_audit import analyze_js, discover_script_urls


def test_js_discovery_is_same_origin():
    body = b'<script src="/app.js"></script><script src="https://evil.example/a.js"></script>'
    assert discover_script_urls("https://example.com/", body) == ("https://example.com/app.js",)


def test_js_secret_is_redacted():
    value = b"AIza123456789012345678901234567890"
    findings = analyze_js("https://example.com/app.js", b'const token="' + value + b'";')
    assert findings
    assert "REDACTED" in findings[0].evidence
    assert value.decode() not in findings[0].evidence


def test_js_private_key_is_high_severity():
    findings = analyze_js("https://example.com/app.js", b"-----BEGIN RSA PRIVATE KEY-----")
    assert findings[0].severity == "high"


def test_cms_wordpress_fingerprint():
    headers = {"Link": '<https://example.com/wp-json/>; rel="https://api.w.org/"'}
    body = b'<script src="/wp-content/js/app.js"></script>'
    matches = fingerprint("https://example.com/", headers, body)
    assert any(match.product == "WordPress" for match in matches)
    assert cms_findings(matches)


def test_dns_permissive_spf():
    report = DNSReport("example.com", (), (), (), (), ("v=spf1 +all",), ())
    findings = dns_findings(report)
    assert any(f.rule_id == "dns.spf.permissive_all" for f in findings)


def test_ct_discovery_filters_outside_domain(monkeypatch):
    import requests
    from web_audit.subdomains import discover_from_crtsh

    class Resp:
        def raise_for_status(self):
            return None
        def json(self):
            return [
                {"name_value": "api.example.com\n*.example.com"},
                {"name_value": "evil.example.net"},
            ]

    monkeypatch.setattr(requests, "get", lambda *a, **k: Resp())
    assert discover_from_crtsh("example.com") == ("api.example.com", "example.com")


def test_dns_multiple_spf():
    report = DNSReport("example.com", (), (), (), (), ("v=spf1 a", "v=spf1 mx"), ())
    assert any(f.rule_id == "dns.spf.multiple" for f in dns_findings(report))


def test_dashboard_requires_token(tmp_path):
    from fastapi.testclient import TestClient
    from web_audit.serve import create_app

    db = tmp_path / "audit.db"
    import sqlite3
    with sqlite3.connect(db) as conn:
        conn.executescript(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT, started_at TEXT, "
            "finished_at TEXT, result_count INTEGER);"
            "CREATE TABLE findings (severity TEXT);"
        )
    client = TestClient(create_app(db, "secret"))
    assert client.get("/").status_code == 401
    assert client.get("/?access_token=secret").status_code == 200



def test_dashboard_testclient_dependencies_are_declared():
    from pathlib import Path

    requirements = Path("requirements-dev.txt").read_text(encoding="utf-8")
    assert "httpx==0.28.1" in requirements
    assert "httpx2==2.12.0" in requirements

def test_nvd_cache_uses_existing_entry(tmp_path, monkeypatch):
    from web_audit import nvd

    cache = tmp_path / "nvd.db"
    monkeypatch.setattr(
        nvd,
        "lookup_cves",
        lambda *a, **k: [{"id": "CVE-X", "description": "test", "published": "2026"}],
    )
    first = nvd.cache_lookup(cache, "WordPress", "6.0")
    monkeypatch.setattr(
        nvd,
        "lookup_cves",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network call")),
    )
    second = nvd.cache_lookup(cache, "WordPress", "6.0")
    assert first == second


def test_tui_fallback_passes_callback(monkeypatch):
    import web_audit.tui as tui

    monkeypatch.setattr(tui, "Progress", None)
    seen = []

    def scan(callback):
        seen.append(callable(callback))
        return [1]

    assert tui.run_with_progress(scan, 1) == [1]
    assert seen == [True]


def test_dns_txt_rrset_is_flattened_and_spf_detected(monkeypatch):
    import web_audit.dns_audit as dns_audit

    class TxtRdata:
        strings = [b"v=spf1", b" -all"]

    class Resolver:
        def resolve(self, _name, record_type, lifetime):
            assert lifetime == 3.0
            return (TxtRdata(),) if record_type == "TXT" else ()

    assert dns_audit._resolve(Resolver(), "example.com", "TXT") == ("v=spf1 -all",)


def test_nvd_429_retries_after_retry_after(monkeypatch):
    from web_audit import nvd

    waits = []
    responses = []

    class Response:
        def __init__(self, status_code, payload=None, headers=None):
            self.status_code = status_code
            self._payload = payload or {}
            self.headers = headers or {}

        def raise_for_status(self):
            if self.status_code >= 400:
                raise AssertionError(f"unexpected status {self.status_code}")

        def json(self):
            return self._payload

    responses.extend([
        Response(429, headers={"Retry-After": "0"}),
        Response(200, {"vulnerabilities": []}),
    ])
    monkeypatch.setattr(nvd, "_wait_for_rate_limit", lambda _interval: None)
    monkeypatch.setattr(nvd.time, "sleep", lambda value: waits.append(value))
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: responses.pop(0))
    assert nvd.lookup_cves("WordPress", "6.0", max_attempts=2) == []
    assert waits == [0.0]


def test_tui_emits_high_alert(monkeypatch):
    import web_audit.tui as tui
    from web_audit.models import CheckResult, Finding
    from datetime import UTC, datetime

    if tui.Progress is None:
        return

    alerts = []

    class Console:
        def print(self, text):
            alerts.append(text)

    class Progress:
        console = Console()
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def add_task(self, *args, **kwargs):
            return 1
        def advance(self, *_args):
            return None

    monkeypatch.setattr(tui, "Console", Console)
    monkeypatch.setattr(tui, "Progress", Progress)
    finding = Finding("test.high", "High issue", "high", "test", "evidence", "fix")
    result = CheckResult(
        "https://example.com/", 200, 1, 1.0, datetime.now(UTC), findings=(finding,)
    )
    assert tui.run_with_progress(lambda callback: (callback(result), [result])[1], 1) == [result]
    assert any("High issue" in message for message in alerts)


def test_nvd_api_key_is_sent_without_cli_exposure(monkeypatch):
    from web_audit import nvd

    captured = {}

    class Response:
        status_code = 200
        headers = {}

        def raise_for_status(self):
            return None

        def json(self):
            return {"vulnerabilities": []}

    monkeypatch.setenv("NVD_API_KEY", "test-key")
    monkeypatch.setattr(nvd, "_wait_for_rate_limit", lambda _interval: None)

    def fake_get(*args, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(nvd.requests, "get", fake_get)
    assert nvd.lookup_cves("WordPress", "6.0") == []
    assert captured["headers"]["apiKey"] == "test-key"
    assert "test-key" not in captured["headers"]["User-Agent"]


def test_dns_txt_list_value_is_normalized_before_spf_check(monkeypatch):
    import web_audit.dns_audit as dns_audit

    class Resolver:
        def resolve(self, _name, record_type, lifetime):
            assert lifetime == 3.0
            if record_type == "TXT":
                return ([(b"v=spf1", b" ~all")],)
            return ()

    assert dns_audit._resolve(Resolver(), "example.com", "TXT") == ("v=spf1 ~all",)


def test_dns_spf_detection_handles_quoted_txt_value():
    from web_audit.dns_audit import _is_spf_record

    assert _is_spf_record('"v=spf1 include:example.com -all"') is True
    assert _is_spf_record('"not-an-spf-record"') is False


def test_local_vulndb_lookup_is_offline(tmp_path):
    from web_audit.vulndb import init_db, lookup_local
    import sqlite3

    db = tmp_path / "vulndb.sqlite3"
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO advisories "
            "(product,cve_id,version_hint,description,published,source,updated_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("WordPress", "CVE-TEST", "", "demo", "2026-01-01", "NVD", 0.0),
        )
        conn.commit()
    rows = lookup_local(db, "WordPress", "6.0")
    assert rows[0]["id"] == "CVE-TEST"


def test_local_cms_advisory_lookup_does_not_call_network(tmp_path, monkeypatch):
    from web_audit import vulndb
    db = tmp_path / "vulndb.sqlite3"
    vulndb.init_db(db)
    monkeypatch.setattr(vulndb, "lookup_cves", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("network should not be used")))
    assert vulndb.lookup_local(db, "WordPress", None) == []


def test_cli_update_db_does_not_require_target(monkeypatch, capsys):
    import web_audit.vulndb as vulndb
    from web_audit import cli

    monkeypatch.setattr(vulndb, "update_database", lambda *a, **k: (3, 0))
    assert cli.main(["--update-db"]) == 0
    assert "updated: 3 records" in capsys.readouterr().out


def test_vulndb_path_uses_environment_override(tmp_path, monkeypatch):
    from web_audit import vulndb

    override = tmp_path / "custom.sqlite3"
    monkeypatch.setenv("WEB_AUDIT_VULN_DB", str(override))
    assert vulndb.default_db_path() == override


def test_vulndb_path_uses_docker_persistent_location(monkeypatch):
    from pathlib import Path
    from web_audit import vulndb

    monkeypatch.delenv("WEB_AUDIT_VULN_DB", raising=False)
    monkeypatch.setattr(vulndb, "DOCKER_ENV_FILE", Path("/tmp/fake-dockerenv"))
    original = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self: True if self == Path("/tmp/fake-dockerenv") else original(self),
    )
    assert vulndb.default_db_path() == Path("/app/reports/vulndb.sqlite3")


def test_makefile_active_venv_missing_tools_gives_install_hint(tmp_path):
    import os
    import subprocess
    import sys

    active = tmp_path / "venv"
    bindir = active / "bin"
    bindir.mkdir(parents=True)
    (bindir / "python").symlink_to(sys.executable)
    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(active)
    result = subprocess.run(
        ["make", "test"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 2
    combined = result.stdout + result.stderr
    assert "Pytest is missing in the selected virtual environment." in combined
    assert "pip install -r requirements-dev.txt" in combined


def test_vulndb_path_uses_xdg_cache_home(monkeypatch, tmp_path):
    from pathlib import Path
    from web_audit import vulndb

    monkeypatch.delenv("WEB_AUDIT_VULN_DB", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(vulndb, "DOCKER_ENV_FILE", tmp_path / "missing-dockerenv")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    assert vulndb.default_db_path() == tmp_path / "cache" / "web-audit-pro" / "vulndb.sqlite3"


def test_nvd_retry_after_http_date(monkeypatch):
    import time
    from email.utils import formatdate
    from web_audit import nvd

    waits = []

    class Response:
        status_code = 429
        headers = {
        "Retry-After": formatdate(timeval=time.time() + 2, usegmt=True),
    }

        def raise_for_status(self):
            raise AssertionError("should retry before terminal raise")

    class OK:
        status_code = 200
        headers = {}

        def raise_for_status(self):
            return None

        def json(self):
            return {"vulnerabilities": []}

    responses = [Response(), OK()]
    monkeypatch.setattr(nvd, "_wait_for_rate_limit", lambda _interval: None)
    monkeypatch.setattr(nvd.time, "sleep", lambda value: waits.append(value))
    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: responses.pop(0))
    assert nvd.lookup_cves("WordPress", None, max_attempts=2) == []
    assert waits and 0 <= waits[0] <= 300


def test_vulndb_local_lookup_uses_read_only_connection(tmp_path, monkeypatch):
    import sqlite3
    from web_audit import vulndb

    db = tmp_path / "vulndb.sqlite3"
    vulndb.init_db(db)
    original_connect = vulndb.sqlite3.connect
    calls = []

    def spy_connect(*args, **kwargs):
        calls.append((args, kwargs))
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(vulndb.sqlite3, "connect", spy_connect)
    assert vulndb.lookup_local(db, "WordPress", None) == []
    assert calls and calls[-1][0][0].endswith("?mode=ro")
    assert calls[-1][1]["uri"] is True

    with sqlite3.connect(calls[-1][0][0], uri=True) as conn:
        with __import__("pytest").raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO advisories VALUES ('x','y','','','','NVD',0)")


def test_report_filenames_are_unique(tmp_path):
    from datetime import UTC, datetime
    from web_audit.cli import _run_output_paths
    from web_audit.config import Settings

    settings = Settings(output_dir=tmp_path)
    started = datetime(2026, 9, 9, tzinfo=UTC)
    _run_output_paths(settings, "https://example.com/", started)
    names = {settings.csv_name, settings.html_name, settings.json_name, settings.sarif_name}
    assert len(names) == 4
    assert all("20260909T000000Z" in name for name in names)


def test_nvd_retry_after_invalid_value_uses_safe_fallback(monkeypatch):
    from web_audit import nvd

    class Response:
        status_code = 429
        headers = {"Retry-After": "not-a-delay"}

    assert nvd._retry_after(Response()) == 6.0


def test_vulndb_writer_uses_wal_and_local_lookup_is_read_only(tmp_path):
    from web_audit import vulndb

    db = tmp_path / "vulndb.sqlite3"
    vulndb.init_db(db)
    with __import__("sqlite3").connect(db) as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
    assert vulndb.lookup_local(db, "WordPress", None) == []


def test_report_output_paths_do_not_overwrite_defaults(tmp_path):
    from datetime import UTC, datetime
    from web_audit.cli import _run_output_paths
    from web_audit.config import Settings

    settings = Settings(output_dir=tmp_path)
    _run_output_paths(settings, "https://example.com/", datetime.now(UTC))
    assert settings.html_name != "report.html"
    assert settings.json_name != "report.json"
    assert settings.sarif_name != "report.sarif"
    assert settings.log_name != "scanner.log"


def test_report_output_paths_preserve_explicit_json_name(tmp_path):
    from datetime import UTC, datetime
    from web_audit.cli import _run_output_paths
    from web_audit.config import Settings

    settings = Settings(output_dir=tmp_path, json_name="custom.json")
    _run_output_paths(settings, "https://example.com/", datetime.now(UTC))
    assert settings.json_name == "custom.json"


def test_report_output_paths_include_unique_run_id(tmp_path):
    from datetime import UTC, datetime
    from web_audit.cli import _run_output_paths
    from web_audit.config import Settings

    started = datetime(2026, 9, 9, tzinfo=UTC)
    first = Settings(output_dir=tmp_path)
    second = Settings(output_dir=tmp_path)
    _run_output_paths(first, "https://example.com/", started)
    _run_output_paths(second, "https://example.com/", started)
    assert first.json_name != second.json_name
    assert first.sarif_name != second.sarif_name
    assert first.log_name != second.log_name


def test_local_vulndb_is_read_only(tmp_path):
    import sqlite3
    from web_audit.vulndb import init_db, lookup_local

    db = tmp_path / "vulndb.sqlite3"
    init_db(db)
    rows = lookup_local(db, "WordPress", None)
    assert rows == []
    with pytest.raises(sqlite3.OperationalError):
        uri = db.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            conn.execute("PRAGMA query_only = ON")
            conn.execute("INSERT INTO advisories VALUES ('x','y','','d','p','s',0)")


def test_update_database_initializes_inside_writer_lock(tmp_path, monkeypatch):
    from web_audit import vulndb

    db = tmp_path / "vulndb.sqlite3"
    monkeypatch.setattr(vulndb, "_db", lambda: [{"product": "WordPress"}])
    monkeypatch.setattr(vulndb, "lookup_cves", lambda *a, **k: [])
    updated, failed = vulndb.update_database(db)
    assert (updated, failed) == (0, 0)
    assert db.exists()
