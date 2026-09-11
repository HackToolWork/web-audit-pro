from pathlib import Path

from web_audit import cli


def test_cli_requires_authorization():
    assert cli.main(["example.com"]) == 2


def test_cli_blocks_non_public_target(monkeypatch, tmp_path, capsys):
    import ipaddress

    monkeypatch.setattr(
        cli,
        "resolve_target_addresses",
        lambda target: {ipaddress.ip_address("127.0.0.1")},
    )
    code = cli.main(
        [
            "example.com",
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 2
    assert "non-public/reserved" in capsys.readouterr().out


def test_paths_file_is_loaded_and_deduplicated(tmp_path):
    path_file = tmp_path / "paths.txt"
    path_file.write_text("# comment\n/admin\n/admin\n/.well-known/security.txt\n", encoding="utf-8")
    assert cli._load_paths_file(path_file) == ("/admin", "/.well-known/security.txt")


def test_empty_paths_file_is_rejected(tmp_path):
    path_file = tmp_path / "paths.txt"
    path_file.write_text("# comments only\n", encoding="utf-8")
    try:
        cli._load_paths_file(path_file)
    except ValueError as exc:
        assert "no paths" in str(exc)
    else:
        raise AssertionError("expected empty paths file to fail")


def test_paths_file_normalizes_relative_entries(tmp_path):
    path_file = tmp_path / "paths.txt"
    path_file.write_text("admin\n/login\nadmin\n", encoding="utf-8")
    assert cli._load_paths_file(path_file) == ("/admin", "/login")


def test_paths_file_rejects_full_urls(tmp_path):
    path_file = tmp_path / "paths.txt"
    path_file.write_text("https://example.com/admin\n", encoding="utf-8")
    try:
        cli._load_paths_file(path_file)
    except ValueError as exc:
        assert "full URLs" in str(exc)
    else:
        raise AssertionError("expected full URL path entry to fail")


def test_wordlist_discovery_prefers_environment_override(monkeypatch, tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nhealth\n", encoding="utf-8")
    monkeypatch.setenv("WEB_AUDIT_WORDLIST", str(wordlist))
    assert cli._find_wordlist() == wordlist


def test_wordlist_discovery_falls_back_to_candidates(monkeypatch, tmp_path):
    monkeypatch.delenv("WEB_AUDIT_WORDLIST", raising=False)
    candidate = tmp_path / "common.txt"
    candidate.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(cli, "_WORDLIST_CANDIDATES", (str(candidate),))
    assert cli._find_wordlist() == candidate


def test_cli_returns_parser_error_code_for_missing_company_value():
    assert cli.main(["example.com", "--company"]) == 2


def test_cli_empty_company_value_uses_default(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())

    class DummyScanner:
        def __init__(self, settings, proxy=None):
            self.settings = settings

        def scan_target(self, target):
            from datetime import UTC, datetime

            from web_audit.models import CheckResult

            return [
                CheckResult(
                    url=target + "/",
                    status=200,
                    size=0,
                    elapsed_ms=1.0,
                    scanned_at=datetime.now(UTC),
                )
            ]

    monkeypatch.setattr(cli, "Scanner", DummyScanner)
    code = cli.main(
        [
            "https://example.com",
            "--company",
            "",
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--no-dns",
            "--no-cms",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert "using the default company name" in capsys.readouterr().out


def test_cli_help_returns_zero():
    assert cli.main(["--help"]) == 0


def test_empty_company_flag_uses_default_when_last(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())

    class DummyScanner:
        def __init__(self, settings, proxy=None):
            self.settings = settings

        def scan_target(self, target):
            from datetime import UTC, datetime

            from web_audit.models import CheckResult

            return [
                CheckResult(
                    url=target + "/",
                    status=200,
                    size=0,
                    elapsed_ms=1.0,
                    scanned_at=datetime.now(UTC),
                )
            ]

    monkeypatch.setattr(cli, "Scanner", DummyScanner)
    assert (
        cli.main(
            [
                "https://example.com",
                "--yes-i-am-authorized",
                "--company",
                "--paths",
                "/",
                "--no-dns",
                "--no-cms",
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert "using the default company name" in capsys.readouterr().out


def test_empty_company_flag_uses_default_and_continues(monkeypatch, tmp_path, capsys):
    class DummyScanner:
        def __init__(self, settings, proxy=None):
            self.settings = settings

        def scan_target(self, target):
            from datetime import UTC, datetime

            from web_audit.models import CheckResult

            return [
                CheckResult(
                    url=target + "/",
                    status=200,
                    size=0,
                    elapsed_ms=1.0,
                    scanned_at=datetime.now(UTC),
                )
            ]

    monkeypatch.setattr(cli, "Scanner", DummyScanner)
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    code = cli.main(
        [
            "https://example.com",
            "--company",
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--dns",
            "--no-cms",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert "using the default company name" in capsys.readouterr().out


def test_kali_wordlist_missing_is_informational(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_find_wordlist", lambda: None)
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())

    class DummyScanner:
        def __init__(self, settings, proxy=None):
            pass

        def scan_target(self, target):
            from datetime import UTC, datetime

            from web_audit.models import CheckResult

            return [
                CheckResult(
                    url=target + "/",
                    status=200,
                    size=0,
                    elapsed_ms=1.0,
                    scanned_at=datetime.now(UTC),
                )
            ]

    monkeypatch.setattr(cli, "Scanner", DummyScanner)
    code = cli.main(
        [
            "https://example.com",
            "--kali-wordlist",
            "--yes-i-am-authorized",
            "--no-dns",
            "--no-cms",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert "No system wordlist found; using the built-in safe path set." in capsys.readouterr().out


def test_open_report_uses_absolute_path_and_does_not_fail_scan(monkeypatch, tmp_path):
    report = tmp_path / "report.html"
    report.write_text("<html></html>", encoding="utf-8")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    assert cli._open_report(report)
    assert calls[0][0][0] == "xdg-open"
    assert Path(calls[0][0][1]).is_absolute()


def test_version_flag_prints_project_name_and_version(capsys):
    try:
        cli.main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    output = capsys.readouterr().out.strip()
    assert output == "web-audit-pro 5.0.1"


def test_cli_compare_renders_lifecycle_summary(monkeypatch, tmp_path, capsys):
    from datetime import UTC, datetime

    from web_audit.models import CheckResult, Finding

    previous_report = tmp_path / "previous.json"
    previous_report.write_text(
        """
{
  "schema_version": "4.0",
  "tool": "Web Audit Pro",
  "target": "https://example.com",
  "generated_at": "2026-09-10T00:00:00+00:00",
  "summary": {},
  "results": [
    {
      "url": "https://example.com/",
      "status": 200,
      "size": 10,
      "elapsed_ms": 1.0,
      "scanned_at": "2026-09-10T00:00:00+00:00",
      "truncated": false,
      "location": "",
      "error": "",
      "findings": [
        {
          "rule_id": "headers.referrer_policy",
          "title": "Missing Referrer-Policy header",
          "severity": "low",
          "category": "headers",
          "evidence": "missing",
          "recommendation": "Set a Referrer-Policy header.",
          "confidence": "high"
        }
      ]
    }
  ]
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())

    class DummyScanner:
        def __init__(self, settings, proxy=None):
            self.settings = settings

        def scan_target(self, target):
            return [
                CheckResult(
                    url=target + "/",
                    status=200,
                    size=10,
                    elapsed_ms=1.0,
                    scanned_at=datetime.now(UTC),
                    findings=(
                        Finding(
                            rule_id="cors.wildcard_credentials",
                            title="Wildcard CORS with credentials",
                            severity="medium",
                            category="cors",
                            evidence="Access-Control-Allow-Origin: *",
                            recommendation="Restrict allowed origins.",
                        ),
                    ),
                )
            ]

    monkeypatch.setattr(cli, "Scanner", DummyScanner)

    code = cli.main(
        [
            "https://example.com",
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--no-dns",
            "--no-cms",
            "--output-dir",
            str(tmp_path / "current"),
            "--compare",
            str(previous_report),
        ]
    )

    output = capsys.readouterr().out

    assert code == 0
    assert "DIFF:" in output
    assert "Security changes" in output
    assert "NEW         1" in output
    assert "FIXED       1" in output
    assert "[NEW] cors.wildcard_credentials" in output
    assert "[FIXED] headers.referrer_policy" in output
