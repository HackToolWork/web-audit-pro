import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from web_audit import cli
from web_audit.models import CheckResult, Finding
from web_audit.owner_report import AREAS, build_owner_summary, render_owner_report_html
from web_audit.owner_texts import LANGUAGES, RULE_TEXTS, UI, rule_text

ALL_CHECKED = {area: "checked" for area in AREAS}


def _finding(rule_id, severity="low", evidence="evidence", confidence="high"):
    return Finding(rule_id, f"title {rule_id}", severity, "cat", evidence, "fix it", confidence)


def _result(*findings, status=200, url="https://example.com/"):
    return CheckResult(
        url=url,
        status=status,
        size=0,
        elapsed_ms=1.0,
        scanned_at=datetime.now(UTC),
        findings=tuple(findings),
    )


def test_every_emitted_rule_has_plain_language_text():
    package = Path(cli.__file__).parent
    source = "".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))
    emitted = set(
        re.findall(
            r'"((?:headers|cookies|cors|info|redirect|dns|tls)\.[a-z_]+(?:\.[a-z_]+)?)"', source
        )
    )
    assert emitted, "rule extraction pattern no longer matches the source"
    missing = sorted(rule for rule in emitted if rule_text(rule, "en") is None)
    assert missing == []


def test_texts_exist_for_every_language():
    for rule_id, texts in RULE_TEXTS.items():
        assert set(texts) == set(LANGUAGES), rule_id
        assert all(all(part.strip() for part in text) for text in texts.values()), rule_id
    assert set(UI["ru"]) == set(UI["en"])
    assert rule_text("secret.jwt", "ru") is not None
    assert rule_text("cms.detected.wordpress", "ru") is not None


@pytest.mark.parametrize(
    ("findings", "status"),
    [
        ((_finding("tls.certificate_expired", "high"),), "red"),
        ((_finding("dns.dmarc.missing", "medium"),), "yellow"),
        ((_finding("headers.csp", "low"), _finding("info.stack_headers", "info")), "green"),
        ((), "green"),
    ],
)
def test_traffic_light_follows_highest_severity(findings, status):
    data = build_owner_summary([_result(*findings)], coverage=ALL_CHECKED)
    assert data["status"] == status


def test_unreachable_site_is_unknown_not_green():
    data = build_owner_summary([_result(status=None)], coverage=ALL_CHECKED)
    assert data["status"] == "unknown"
    assert data["areas"]["site"] == "failed"


def test_known_urgent_problem_wins_over_incomplete_coverage():
    results = [_result(_finding("tls.certificate_expired", "high"), status=503)]
    assert build_owner_summary(results, coverage=ALL_CHECKED)["status"] == "red"


def test_areas_fail_closed():
    data = build_owner_summary([_result()], coverage={"tls": "failed"})
    assert data["areas"] == {
        "tls": "failed",
        "email": "not_checked",
        "site": "ok",
        "cms": "not_checked",
        "js": "not_checked",
    }


def test_area_state_follows_worst_issue():
    results = [
        _result(
            _finding("dns.spf.missing", "low"),
            _finding("tls.certificate_expiring", "high"),
            _finding("tls.certificate_invalid", "medium"),
        )
    ]
    data = build_owner_summary(results, coverage=ALL_CHECKED)
    assert data["areas"]["email"] == "issues"
    assert data["areas"]["tls"] == "urgent"


def test_cms_detection_is_never_reported_as_ok():
    detected = _finding(
        "cms.detected.wordpress",
        "info",
        evidence="Detected WordPress version 6.2.1 (generator meta).",
    )
    data = build_owner_summary([_result(detected)], coverage=ALL_CHECKED)
    assert data["areas"]["cms"] == "detected"
    assert data["area_notes"]["cms"] == ["WordPress 6.2.1"]
    assert build_owner_summary([_result()], coverage=ALL_CHECKED)["areas"]["cms"] == "not_detected"
    assert build_owner_summary([_result(detected)])["areas"]["cms"] == "not_checked"


def test_uncertain_findings_ask_for_validation():
    results = [_result(_finding("dns.dmarc.missing", "medium", confidence="medium"))]
    (item,) = build_owner_summary(results, coverage=ALL_CHECKED)["items"]
    assert item["needs_validation"] is True


def test_unknown_rule_falls_back_to_scanner_text():
    (item,) = build_owner_summary([_result(_finding("custom.rule"))])["items"]
    assert (item["title"], item["why"], item["todo"]) == ("title custom.rule", "", "fix it")


def test_lifecycle_changes_use_owner_titles():
    lifecycle = {
        "fixed": [{"rule_id": "headers.csp", "url": "u", "severity": "low"}],
        "new": [{"rule_id": "custom.rule", "url": "u", "severity": "low"}],
    }
    data = build_owner_summary([_result()], lifecycle=lifecycle, lang="ru")
    assert data["changes"]["fixed"] == [RULE_TEXTS["headers.csp"]["ru"][0]]
    assert data["changes"]["new"] == ["custom.rule"]
    assert data["changes"]["regressed"] == []


def test_rejects_unknown_language():
    with pytest.raises(ValueError):
        build_owner_summary([], lang="de")


def test_render_escapes_untrusted_values():
    results = [_result(_finding("custom.rule", evidence="<script>alert(1)</script>"))]
    data = build_owner_summary(results, coverage=ALL_CHECKED, lang="ru")
    page = render_owner_report_html("https://example.com/<x>", data, company="<b>Studio</b>")
    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;" in page
    assert "<b>Studio</b>" not in page
    assert 'lang="ru"' in page
    assert UI["ru"]["status_green"] in page


class _Scanner:
    def __init__(self, settings, proxy=None):
        pass

    def scan_target(self, target, progress_callback=None):
        finding = Finding(
            "headers.csp", "Missing CSP", "low", "headers", "No CSP header", "Add CSP"
        )
        return [_result(finding, url=target + "/")]


def _run_cli(monkeypatch, tmp_path, *extra):
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    monkeypatch.setattr(cli, "Scanner", _Scanner)
    code = cli.main(
        [
            "https://example.com",
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--no-dns",
            "--output-dir",
            str(tmp_path),
            *extra,
        ]
    )
    (report,) = tmp_path.glob("owner-report-*.html")
    return code, report.read_text(encoding="utf-8")


def test_cli_writes_russian_owner_report(monkeypatch, tmp_path, capsys):
    code, page = _run_cli(monkeypatch, tmp_path, "--lang", "ru", "--company", "Студия Пример")
    assert code == 0
    assert "OWNER:" in capsys.readouterr().out
    assert UI["ru"]["title"] in page
    assert "Студия Пример" in page
    assert RULE_TEXTS["headers.csp"]["ru"][0] in page
    # The offline TLS stub reports a connection failure; DNS was disabled.
    assert f'area-failed">{UI["ru"]["area_failed"]}' in page
    assert f'area-not_checked">{UI["ru"]["area_not_checked"]}' in page


def test_cli_owner_report_defaults_to_english(monkeypatch, tmp_path):
    code, page = _run_cli(monkeypatch, tmp_path)
    assert code == 0
    assert 'lang="en"' in page
    assert UI["en"]["title"] in page


def test_config_rejects_unknown_language(tmp_path, capsys):
    config = tmp_path / "web-audit.toml"
    config.write_text('[report]\nlang = "de"\n', encoding="utf-8")
    code = cli.main(
        [
            "example.com",
            "--yes-i-am-authorized",
            "--config",
            str(config),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 2
    assert "lang must be en or ru" in capsys.readouterr().out
