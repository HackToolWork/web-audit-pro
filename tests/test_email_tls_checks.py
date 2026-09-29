import json
import ssl
from datetime import UTC, datetime, timedelta

import pytest

from web_audit import audit, cli, dns_audit, tls_audit
from web_audit.dns_audit import DNSReport
from web_audit.models import CheckResult
from web_audit.tls_audit import CertificateReport

NOW = datetime(2026, 9, 29, tzinfo=UTC)


def _dns(dmarc=(), mx=("10 mx.example.com",), domain="example.com"):
    return DNSReport(
        "example.com", (), (), mx, (), ("v=spf1 -all",), (), dmarc, domain if dmarc else ""
    )


def _rules(findings):
    return {finding.rule_id: finding for finding in findings}


def test_dmarc_missing_is_medium_when_domain_receives_mail():
    assert _rules(dns_audit.findings(_dns()))["dns.dmarc.missing"].severity == "medium"
    assert _rules(dns_audit.findings(_dns(mx=())))["dns.dmarc.missing"].severity == "low"


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        (("v=DMARC1; p=none; rua=mailto:d@example.com",), "dns.dmarc.monitor_only"),
        (("v=DMARC1; rua=mailto:d@example.com",), "dns.dmarc.invalid_policy"),
        (("v=DMARC1; p=bogus",), "dns.dmarc.invalid_policy"),
        (("v=DMARC1; p=reject", "v=DMARC1; p=none"), "dns.dmarc.multiple"),
    ],
)
def test_dmarc_policy_problems(records, expected):
    dmarc_rules = {
        rule for rule in _rules(dns_audit.findings(_dns(records))) if rule.startswith("dns.dmarc")
    }
    assert dmarc_rules == {expected}


@pytest.mark.parametrize("policy", ["quarantine", "reject", "REJECT"])
def test_enforcing_dmarc_policy_has_no_finding(policy):
    report = _dns((f"v=DMARC1; p={policy}; rua=mailto:d@example.com",))
    assert not any(f.rule_id.startswith("dns.dmarc") for f in dns_audit.findings(report))


def test_dmarc_lookup_falls_back_to_parent_domain(monkeypatch):
    queried = []

    def resolve(resolver, name, record_type):
        queried.append((name, record_type))
        if (name, record_type) == ("_dmarc.example.com", "TXT"):
            return ("v=DMARC1; p=reject", "unrelated")
        return ()

    monkeypatch.setattr(dns_audit, "_resolve", resolve)
    report = dns_audit.inspect_domain("www.example.com")

    assert report.dmarc == ("v=DMARC1; p=reject",)
    assert report.dmarc_domain == "example.com"
    assert ("_dmarc.www.example.com", "TXT") in queried
    assert ("_dmarc.com", "TXT") not in queried


def test_tls_expiry_thresholds():
    def rules(days):
        report = CertificateReport("example.com", 443, not_after=NOW + timedelta(days=days))
        return [(f.rule_id, f.severity) for f in tls_audit.findings(report, now=NOW)]

    assert rules(90) == []
    assert rules(31) == []
    assert rules(30) == [("tls.certificate_expiring", "medium")]
    assert rules(14) == [("tls.certificate_expiring", "high")]
    assert rules(-1) == [("tls.certificate_expired", "high")]


def test_tls_verification_errors_are_high():
    expired = CertificateReport("example.com", 443, verify_error="certificate has expired")
    mismatch = CertificateReport("example.com", 443, verify_error="Hostname mismatch")
    assert [f.rule_id for f in tls_audit.findings(expired)] == ["tls.certificate_expired"]
    assert [f.rule_id for f in tls_audit.findings(mismatch)] == ["tls.certificate_invalid"]


def test_tls_connection_failure_is_not_a_certificate_finding():
    report = CertificateReport("example.com", 443, connect_error="TimeoutError: timed out")
    assert tls_audit.findings(report) == ()


def test_inspect_certificate_reports_verification_failure(monkeypatch):
    class Sock:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class Context:
        def wrap_socket(self, sock, server_hostname):
            error = ssl.SSLCertVerificationError("verify failed")
            error.verify_message = "certificate has expired"
            raise error

    monkeypatch.setattr(tls_audit.socket, "create_connection", lambda *a, **k: Sock())
    monkeypatch.setattr(tls_audit.ssl, "create_default_context", Context)

    report = tls_audit.inspect_certificate("example.com")
    assert report.verify_error == "certificate has expired"
    assert report.connect_error == ""


def test_inspect_certificate_requires_tls_1_2(monkeypatch):
    contexts = []
    real_context = ssl.create_default_context

    def capture():
        context = real_context()
        contexts.append(context)
        return context

    def refuse(*args, **kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(tls_audit.ssl, "create_default_context", capture)
    monkeypatch.setattr(tls_audit.socket, "create_connection", refuse)
    tls_audit.inspect_certificate("example.com")
    assert contexts[0].minimum_version == ssl.TLSVersion.TLSv1_2
    assert contexts[0].verify_mode == ssl.CERT_REQUIRED and contexts[0].check_hostname


def test_inspect_certificate_reports_connection_failure(monkeypatch):
    def refuse(*args, **kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(tls_audit.socket, "create_connection", refuse)
    report = tls_audit.inspect_certificate("example.com")
    assert report.connect_error.startswith("ConnectionRefusedError")
    assert report.verify_error == ""


def test_ip_literal_detection_does_not_skip_domains_with_digits():
    assert audit.is_ip_literal("192.0.2.1")
    assert audit.is_ip_literal("2001:db8::1")
    assert not audit.is_ip_literal("site24.ru")
    assert not audit.is_ip_literal("1c-bitrix.ru")


class _Scanner:
    def __init__(self, settings, proxy=None):
        pass

    def scan_target(self, target, progress_callback=None):
        return [
            CheckResult(
                url=target + "/", status=200, size=0, elapsed_ms=1.0, scanned_at=datetime.now(UTC)
            )
        ]


def _run(monkeypatch, tmp_path, *extra):
    calls = []

    def inspect(host, port=443, *, timeout=5.0):
        calls.append((host, port))
        return CertificateReport(host, port, verify_error="certificate has expired")

    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    monkeypatch.setattr(cli, "Scanner", _Scanner)
    monkeypatch.setattr(cli, "inspect_certificate", inspect)
    code = cli.main(
        [
            "https://example.com",
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--no-dns",
            "--no-cms",
            "--output-dir",
            str(tmp_path),
            *extra,
        ]
    )
    reports = [p for p in tmp_path.glob("report-*.json") if "diff" not in p.name]
    findings = [
        finding["rule_id"]
        for report in reports
        for result in json.loads(report.read_text(encoding="utf-8"))["results"]
        for finding in result["findings"]
    ]
    return code, calls, findings


def test_cli_attaches_tls_findings_to_target_result(monkeypatch, tmp_path):
    code, calls, findings = _run(monkeypatch, tmp_path)
    assert code == 0
    assert calls == [("example.com", 443)]
    assert "tls.certificate_expired" in findings


def test_cli_tls_check_can_be_disabled(monkeypatch, tmp_path):
    code, calls, findings = _run(monkeypatch, tmp_path, "--no-tls-check")
    assert code == 0
    assert calls == []
    assert "tls.certificate_expired" not in findings


def test_cli_skips_direct_tls_check_when_proxy_is_configured(monkeypatch, tmp_path, capsys):
    code, calls, _ = _run(monkeypatch, tmp_path, "--proxy", "http://127.0.0.1:8080")
    assert code == 0
    assert calls == []
    assert "proxy is configured" in capsys.readouterr().out


def test_spf_and_mx_fall_back_to_parent_domain(monkeypatch):
    records = {
        ("example.com", "TXT"): ("v=spf1 include:_spf.mail.example -all", "other"),
        ("example.com", "MX"): ("10 mx.example.com",),
        ("_dmarc.example.com", "TXT"): ("v=DMARC1; p=reject",),
    }
    monkeypatch.setattr(
        dns_audit,
        "_resolve",
        lambda resolver, name, record_type: records.get((name, record_type), ()),
    )
    report = dns_audit.inspect_domain("www.example.com")

    assert report.spf == ("v=spf1 include:_spf.mail.example -all",)
    assert (report.spf_domain, report.mx_domain) == ("example.com", "example.com")
    assert report.txt == ()
    assert dns_audit.findings(report) == ()


def test_dmarc_missing_on_www_host_uses_parent_mx_for_severity(monkeypatch):
    records = {("example.com", "MX"): ("10 mx.example.com",)}
    monkeypatch.setattr(
        dns_audit,
        "_resolve",
        lambda resolver, name, record_type: records.get((name, record_type), ()),
    )
    rules = _rules(dns_audit.findings(dns_audit.inspect_domain("www.example.com")))
    assert rules["dns.dmarc.missing"].severity == "medium"
    assert "dns.spf.missing" in rules
