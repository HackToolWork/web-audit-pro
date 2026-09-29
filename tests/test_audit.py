from datetime import UTC, datetime

from web_audit.audit import AuditRun, attach_to_primary, run_audit
from web_audit.config import Settings
from web_audit.dns_audit import DNSReport
from web_audit.models import CheckResult, Finding
from web_audit.tls_audit import CertificateReport

TARGET = "https://example.com"


def _result(url, *findings):
    return CheckResult(
        url=url, status=200, size=0, elapsed_ms=1.0, scanned_at=datetime.now(UTC), findings=findings
    )


class FakeScanner:
    scanned: list[str] = []

    def __init__(self, settings, proxy=None):
        self.proxy = proxy

    def scan_target(self, url):
        FakeScanner.scanned.append(url)
        return [_result(url + "/", Finding("headers.csp", "CSP", "low", "h", "e", "r"))]


def _dns(host):
    return DNSReport(host, (), (), (), (), (), ())  # no SPF, no DMARC


def _cert_ok(host, port, *, timeout):
    return CertificateReport(host, port, not_after=datetime(2030, 1, 1, tzinfo=UTC))


def _cert_down(host, port, *, timeout):
    return CertificateReport(host, port, connect_error="TimeoutError: timed out")


def _run(**kwargs):
    FakeScanner.scanned = []
    options = {
        "scanner_factory": FakeScanner,
        "inspect_domain": _dns,
        "inspect_certificate": _cert_ok,
    }
    options.update(kwargs)
    return run_audit(TARGET, Settings(paths=("/",)), **options)


def test_run_audit_collects_findings_and_coverage():
    run = _run()
    assert isinstance(run, AuditRun)
    rules = {f.rule_id for r in run.results for f in r.findings}
    assert {"headers.csp", "dns.spf.missing", "dns.dmarc.missing"} <= rules
    assert run.coverage == {"cms": "checked", "js": "checked", "email": "checked", "tls": "checked"}
    assert run.wp_vulns_checked_on is None


def test_run_audit_reports_messages_through_notify_only(capsys):
    messages = []
    run = _run(inspect_certificate=_cert_down, notify=messages.append, lang="ru")
    assert run.coverage["tls"] == "failed"
    assert messages == ["Предупреждение TLS: TimeoutError: timed out"]
    assert capsys.readouterr().out == ""


def test_run_audit_scans_extra_targets_once_in_order():
    _run(extra_targets=["https://example.com", "https://a.example.com"])
    assert FakeScanner.scanned == ["https://example.com", "https://a.example.com"]


def test_run_audit_uses_custom_scan_hook_and_ignores_rules():
    seen = []

    def scan(scanner, url):
        seen.append(url)
        return scanner.scan_target(url)

    run = _run(scan=scan, ignore_rules=["headers.csp"])
    assert seen == [TARGET]
    assert all(f.rule_id != "headers.csp" for r in run.results for f in r.findings)


def test_proxy_skips_direct_tls_check():
    def fail(*args, **kwargs):
        raise AssertionError("no direct TLS connection through a proxy")

    messages = []
    run = _run(proxy="http://127.0.0.1:8080", inspect_certificate=fail, notify=messages.append)
    assert run.coverage["tls"] == "not_checked"
    assert messages == ["[i] TLS certificate check skipped: a proxy is configured."]


def test_attach_to_primary_prefers_the_target_root():
    extra = (Finding("tls.certificate_expired", "t", "high", "tls", "e", "r"),)
    results = [_result("https://example.com/robots.txt"), _result("https://example.com/")]
    updated = attach_to_primary(results, TARGET, extra)
    assert updated[1].findings == extra and updated[0].findings == ()
    assert attach_to_primary([], TARGET, extra) == []


class UnreachableScanner(FakeScanner):
    def scan_target(self, url):
        return [
            CheckResult(
                url=url + "/",
                status=None,
                size=0,
                elapsed_ms=1.0,
                scanned_at=datetime.now(UTC),
                error="SSLError: certificate verify failed",
            )
        ]


def test_content_checks_fail_when_no_page_was_fetched():
    # Found on sitozor.ru: with an invalid certificate no page loads, so leaked-key
    # and CMS checks never ran and must not be reported as passing.
    run = _run(scanner_factory=UnreachableScanner)
    assert run.coverage["js"] == "failed"
    assert run.coverage["cms"] == "failed"
    assert run.coverage["email"] == "checked"


def test_disabled_content_checks_stay_not_checked():
    from web_audit.config import Settings

    settings = Settings(paths=("/",), scan_js=False, cms_enabled=False)
    run = run_audit(
        TARGET,
        settings,
        scanner_factory=UnreachableScanner,
        inspect_domain=_dns,
        inspect_certificate=_cert_ok,
    )
    assert run.coverage["js"] == "not_checked" and run.coverage["cms"] == "not_checked"
