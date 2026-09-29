import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from web_audit.config import Settings
from web_audit.scanner import Scanner


class FakeResponse:
    status_code = 200
    headers = {"Content-Type": "text/plain"}
    raw = object()

    def __init__(self, chunks):
        self.chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size):
        yield from self.chunks


def test_exact_max_size_is_not_marked_truncated(monkeypatch):
    scanner = Scanner(Settings(max_size=4, retries=0, paths=("/",)))
    monkeypatch.setattr(scanner._session(), "get", lambda *a, **k: FakeResponse([b"abcd"]))
    result = scanner.check("https://example.com/")
    assert result.size == 4
    assert result.truncated is False


def test_oversized_response_is_marked_truncated(monkeypatch):
    scanner = Scanner(Settings(max_size=4, retries=0, paths=("/",)))
    monkeypatch.setattr(scanner._session(), "get", lambda *a, **k: FakeResponse([b"abcd", b"e"]))
    result = scanner.check("https://example.com/")
    assert result.size == 4
    assert result.truncated is True


def test_request_errors_are_returned_as_results(monkeypatch):
    scanner = Scanner(Settings(retries=0, paths=("/",)))

    def fail(*args, **kwargs):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(scanner._session(), "get", fail)
    result = scanner.check("https://example.com/")
    assert result.status is None
    assert result.error.startswith("Timeout:")


def test_tls_verification_setting_is_forwarded(monkeypatch):
    scanner = Scanner(Settings(verify_tls=False, retries=0, paths=("/",)))
    captured = {}

    def get(*args, **kwargs):
        captured.update(kwargs)
        return FakeResponse([b"ok"])

    monkeypatch.setattr(scanner._session(), "get", get)
    scanner.check("https://example.com/")
    assert captured["verify"] is False


def test_scanner_can_complete_real_local_http_workflow():
    class Handler(BaseHTTPRequestHandler):
        requests_seen = []

        def do_GET(self):  # noqa: N802 - stdlib handler API
            self.__class__.requests_seen.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", "12")
            self.end_headers()
            self.wfile.write(b"hello world!")

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        settings = Settings(
            paths=("/", "/health"),
            threads=2,
            requests_per_second=1000,
            retries=0,
        )
        scanner = Scanner(settings)
        results = scanner.scan_target(f"http://127.0.0.1:{server.server_port}")
        assert [result.status for result in results] == [200, 200]
        assert set(Handler.requests_seen) == {"/", "/health"}
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def verification_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler API
            if self.path == "/timeout":
                time.sleep(0.2)
                self.close_connection = True
                return
            status = {"/error": 503, "/redirect": 302}.get(self.path, 200)
            body = b"a" * 64 if self.path == "/oversized" else b"<html>ok</html>"
            # Avoid the stdlib's automatically disclosed Server header in this fixture.
            self.send_response_only(status)
            self.send_header(
                "Content-Type", "application/json" if self.path == "/json" else "text/html"
            )
            self.send_header(
                "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header(
                "Content-Length", "100" if self.path == "/incomplete" else str(len(body))
            )
            if status == 302:
                self.send_header("Location", "/ok")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_scanner_records_positive_verification_from_completed_http_response(verification_server):
    scanner = Scanner(Settings(retries=0, scan_js=False, cms_enabled=False))
    result = scanner.check(f"{verification_server}/ok")
    assert result.status == 200
    assert result.error == ""
    assert result.verification_version == 1
    assert set(result.verified_rules) == {
        "headers.content_type_options",
        "headers.csp",
        "headers.csp_report_only",
        "headers.referrer_policy",
        "headers.clickjacking",
        "cors.wildcard_credentials",
        "info.stack_headers",
    }
    # HSTS on this plain-HTTP response cannot verify either HTTPS finding.
    assert "headers.hsts" not in result.verified_rules


def test_scanner_does_not_verify_html_rules_when_resource_changes_type(verification_server):
    scanner = Scanner(Settings(retries=0, scan_js=False, cms_enabled=False))
    result = scanner.check(f"{verification_server}/json")
    assert result.verification_version == 1
    assert "headers.content_type_options" in result.verified_rules
    assert not {"headers.csp", "headers.csp_report_only", "headers.clickjacking"} & set(
        result.verified_rules
    )


@pytest.mark.parametrize(
    ("path", "status", "truncated"),
    [("/error", 503, False), ("/redirect", 302, False), ("/oversized", 200, True)],
)
def test_scanner_does_not_verify_error_redirect_or_truncated_responses(
    verification_server, path, status, truncated
):
    scanner = Scanner(Settings(retries=0, max_size=16, scan_js=False, cms_enabled=False))
    result = scanner.check(f"{verification_server}{path}")
    assert result.status == status
    assert result.truncated is truncated
    assert result.verification_version == 0
    assert result.verified_rules == ()


@pytest.mark.parametrize("path", ["/timeout", "/incomplete"])
def test_scanner_does_not_verify_timed_out_or_incomplete_responses(verification_server, path):
    scanner = Scanner(Settings(retries=0, timeout=0.05, scan_js=False, cms_enabled=False))
    result = scanner.check(f"{verification_server}{path}")
    assert result.status is None
    assert result.error
    assert result.verification_version == 0
    assert result.verified_rules == ()
