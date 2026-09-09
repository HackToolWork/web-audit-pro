import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
