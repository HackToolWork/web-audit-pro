"""End-to-end CLI runs through the real Scanner, database and reports.

Only the HTTP layer is replaced. These tests exist because unit tests built
findings by hand and missed a CMS finding that could not be stored.
"""

import json

import pytest
import requests

from web_audit import cli
from web_audit.database import Database
from web_audit.models import Finding

WORDPRESS_HOME = b"""<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.3">
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.3.1">
<script src="/wp-content/plugins/contact-form-7/includes/js/scripts.js?ver=5.3.1"></script>
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body>Shop</body></html>"""


class _Raw:
    headers = None


class _Response:
    def __init__(self, url):
        self.url = url
        is_home = url.rstrip("/").endswith("example.com")
        self.status_code = 200 if is_home else 404
        self.body = WORDPRESS_HOME if is_home else b"not found"
        self.headers = requests.structures.CaseInsensitiveDict(
            {
                "Content-Type": "text/html; charset=UTF-8",
                "Link": '<https://example.com/wp-json/>; rel="https://api.w.org/"',
            }
        )
        self.raw = _Raw()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size):
        yield self.body


@pytest.fixture
def wordpress_site(monkeypatch):
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    monkeypatch.setattr(requests.Session, "get", lambda self, url, **kwargs: _Response(url))


def _run(tmp_path, *extra):
    return cli.main(
        [
            "https://example.com",
            "--yes-i-am-authorized",
            "--no-dns",
            "--no-scan-js",
            "--requests-per-second",
            "100",
            "--output-dir",
            str(tmp_path),
            *extra,
        ]
    )


def _rules(tmp_path):
    (report,) = [p for p in tmp_path.glob("report-*.json") if "cms" not in p.name]
    payload = json.loads(report.read_text(encoding="utf-8"))
    return {f["rule_id"] for r in payload["results"] for f in r["findings"]}


def test_wordpress_site_scan_is_stored_and_reported(wordpress_site, tmp_path):
    assert _run(tmp_path, "--lang", "ru") == 0
    rules = _rules(tmp_path)
    assert {"cms.detected.wordpress", "wordpress.plugin.contact-form-7"} <= rules

    with Database(tmp_path / "audit_results.db") as db:
        (scan,) = db.load_scan_history("https://example.com")
    stored = {f["rule_id"] for r in scan["results"] for f in r["findings"]}
    assert "cms.detected.wordpress" in stored

    (owner,) = tmp_path.glob("owner-report-*.html")
    page = owner.read_text(encoding="utf-8")
    assert "WordPress 6.4.3" in page
    assert "contact-form-7" in page


def test_second_scan_builds_history(wordpress_site, tmp_path):
    assert _run(tmp_path) == 0
    assert _run(tmp_path) == 0
    with Database(tmp_path / "audit_results.db") as db:
        assert len(db.load_scan_history("https://example.com")) == 2


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("recommendation", ("tuple",), TypeError),
        ("evidence", None, TypeError),
        ("severity", "critical", ValueError),
        ("confidence", "certain", ValueError),
    ],
)
def test_finding_rejects_malformed_values(field, value, error):
    values = {
        "rule_id": "r",
        "title": "t",
        "severity": "low",
        "category": "c",
        "evidence": "e",
        "recommendation": "fix",
        "confidence": "high",
    }
    values[field] = value
    with pytest.raises(error):
        Finding(**values)


def test_single_label_hosts_skip_mail_checks(monkeypatch, tmp_path):
    def fail(host):
        raise AssertionError(f"DNS mail checks must not run for {host}")

    monkeypatch.setattr(cli, "inspect_domain", fail)
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    monkeypatch.setattr(requests.Session, "get", lambda self, url, **kwargs: _Response(url))
    code = cli.main(
        ["http://localhost:8081", "--yes-i-am-authorized", "--allow-private", "--no-scan-js"]
        + ["--paths", "/", "--output-dir", str(tmp_path)]
    )
    assert code == 0
