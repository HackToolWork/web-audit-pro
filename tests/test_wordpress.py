from datetime import UTC, datetime

from web_audit import wordpress
from web_audit.config import Settings
from web_audit.models import CheckResult
from web_audit.owner_report import build_owner_summary, render_owner_report_html
from web_audit.owner_texts import UI
from web_audit.scanner import Scanner
from web_audit.wordpress import Component, detect_components, parse_evidence

PAGE = """
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="https://shop.example/wp-content/plugins/woocommerce/assets/css/woo.css?ver=8.5.1">
<script src="/wp-content/plugins/woocommerce/assets/js/cart.js?ver=8.5.1"></script>
<script src="/wp-content/plugins/Contact-Form-7/includes/js/index.js?foo=1&#038;ver=5.8.4"></script>
<script src="/wp-content/plugins/elementor/assets/app.js?a=1&amp;ver=3.18.0"></script>
<script src="/wp-content/plugins/no-version/app.js?ver=6.4.2"></script>
<script src="/wp-content/plugins/cache-buster/app.js?ver=1699999999"></script>
<link href="/wp-content/themes/astra/style.css?ver=4.5.2" rel="stylesheet">
"""


def _by_slug(components):
    return {(c.kind, c.slug): c.version for c in components}


def test_detects_plugins_and_themes_with_conservative_versions():
    found = _by_slug(detect_components(PAGE, core_version="6.4.2"))
    assert found == {
        ("plugin", "woocommerce"): "8.5.1",
        ("plugin", "contact-form-7"): "5.8.4",
        ("plugin", "elementor"): "3.18.0",
        # WordPress appends its core version to assets enqueued without one.
        ("plugin", "no-version"): None,
        # Timestamps are cache busters, not versions.
        ("plugin", "cache-buster"): None,
        ("theme", "astra"): "4.5.2",
    }


def test_conflicting_versions_are_unknown():
    html = (
        '<script src="/wp-content/plugins/demo/a.js?ver=1.0.0"></script>'
        '<script src="/wp-content/plugins/demo/b.js?ver=2.0.0"></script>'
        '<script src="/wp-content/plugins/demo/c.js"></script>'
    )
    assert _by_slug(detect_components(html)) == {("plugin", "demo"): None}


def test_component_count_is_capped():
    html = "".join(f'<script src="/wp-content/plugins/p{i}/x.js"></script>' for i in range(100))
    assert len(detect_components(html)) == wordpress.MAX_COMPONENTS


def test_findings_round_trip_through_evidence():
    components = (
        Component("plugin", "contact-form-7", "5.8.4", "/wp-content/plugins/contact-form-7/x.js"),
        Component("theme", "astra", None, "/wp-content/themes/astra/style.css"),
    )
    findings = wordpress.findings(components)
    assert [f.rule_id for f in findings] == [
        "wordpress.plugin.contact-form-7",
        "wordpress.theme.astra",
    ]
    assert all(f.severity == "info" and f.confidence == "medium" for f in findings)
    assert [parse_evidence(f.evidence) for f in findings] == [
        ("plugin", "contact-form-7", "5.8.4"),
        ("theme", "astra", None),
    ]
    assert parse_evidence("something else") is None


class _HTMLResponse:
    status_code = 200
    raw = object()

    def __init__(self, body):
        self.body = body
        self.headers = {"Content-Type": "text/html; charset=utf-8"}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size):
        yield self.body


def _scan(monkeypatch, body, **settings):
    scanner = Scanner(Settings(retries=0, paths=("/",), scan_js=False, **settings))
    monkeypatch.setattr(scanner._session(), "get", lambda *a, **k: _HTMLResponse(body))
    return {f.rule_id for f in scanner.check("https://shop.example/").findings}


def test_scanner_reports_components_only_for_wordpress_pages(monkeypatch):
    rules = _scan(monkeypatch, PAGE.encode())
    assert {
        "cms.detected.wordpress",
        "wordpress.plugin.woocommerce",
        "wordpress.theme.astra",
    } <= rules
    assert not any(r.startswith("wordpress.") for r in _scan(monkeypatch, b"<html>plain</html>"))
    assert not any(
        r.startswith("wordpress.") for r in _scan(monkeypatch, PAGE.encode(), cms_enabled=False)
    )


def _result(url, *components):
    return CheckResult(
        url=url,
        status=200,
        size=0,
        elapsed_ms=1.0,
        scanned_at=datetime.now(UTC),
        findings=wordpress.findings(components),
    )


def test_owner_report_lists_components_in_one_table():
    results = [
        _result(
            "https://shop.example/",
            Component("plugin", "woocommerce", "8.5.1", "a"),
            Component("plugin", "elementor", "3.18.0", "a"),
        ),
        _result(
            "https://shop.example/shop/",
            Component("plugin", "woocommerce", "8.5.1", "b"),
            Component("plugin", "elementor", "3.19.0", "b"),
            Component("theme", "astra", None, "b"),
        ),
    ]
    data = build_owner_summary(results, coverage={"cms": "checked"}, lang="ru")
    (item,) = [i for i in data["items"] if i["area"] == "cms"]
    assert item["components"] == [
        ("plugin", "elementor", None),  # different versions on different pages
        ("plugin", "woocommerce", "8.5.1"),
        ("theme", "astra", None),
    ]
    assert data["area_notes"]["cms"] == [UI["ru"]["components_count"].format(count=3)]

    page = render_owner_report_html("https://shop.example", data, company="Studio")
    assert page.count("<tr>") == 4
    assert UI["ru"]["version_unknown"] in page


def test_lifecycle_titles_name_the_component():
    lifecycle = {"new": [{"rule_id": "wordpress.plugin.elementor", "url": "u", "severity": "info"}]}
    data = build_owner_summary([], lifecycle=lifecycle, lang="ru")
    assert data["changes"]["new"] == ["Плагин WordPress: elementor"]
