import json
import time
from datetime import UTC, datetime

import pytest

from web_audit import cli, wp_vulndb
from web_audit.models import CheckResult
from web_audit.owner_texts import UI
from web_audit.wordpress import Component
from web_audit.wordpress import findings as component_findings
from web_audit.wp_vulndb import VersionRange, version_key

MITRE = "Copyright 1999-2026 The MITRE Corporation"


def _record(slug="elementor", *, kind="plugin", to="3.18.1", patched=("3.18.2",), **extra):
    record = {
        "id": f"uuid-{slug}",
        "title": f"{slug} <= {to} - Stored XSS",
        "software": [
            {
                "type": kind,
                "name": slug.title(),
                "slug": slug,
                "affected_versions": {
                    f"* - {to}": {
                        "from_version": "*",
                        "from_inclusive": True,
                        "to_version": to,
                        "to_inclusive": True,
                    }
                },
                "patched": bool(patched),
                "patched_versions": list(patched),
            }
        ],
        "informational": False,
        "references": [f"https://example.test/{slug}"],
        "cvss": {"vector": "CVSS:3.1/...", "score": 6.4, "rating": "Medium"},
        "cve": "CVE-2026-0001",
        "copyrights": {"mitre": {"notice": MITRE}},
    }
    record.update(extra)
    return record


def _feed(*records):
    return {record["id"]: record for record in records}


def _write_db(path, feed, *, updated_at=None):
    index, count = wp_vulndb.normalize_feed(feed)
    payload = {"source": "test", "updated_at": updated_at or time.time(), "records": count}
    path.write_text(json.dumps({**payload, "index": index}), encoding="utf-8")
    return wp_vulndb.load(path)


@pytest.mark.parametrize(
    ("left", "right"),
    [("1.0", "1"), ("1.0.0", "1"), ("v2.3", "2.3"), ("3.18.0-beta1", "3.18")],
)
def test_version_keys_normalize(left, right):
    assert version_key(left) == version_key(right)


def test_version_key_ordering_and_invalid():
    assert version_key("3.9") < version_key("3.18") < version_key("3.18.1")
    assert version_key("latest") is None


@pytest.mark.parametrize(
    ("bounds", "version", "expected"),
    [
        (("*", True, "3.18.1", True), "3.18.1", True),
        (("*", True, "3.18.1", False), "3.18.1", False),
        (("*", True, "3.18.1", True), "3.18.2", False),
        (("2.0", False, "*", True), "2.0", False),
        (("2.0", True, "*", True), "99", True),
        (("1.0", True, "2.0", True), "garbage", None),
        (("oops", True, "2.0", True), "1.5", None),
    ],
)
def test_version_range_contains(bounds, version, expected):
    assert VersionRange(*bounds).contains(version) is expected


def test_normalize_skips_informational_core_and_malformed_records():
    feed = _feed(
        _record("elementor"),
        _record("astra", kind="theme"),
        _record("core-thing", kind="core"),
        _record("notice-only", informational=True),
        {"id": "broken", "software": "nope"},
    )
    index, count = wp_vulndb.normalize_feed(feed)
    assert count == 2
    assert set(index) == {"plugin:elementor", "theme:astra"}
    (entry,) = index["plugin:elementor"]
    assert entry["ranges"] == [["*", True, "3.18.1", True]]
    assert entry["copyright"] == MITRE
    assert wp_vulndb.normalize_feed([_record("elementor")])[1] == 1


def test_component_findings_match_only_affected_versions(tmp_path):
    db = _write_db(tmp_path / "db.json", _feed(_record("elementor")))
    assert wp_vulndb.component_findings("plugin", "elementor", "3.18.2", db) == ()
    assert wp_vulndb.component_findings("plugin", "other", "1.0", db) == ()
    assert wp_vulndb.component_findings("theme", "elementor", "1.0", db) == ()

    (finding,) = wp_vulndb.component_findings("plugin", "elementor", "3.18.0", db)
    assert finding.rule_id == "wordpress.vulnerable.plugin.elementor"
    assert finding.severity == "medium"
    assert "fixed in 3.18.2" in finding.evidence
    assert MITRE in finding.evidence
    assert finding.recommendation.startswith("Update elementor to 3.18.2 or later.")


def test_severity_and_fixed_version_cover_all_matches(tmp_path):
    critical = _record(
        "elementor", to="3.20.0", patched=("3.20.1",), cvss={"score": 9.8, "rating": "Critical"}
    )
    critical["id"] = "uuid-critical"
    unpatched = _record("elementor", to="*", patched=())
    unpatched["id"] = "uuid-unpatched"
    db = _write_db(tmp_path / "db.json", _feed(_record("elementor"), critical))
    (finding,) = wp_vulndb.component_findings("plugin", "elementor", "3.18.0", db)
    assert finding.severity == "high"
    assert "matches 2 known vulnerabilities; fixed in 3.20.1" in finding.evidence

    db = _write_db(tmp_path / "db.json", _feed(_record("elementor"), unpatched))
    (finding,) = wp_vulndb.component_findings("plugin", "elementor", "3.18.0", db)
    assert "fixed in" not in finding.evidence
    assert finding.recommendation.startswith("No fixed version is listed")


def test_load_rejects_missing_or_corrupt_files(tmp_path):
    assert wp_vulndb.load(tmp_path / "missing.json") is None
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert wp_vulndb.load(corrupt) is None
    corrupt.write_text('{"updated_at": 1, "index": []}', encoding="utf-8")
    assert wp_vulndb.load(corrupt) is None


class _Response:
    def __init__(self, status, body=b"", headers=None):
        self.status_code = status
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size):
        yield self.body


def _fake_get(monkeypatch, response):
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs["headers"]))
        return response

    monkeypatch.setattr(wp_vulndb.requests, "get", get)
    return calls


def test_update_sends_bearer_key_and_writes_database(monkeypatch, tmp_path):
    body = json.dumps(_feed(_record("elementor"))).encode()
    calls = _fake_get(monkeypatch, _Response(200, body))
    path = tmp_path / "cache" / "wp.json"

    assert wp_vulndb.update(path, api_key="secret-key") == 1
    assert calls == [
        (
            wp_vulndb.FEED_URL,
            {"Authorization": "Bearer secret-key", "Accept": "application/json"},
        )
    ]
    db = wp_vulndb.load(path)
    assert db is not None and db.lookup("plugin", "elementor")
    assert list(path.parent.iterdir()) == [path] or all(
        p.suffix == ".lock" for p in path.parent.iterdir() if p != path
    )


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (_Response(401), PermissionError),
        (_Response(429, headers={"Retry-After": "3600"}), wp_vulndb.RateLimitedError),
        (_Response(500), RuntimeError),
        (_Response(200, b"{}"), ValueError),
        (_Response(200, b"not json"), ValueError),
    ],
)
def test_failed_update_keeps_existing_database(monkeypatch, tmp_path, response, error):
    path = tmp_path / "wp.json"
    _write_db(path, _feed(_record("astra", kind="theme")))
    before = path.read_bytes()
    _fake_get(monkeypatch, response)
    with pytest.raises(error):
        wp_vulndb.update(path, api_key="k")
    assert path.read_bytes() == before


def test_rate_limit_message_explains_the_wait(monkeypatch, tmp_path):
    _fake_get(monkeypatch, _Response(429, headers={"Retry-After": "3600"}))
    with pytest.raises(wp_vulndb.RateLimitedError, match="Retry after 3600 seconds"):
        wp_vulndb.update(tmp_path / "wp.json", api_key="k")
    _fake_get(monkeypatch, _Response(429))
    with pytest.raises(wp_vulndb.RateLimitedError, match="Wait a few hours") as error:
        wp_vulndb.update(tmp_path / "other.json", api_key="k")
    assert "Retry after" not in str(error.value)


def test_rate_limit_starts_a_cooldown_without_further_requests(monkeypatch, tmp_path):
    path = tmp_path / "wp.json"
    calls = _fake_get(monkeypatch, _Response(429))
    with pytest.raises(wp_vulndb.RateLimitedError):
        wp_vulndb.update(path, api_key="k")
    assert len(calls) == 1
    assert 11.9 < wp_vulndb.cooldown_hours_left(path) <= 12

    with pytest.raises(wp_vulndb.RateLimitedError, match="no request was sent"):
        wp_vulndb.update(path, api_key="k")
    assert len(calls) == 1


def test_cooldown_expires_and_success_clears_it(monkeypatch, tmp_path):
    path = tmp_path / "wp.json"
    marker = path.with_name(path.name + ".rate-limited")
    marker.write_text(str(time.time() - 13 * 3600), encoding="utf-8")
    assert wp_vulndb.cooldown_hours_left(path) == 0
    _fake_get(monkeypatch, _Response(200, json.dumps(_feed(_record("elementor"))).encode()))
    assert wp_vulndb.update(path, api_key="k") == 1
    assert not marker.exists()


def test_corrupt_cooldown_marker_does_not_block(tmp_path):
    path = tmp_path / "wp.json"
    path.with_name(path.name + ".rate-limited").write_text("garbage", encoding="utf-8")
    assert wp_vulndb.cooldown_hours_left(path) == 0


def test_cli_skips_download_while_database_is_fresh(monkeypatch, capsys):
    _write_db(wp_vulndb.default_path(), _feed(_record("elementor")))
    monkeypatch.setenv("WORDFENCE_API_KEY", "k")

    def fail(*args, **kwargs):
        raise AssertionError("no request expected")

    monkeypatch.setattr(wp_vulndb.requests, "get", fail)
    assert cli.main(["--update-wp-db"]) == 0
    assert "try again in 12.0 hour(s)" in capsys.readouterr().out


def test_cli_downloads_again_once_database_is_old(monkeypatch, capsys):
    old = time.time() - (wp_vulndb.MIN_REFRESH_HOURS + 1) * 3600
    _write_db(wp_vulndb.default_path(), _feed(_record("astra", kind="theme")), updated_at=old)
    monkeypatch.setenv("WORDFENCE_API_KEY", "k")
    _fake_get(monkeypatch, _Response(200, json.dumps(_feed(_record("elementor"))).encode()))
    assert cli.main(["--update-wp-db"]) == 0
    assert "database updated: 1 records" in capsys.readouterr().out


def test_update_requires_api_key(tmp_path):
    with pytest.raises(PermissionError, match="WORDFENCE_API_KEY"):
        wp_vulndb.update(tmp_path / "wp.json")


def test_cli_update_wp_db_reports_missing_key(capsys):
    assert cli.main(["--update-wp-db"]) == 1
    output = capsys.readouterr().out
    assert "WORDFENCE_API_KEY" in output
    assert "existing local database, if any, was kept" in output


class _Scanner:
    def __init__(self, settings, proxy=None):
        pass

    def scan_target(self, target, progress_callback=None):
        components = (
            Component("plugin", "elementor", "3.18.0", "/wp-content/plugins/elementor/a.js"),
            Component("plugin", "unknown-version", None, "/wp-content/plugins/x/a.js"),
        )
        return [
            CheckResult(
                url=target + "/",
                status=200,
                size=0,
                elapsed_ms=1.0,
                scanned_at=datetime.now(UTC),
                findings=component_findings(components),
            )
        ]


def _run(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    monkeypatch.setattr(cli, "Scanner", _Scanner)
    out = tmp_path / "out"
    code = cli.main(
        [
            "https://shop.example",
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--no-dns",
            "--lang",
            "ru",
            "--output-dir",
            str(out),
        ]
    )
    (owner,) = out.glob("owner-report-*.html")
    (report,) = [p for p in out.glob("report-*.json") if "cms" not in p.name]
    rules = {
        f["rule_id"]
        for r in json.loads(report.read_text(encoding="utf-8"))["results"]
        for f in r["findings"]
    }
    return code, owner.read_text(encoding="utf-8"), rules


def test_cli_matches_components_against_local_database(monkeypatch, tmp_path, capsys):
    path = wp_vulndb.default_path()
    _write_db(path, _feed(_record("elementor"), _record("unknown-version", to="*")))

    code, page, rules = _run(monkeypatch, tmp_path)
    assert code == 0
    assert "wordpress.vulnerable.plugin.elementor" in rules
    # Unknown versions are never claimed to be vulnerable.
    assert "wordpress.vulnerable.plugin.unknown-version" not in rules
    assert "«elementor» версии 3.18.0 содержит известные уязвимости" in page
    assert "Обновите до версии 3.18.2 или новее" in page
    assert "Wordfence Intelligence" in page
    assert MITRE in page
    assert UI["ru"]["area_cms_desc"] not in page


def test_cli_without_database_suggests_update(monkeypatch, tmp_path, capsys):
    code, page, rules = _run(monkeypatch, tmp_path)
    assert code == 0
    assert not any(rule.startswith("wordpress.vulnerable.") for rule in rules)
    assert "--update-wp-db" in capsys.readouterr().out
    assert UI["ru"]["area_cms_desc"] in page


def test_cli_warns_about_stale_database(monkeypatch, tmp_path, capsys):
    _write_db(
        wp_vulndb.default_path(), _feed(_record("elementor")), updated_at=time.time() - 30 * 86400
    )
    code, _, rules = _run(monkeypatch, tmp_path)
    assert code == 0
    assert "wordpress.vulnerable.plugin.elementor" in rules
    assert "Базе уязвимостей WordPress уже 30 дн." in capsys.readouterr().out
