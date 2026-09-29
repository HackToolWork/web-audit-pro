"""Check the standalone action plan as a CLI and report consumer sees it."""

import json
from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest
from markdown_it import MarkdownIt

from web_audit import cli
from web_audit.database import Database
from web_audit.models import CheckResult, Finding
from web_audit.reports import save_action_plan, save_html, save_json

TARGET = "https://example.com"
URL = TARGET + "/"


class Document(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)

    @property
    def readable(self):
        return " ".join(" ".join(self.text).split())


def observation(rule="headers.csp", *, evidence="Missing CSP", recommendation="Review CSP"):
    return Finding(rule, "Check this setting", "low", "headers", evidence, recommendation)


def result(*findings, status=200, error="", truncated=False, url=URL):
    return CheckResult(
        url=url,
        status=status,
        size=0,
        elapsed_ms=1,
        scanned_at=datetime(2026, 9, 28, tzinfo=UTC),
        findings=tuple(findings),
        error=error,
        truncated=truncated,
    )


def rendered_markdown(path):
    return Document(MarkdownIt("commonmark").render(path.read_text(encoding="utf-8")))


@pytest.fixture
def run_cli(monkeypatch, tmp_path, capsys):
    def run(results, *, previous=None, compare=False, extra=()):
        output_dir = tmp_path / "output"

        class LocalScanner:
            def __init__(self, settings, proxy=None):
                pass

            def scan_target(self, target):
                return results

        monkeypatch.setattr(cli, "Scanner", LocalScanner)
        monkeypatch.setattr(cli, "resolve_target_addresses", lambda _target: set())
        arguments = [
            TARGET,
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--no-dns",
            "--no-cms",
            "--no-scan-js",
            "--output-dir",
            str(output_dir),
        ]
        if previous is not None:
            if compare:
                previous_path = tmp_path / "previous.json"
                save_json(TARGET, previous, previous_path)
                arguments.extend(["--compare", str(previous_path)])
            else:
                with Database(output_dir / "audit_results.db") as db:
                    db.save_scan(TARGET, "2026-09-27T00:00:00+00:00", "", previous)
        code = cli.main([*arguments, *extra])
        output = capsys.readouterr().out
        plans = list(output_dir.glob("*-actions.md"))
        pages = list(output_dir.glob("report-*.html"))
        reports = list(output_dir.glob("report-*.json"))
        assert len(plans) == len(pages) == len(reports) == 1
        return code, output, plans[0], pages[0], reports[0]

    return run


def test_cli_emits_portable_plan_without_changing_raw_json(run_cli):
    finding = observation(evidence="response detail", recommendation="Check the deployment")
    original = result(finding)

    code, output, plan_path, page_path, json_path = run_cli([original])

    assert code == 0
    assert f"PLAN: {plan_path}" in output
    assert plan_path.name == json_path.stem + "-actions.md"
    for document in (rendered_markdown(plan_path), Document(page_path.read_text())):
        assert "Action plan" in document.readable or "action plan" in document.readable
        assert finding.evidence in document.readable
        assert finding.recommendation in document.readable
        assert "Plan a fix" in document.readable
    payload = json.loads(json_path.read_text())
    assert payload["schema_version"] == "4.1"
    assert "tasks" not in payload
    assert payload["results"][0]["findings"] == [
        {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "category": finding.category,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
        }
    ]
    assert payload["results"][0]["verification_version"] == 0
    assert payload["results"][0]["verified_rules"] == []
    assert original.findings == (finding,)


def test_cli_ignored_rule_is_not_reintroduced_as_an_action(run_cli):
    ignored = observation(evidence="IGNORED evidence", recommendation="IGNORED recommendation")
    retained = observation("headers.hsts", evidence="Retained evidence")

    code, _, plan_path, page_path, json_path = run_cli(
        [result(ignored, retained)], extra=("--ignore-rule", "headers.csp")
    )

    assert code == 0
    for document in (rendered_markdown(plan_path), Document(page_path.read_text())):
        assert "headers.hsts" in document.readable
        assert "headers.csp" not in document.readable
        assert "IGNORED evidence" not in document.readable
        assert "IGNORED recommendation" not in document.readable
    assert [f["rule_id"] for f in json.loads(json_path.read_text())["results"][0]["findings"]] == [
        "headers.hsts"
    ]


@pytest.mark.parametrize("compare", [False, True], ids=["database", "json-compare"])
def test_cli_failed_recheck_stays_visible_in_both_deliverables(run_cli, compare):
    code, output, plan_path, page_path, _ = run_cli(
        [result(status=None, error="Timeout: recheck unavailable")],
        previous=[result(observation())],
        compare=compare,
    )

    assert code == 0
    assert "[UNVERIFIED] headers.csp" in output
    assert "[FIXED] headers.csp" not in output
    for document in (rendered_markdown(plan_path), Document(page_path.read_text())):
        assert "Rechecks still needed" in document.readable
        assert "UNVERIFIED" in document.readable
        assert "headers.csp" in document.readable
        assert "The recheck returned an error." in document.readable
        assert "1 of 1 requested URLs need follow-up" in document.readable


def test_comparison_error_still_produces_and_announces_current_plan(run_cli, tmp_path):
    invalid = tmp_path / "not-a-report.json"
    invalid.write_text("{}", encoding="utf-8")

    code, output, plan_path, page_path, _ = run_cli(
        [result(observation())], extra=("--compare", str(invalid))
    )

    assert code == 2
    assert "Comparison error:" in output
    assert f"PLAN: {plan_path}" in output
    assert "headers.csp" in rendered_markdown(plan_path).readable
    assert "headers.csp" in Document(page_path.read_text()).readable


def test_untrusted_fields_render_as_text_and_evidence_cannot_escape_markdown_fence(tmp_path):
    attack = (
        "first line\n`````\n### FORGED heading\n"
        "![beacon](https://invalid.example/beacon)\n"
        "<script>alert('captured text')</script>\n~~~~~\nlast line"
    )
    finding = Finding("custom.rule", attack, "medium", "test", attack, attack, confidence="low")
    source_url = 'https://example.com/" onmouseover="alert(1)?value=<svg/onload=alert(1)>'
    results = [result(finding, url=source_url)]
    plan_path = tmp_path / "plan.md"
    page_path = tmp_path / "plan.html"
    save_action_plan(attack, results, plan_path)
    save_html(attack, results, page_path, company=attack)

    parser = MarkdownIt("commonmark")
    markdown = plan_path.read_text()
    tokens = parser.parse(markdown)
    assert any(token.type == "fence" and token.content.rstrip("\n") == attack for token in tokens)
    all_tokens = [token for block in tokens for token in [block, *(block.children or [])]]
    assert not any(
        token.type in {"image", "link_open", "html_inline", "html_block"} for token in all_tokens
    )
    for document in (Document(parser.render(markdown)), Document(page_path.read_text())):
        assert "FORGED heading" in document.readable
        assert "captured text" in document.readable
        assert not any(tag in {"script", "img", "svg", "iframe"} for tag, _ in document.tags)
        assert not any(
            attribute.lower().startswith("on") for _, attrs in document.tags for attribute in attrs
        )


def test_standalone_html_does_not_make_a_non_http_url_executable(tmp_path):
    url = "javascript:alert('not a website')"
    page_path = tmp_path / "plan.html"

    save_html(TARGET, [result(observation(), url=url)], page_path)

    document = Document(page_path.read_text())
    assert url in document.readable
    assert not any(attrs.get("href", "").startswith("javascript:") for _, attrs in document.tags)


@pytest.mark.parametrize("results", [[], [result(status=None, error="Timeout: unavailable")]])
def test_empty_or_failed_scan_is_not_presented_as_an_all_clear(tmp_path, results):
    plan_path = tmp_path / "plan.md"
    page_path = tmp_path / "plan.html"
    save_action_plan(TARGET, results, plan_path)
    save_html(TARGET, results, page_path)

    coverage = "1 of 1 requested URLs need follow-up" if results else "No URLs were checked."
    for document in (rendered_markdown(plan_path), Document(page_path.read_text())):
        assert coverage in document.readable
        assert "No current findings to turn into tasks." in document.readable
        assert "This does not establish that the site is secure." in document.readable
        assert "No security findings." not in document.readable


def test_both_reports_keep_distinct_same_url_cookie_evidence(tmp_path):
    results = [
        result(
            observation("cookies.secure", evidence="Cookie A", recommendation="Fix cookie A"),
            observation("cookies.secure", evidence="Cookie B", recommendation="Fix cookie B"),
        )
    ]
    plan_path = tmp_path / "plan.md"
    page_path = tmp_path / "plan.html"
    save_action_plan(TARGET, results, plan_path)
    save_html(TARGET, results, page_path)

    for document in (rendered_markdown(plan_path), Document(page_path.read_text())):
        for detail in ("Cookie A", "Cookie B", "Fix cookie A", "Fix cookie B"):
            assert detail in document.readable
        assert "Manual verification" in document.readable
        assert "no automatic verification" in document.readable
