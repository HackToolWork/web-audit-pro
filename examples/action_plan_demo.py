"""Generate a synthetic action plan with the real analysis and report functions.

Run from the repository root: python -m examples.action_plan_demo
All responses are constructed in memory; no requests, sockets, or DNS lookups occur.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from web_audit.lifecycle_reporting import summarize_lifecycle
from web_audit.models import CheckResult
from web_audit.reports import save_action_plan, save_html, save_json
from web_audit.security import analyze_response, verified_response_rules

TARGET = "https://demo.example.test"
SCANNED_AT = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _response(path: str, *, hsts: str, disclose_stack: bool = False) -> CheckResult:
    url = TARGET + path
    headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Strict-Transport-Security": hsts,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "X-Frame-Options": "DENY",
    }
    if disclose_stack:
        headers["Server"] = "SyntheticDemoServer"
    body = b"<!doctype html><html><body>Synthetic action plan demo</body></html>"
    return CheckResult(
        url=url,
        status=200,
        size=len(body),
        elapsed_ms=12.0,
        scanned_at=SCANNED_AT,
        findings=analyze_response(url=url, status=200, headers=headers, request_target=TARGET),
        verified_rules=verified_response_rules(url=url, status=200, headers=headers),
        verification_version=1,
    )


def generate_demo(output_dir: Path) -> Path:
    """Write an HTML report, a Markdown action plan, and the supporting JSON report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results = [
        _response("/", hsts="max-age=0", disclose_stack=True),
        _response("/account", hsts="max-age=31536000"),
        CheckResult(
            url=TARGET + "/unavailable",
            status=None,
            size=0,
            elapsed_ms=5000.0,
            scanned_at=SCANNED_AT,
            error="Timeout: synthetic demonstration; no request was made.",
        ),
    ]

    # This URL previously lacked CSP. A timeout now cannot establish a fix.
    baseline = _response("/unavailable", hsts="max-age=31536000")
    previous = {
        "target": TARGET,
        "results": [
            {
                "url": baseline.url,
                "findings": [
                    asdict(finding)
                    for finding in baseline.findings
                    if finding.rule_id == "headers.csp"
                ],
            }
        ],
    }
    json_path = output_dir / "report.json"
    save_json(TARGET, results, json_path)
    current = json.loads(json_path.read_text(encoding="utf-8"))
    lifecycle = summarize_lifecycle(previous, current)

    save_action_plan(TARGET, results, output_dir / "action-plan.md", lifecycle=lifecycle)
    index = output_dir / "index.html"
    save_html(TARGET, results, index, company="Synthetic demo", lifecycle=lifecycle)
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/action-plan-demo"))
    args = parser.parse_args()
    index = generate_demo(args.output_dir)
    print("Synthetic demo generated offline; no site was contacted.")
    print(f"HTML: {index.resolve()}")
    print(f"Actions: {(args.output_dir / 'action-plan.md').resolve()}")
    print(f"JSON: {(args.output_dir / 'report.json').resolve()}")


if __name__ == "__main__":
    main()
