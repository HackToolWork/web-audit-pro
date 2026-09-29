from __future__ import annotations

import base64
import csv
import html
import json
import os
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .action_plan import build_action_plan
from .action_plan_rendering import render_action_plan_html, render_action_plan_markdown
from .lifecycle_cli import render_lifecycle_summary
from .models import CheckResult


def summary(results: list[CheckResult]) -> dict[str, int]:
    counts = Counter(
        "errors"
        if item.status is None
        else "2xx"
        if 200 <= item.status < 300
        else "3xx"
        if 300 <= item.status < 400
        else "4xx"
        if 400 <= item.status < 500
        else "5xx"
        for item in results
    )
    all_findings = [finding for item in results for finding in item.findings]
    findings = Counter(finding.severity for finding in all_findings)
    unique_findings = {finding.rule_id for finding in all_findings}
    return {
        "total": len(results),
        "2xx": counts["2xx"],
        "3xx": counts["3xx"],
        "4xx": counts["4xx"],
        "5xx": counts["5xx"],
        "errors": counts["errors"],
        "findings": len(all_findings),
        "unique_findings": len(unique_findings),
        "high": findings["high"],
        "medium": findings["medium"],
        "low": findings["low"],
        "info": findings["info"],
    }


def _atomic_write(path: Path, writer) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as file:
            writer(file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def save_csv(results: list[CheckResult], path: Path) -> None:
    def write(file) -> None:
        writer = csv.writer(file)
        writer.writerow(
            [
                "url",
                "status",
                "size",
                "elapsed_ms",
                "scanned_at",
                "truncated",
                "location",
                "error",
                "findings",
            ]
        )
        for item in results:
            writer.writerow(
                [
                    item.url,
                    item.status if item.status is not None else "",
                    item.size,
                    f"{item.elapsed_ms:.2f}",
                    item.scanned_at.isoformat(),
                    item.truncated,
                    item.location,
                    item.error,
                    len(item.findings),
                ]
            )

    _atomic_write(path, write)


def save_json(target: str, results: list[CheckResult], path: Path) -> None:
    payload = {
        "schema_version": "4.1",
        "tool": "Web Audit Pro",
        "target": target,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": summary(results),
        "results": [
            {
                "url": item.url,
                "status": item.status,
                "size": item.size,
                "elapsed_ms": round(item.elapsed_ms, 2),
                "scanned_at": item.scanned_at.isoformat(),
                "truncated": item.truncated,
                "location": item.location,
                "error": item.error,
                "verified_rules": list(item.verified_rules),
                "verification_version": item.verification_version,
                "findings": [
                    {
                        "rule_id": finding.rule_id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "category": finding.category,
                        "evidence": finding.evidence,
                        "recommendation": finding.recommendation,
                        "confidence": finding.confidence,
                    }
                    for finding in item.findings
                ],
            }
            for item in results
        ],
    }

    def write(file) -> None:
        json.dump(payload, file, ensure_ascii=False, indent=2)
        file.write("\n")

    _atomic_write(path, write)


def _status_class(status: int | None) -> str:
    if status is None:
        return "error"
    if 200 <= status < 300:
        return "ok"
    if 300 <= status < 400:
        return "redirect"
    if status == 403:
        return "forbidden"
    return "error"


def save_action_plan(
    target: str,
    results: list[CheckResult],
    path: Path,
    *,
    lifecycle: dict | None = None,
) -> None:
    """Export the same triage plan as HTML in a portable Markdown document."""
    plan = build_action_plan(results)
    document = render_action_plan_markdown(target, plan, lifecycle=lifecycle)
    _atomic_write(path, lambda file: file.write(document))


def _severity_class(severity: str) -> str:
    return f"severity-{severity}"


def _url_html(url: str) -> str:
    label = html.escape(url, quote=True)
    try:
        is_web_url = urlsplit(url).scheme.lower() in {"http", "https"}
    except ValueError:
        is_web_url = False
    if not is_web_url:
        return label
    return f'<a href="{label}" target="_blank" rel="noopener noreferrer">{label}</a>'


def logo_html(logo_path: Path | None, company: str) -> str:
    """Embed a PNG/JPEG logo as a data URI so reports stay single-file."""
    if not logo_path or not logo_path.is_file():
        return ""
    mime = "image/png" if logo_path.suffix.lower() == ".png" else "image/jpeg"
    encoded_logo = base64.b64encode(logo_path.read_bytes()).decode()
    return (
        f'<img alt="{html.escape(company)}" style="max-height:56px;max-width:240px"'
        f' src="data:{mime};base64,{encoded_logo}">'
    )


def save_html(
    target: str,
    results: list[CheckResult],
    path: Path,
    *,
    company: str = "Web Audit Pro",
    theme: str = "dark",
    logo_path: Path | None = None,
    lifecycle: dict | None = None,
) -> None:
    stats = summary(results)
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    lifecycle_html = ""
    if lifecycle is not None:
        lifecycle_html = (
            '<section class="summary-panel">'
            "<h2>Recheck results</h2>"
            "<p>FIXED means a supported condition passed its recheck. "
            "UNVERIFIED means there is not enough evidence to confirm its absence.</p>"
            "<p>CSP and Referrer-Policy rechecks confirm header presence only; "
            "policy syntax and effectiveness are not validated.</p>"
            '<pre class="lifecycle-summary">'
            + html.escape(render_lifecycle_summary(lifecycle))
            + "</pre></section>"
        )
    themes = {
        "dark": ("#0b1020", "#ecf1ff", "#151d33", "#84aaff"),
        "light": ("#f6f8fb", "#172033", "#ffffff", "#2457c5"),
        "cyberpunk": ("#090613", "#f7efff", "#171027", "#ff4ecd"),
    }
    bg, fg, card_bg, accent = themes[theme]

    plan = build_action_plan(results)
    finding_summary_html = render_action_plan_html(plan, lifecycle=lifecycle)
    logo = logo_html(logo_path, company)

    rows: list[str] = []

    for item in results:
        status = "ERR" if item.status is None else str(item.status)
        detail = item.error or item.location
        if item.findings:
            finding_parts = []
            for finding in item.findings:
                badge = _severity_class(html.escape(finding.severity))
                finding_parts.append(
                    f'<li><span class="badge {badge}">'
                    f"{html.escape(finding.severity)}</span> "
                    f"<strong>{html.escape(finding.title)}</strong><br>"
                    f"<small>{html.escape(finding.evidence)}<br>"
                    f"<strong>Confidence:</strong> {html.escape(finding.confidence)}<br>"
                    f"<strong>Fix:</strong> {html.escape(finding.recommendation)}"
                    "</small></li>"
                )
            finding_html = '<ul class="findings">' + "".join(finding_parts) + "</ul>"
        else:
            finding_html = "<small>None</small>"
        rows.append(
            f"""
            <tr>
                <td>{_url_html(item.url)}</td>
                <td><span class="badge {_status_class(item.status)}">{status}</span></td>
                <td>{item.size:,}</td>
                <td>{item.elapsed_ms:.2f}</td>
                <td>{"yes" if item.truncated else "no"}</td>
                <td>{html.escape(detail)}</td>
                <td>{finding_html}</td>
            </tr>
            """
        )

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Web Audit Report — {html.escape(target)}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: system-ui, sans-serif; margin: 0; background: {bg}; color: {fg}; }}
main {{ max-width: 1400px; margin: auto; padding: clamp(16px, 3vw, 32px); }}
h1 {{ margin-bottom: 6px; }}
.meta {{ opacity: .75; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
          gap:12px; margin:24px 0; }}
.card {{ background: {card_bg}; border: 1px solid #283250; border-radius: 12px; padding: 16px; }}
.card strong {{ display:block; font-size: 28px; margin-top: 6px; }}
.table-wrap {{ overflow:auto; border:1px solid #283250; border-radius:12px; }}
table {{ width:100%; border-collapse:collapse; background:{card_bg}; }}
th,td {{ padding:12px 14px; border-bottom:1px solid #283250; text-align:left; vertical-align:top; }}
th {{ position:sticky; top:0; background:{card_bg}; }}
a {{ color:{accent}; }}
.badge {{ display:inline-block; min-width:44px; text-align:center;
          padding:4px 8px; border-radius:999px; font-weight:700; }}
.ok {{ background:#143f2c; color:#7ff0b0; }}
.redirect {{ background:#4b3b12; color:#ffd466; }}
.forbidden {{ background:#173a58; color:#8ecbff; }}
.error {{ background:#4a1f2a; color:#ff9bab; }}
.severity-high {{ background:#5a1b1b; color:#ff9c9c; }}
.severity-medium {{ background:#4a3412; color:#ffd466; }}
.severity-low {{ background:#173a58; color:#8ecbff; }}
.severity-info {{ background:#283250; color:#c9d2eb; }}
.findings {{ margin:0; padding-left:18px; min-width:320px; }}
.findings li {{ margin-bottom:10px; }}
.summary-panel {{ margin:24px 0; background:{card_bg}; border:1px solid #283250;
                  border-radius:12px; padding:20px; }}
.finding-meta {{ margin-top:6px; opacity:.75; font-size:13px; }}
.action-plan h2 {{ margin-top:0; }}
.plan-explanation, .recheck-instructions {{ max-width:90ch; line-height:1.6; }}
.coverage-note {{ border-left:3px solid {accent}; padding:10px 14px; line-height:1.5; }}
.coverage-details li, .pending-rechecks li {{ margin:12px 0; overflow-wrap:anywhere; }}
.action-list {{ list-style:none; padding:0; display:grid; gap:18px; }}
.action-item {{ border:1px solid #536078; border-radius:10px; padding:clamp(14px, 2vw, 24px);
                overflow-wrap:anywhere; line-height:1.55; }}
.action-heading {{ display:flex; align-items:flex-start; gap:14px; }}
.action-heading h3 {{ margin:8px 0 0; font-size:1.15rem; }}
.action-number {{ font-size:1.4rem; color:{accent}; font-variant-numeric:tabular-nums; }}
.action-next {{ font-weight:600; margin-left:8px; }}
summary {{ cursor:pointer; font-weight:600; padding:8px 0; }}
.task-evidence {{ padding-left:20px; }}
.task-evidence li {{ margin:20px 0; }}
.task-evidence pre {{ white-space:pre-wrap; overflow-wrap:anywhere; font-size:.9rem; }}
.pending-rechecks {{ border-top:1px solid #536078; margin-top:20px; }}
@media print {{
    body {{ background:#fff; color:#111; }}
    main {{ max-width:none; padding:0; }}
    .card, .summary-panel, table, th {{ background:#fff; color:#111; }}
    .action-item, tr {{ break-inside:avoid; }}
}}
code {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }}
.empty {{ opacity:.8; margin:0; }}
.lifecycle-summary {{ white-space:pre-wrap; overflow-wrap:anywhere; }}
small {{ opacity:.8; display:block; margin-top:4px; }}
</style>
</head>
<body>
<main>
<div class="meta">{logo}</div>
<h1>{html.escape(company)} — Web Audit Report</h1>
<div class="meta">Target: <strong>{html.escape(target)}</strong> · Generated: {generated}</div>
<section class="cards">
<div class="card">Requested URLs<strong>{plan["coverage"]["total_urls"]}</strong></div>
<div class="card">Findings<strong>{stats["findings"]}</strong>
<small>{stats["unique_findings"]} unique rules</small></div>
<div class="card">Medium / high<strong>{stats["high"] + stats["medium"]}</strong></div>
<div class="card">URLs to check again
<strong>{len(plan["coverage"]["incomplete_urls"])}</strong></div>
</section>
<p class="meta">HTTP responses: 2xx {stats["2xx"]} · 3xx {stats["3xx"]} ·
4xx {stats["4xx"]} · 5xx {stats["5xx"]} · Request errors {stats["errors"]}</p>
{finding_summary_html}
{lifecycle_html}
<div class="table-wrap">
<table>
<thead><tr><th>URL</th><th>Status</th><th>Size</th><th>Latency ms</th>
<th>Truncated</th><th>Detail</th><th>Security observations</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
</div>
</main>
</body>
</html>
"""

    _atomic_write(path, lambda file: file.write(doc))
