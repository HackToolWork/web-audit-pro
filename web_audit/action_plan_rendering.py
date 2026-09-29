"""Render a triage plan without treating captured response text as markup."""

from __future__ import annotations

import html
import re

_ACTION_LABELS = {
    "review": "Review context",
    "validate": "Validate first",
    "fix": "Plan a fix",
}
_ORDER_EXPLANATION = (
    "Ordered by highest observed severity, then number of affected URLs, then rule ID. "
    "This is a triage order, not a measure of exploitability or business impact."
)
_RECHECK_INSTRUCTIONS = (
    "After a change, check the affected URLs again with the same scope and scan options. "
    "Keep the original JSON report and compare the new scan with it using --compare. "
    "An error or a missing finding alone does not confirm a fix."
)


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _markdown(value: object) -> str:
    # Flatten untrusted field line breaks to prevent injected Markdown blocks.
    text = html.escape(" ".join(str(value).split()), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|~\-])", r"\\\1", text)


def _literal(value: object) -> str:
    """Preserve evidence verbatim inside a fence it cannot close."""
    text = str(value)
    longest = max((len(match) for match in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def _coverage_text(plan: dict) -> str:
    coverage = plan["coverage"]
    total = coverage["total_urls"]
    incomplete = len(coverage["incomplete_urls"])
    if total == 0:
        return "No URLs were checked. There is no basis for a security conclusion."
    if incomplete:
        return (
            f"{incomplete} of {total} requested URLs need follow-up: "
            "a complete successful HTTP response was not obtained for every URL."
        )
    return (
        f"Complete successful HTTP responses were obtained for all {total} requested URLs. "
        "This describes response coverage, not the completeness of a security assessment."
    )


def render_action_plan_html(plan: dict, *, lifecycle: dict | None = None) -> str:
    parts = [
        '<section class="summary-panel action-plan" aria-labelledby="action-plan-title">',
        '<h2 id="action-plan-title">Action plan</h2>',
        f'<p class="plan-explanation">{_ORDER_EXPLANATION}</p>',
        f'<p class="coverage-note">{_coverage_text(plan)}</p>',
    ]
    incomplete = plan["coverage"]["incomplete_urls"]
    if incomplete:
        parts.append('<details class="coverage-details"><summary>URLs to check again</summary><ul>')
        for item in incomplete:
            parts.append(
                f"<li><code>{_escape(item['url'])}</code>: "
                f"{_escape('; '.join(item['reasons']))}</li>"
            )
        parts.append("</ul></details>")

    tasks = plan["tasks"]
    observation_count = sum(len(task["observations"]) for task in tasks)
    parts.append(
        f'<p class="finding-meta">Security findings: {len(tasks)} unique rules · '
        f"{observation_count} distinct observations</p>"
    )
    if not tasks:
        parts.append(
            '<p class="empty">No current findings to turn into tasks. '
            "This does not establish that the site is secure.</p>"
        )
    else:
        parts.append('<ol class="action-list">')
        for number, task in enumerate(tasks, 1):
            severity = _escape(task["severity"])
            next_step = _ACTION_LABELS[task["next_step"]]
            url_count = len(task["urls"])
            observed_count = len(task["observations"])
            url_label = "URL" if url_count == 1 else "URLs"
            observation_label = "observation" if observed_count == 1 else "observations"
            parts.extend(
                [
                    '<li><article class="action-item">',
                    '<div class="action-heading">',
                    f'<span class="action-number">{number:02d}</span>',
                    f'<div><span class="badge severity-{severity}">{severity}</span> ',
                    f'<span class="action-next">{next_step}</span>',
                    f"<h3>{_escape(task['title'])}</h3></div></div>",
                    f'<p class="finding-meta"><code>{_escape(task["rule_id"])}</code> · ',
                    f"{url_count} affected {url_label} · {observed_count} {observation_label} · ",
                    f"Confidence: {_escape(', '.join(task['confidences']))}</p>",
                    f"<p><strong>Why this order:</strong> {_escape(task['priority_reason'])}</p>",
                ]
            )
            if task["next_step"] == "validate":
                parts.append(
                    "<p><strong>First:</strong> Confirm the evidence in its response and "
                    "application context before choosing a change. Some observations have "
                    "uncertain evidence or an incomplete response.</p>"
                )
            elif task["next_step"] == "review":
                parts.append(
                    "<p><strong>First:</strong> Review whether this informational observation "
                    "requires a change in this application.</p>"
                )
            parts.append("<p><strong>Recommended action:</strong></p><ul>")
            for recommendation in task["recommendations"]:
                parts.append(f"<li>{_escape(recommendation)}</li>")
            if not task["recommendations"]:
                parts.append("<li>Review the observation and agree on an appropriate change.</li>")
            parts.append("</ul>")
            mode = (
                "Automatic condition recheck"
                if task["recheck_mode"] == "automatic"
                else "Manual verification"
            )
            parts.append(f"<p><strong>{mode}:</strong> {_escape(task['recheck'])}</p>")
            parts.append(
                '<details><summary>Affected URLs and evidence</summary><ul class="task-evidence">'
            )
            for observation in task["observations"]:
                parts.extend(
                    [
                        f"<li><code>{_escape(observation['url'])}</code>",
                        f"<p>Severity: {_escape(observation['severity'])} · ",
                        f"Confidence: {_escape(observation['confidence'])}</p>",
                        f"<pre>{_escape(observation['evidence'])}</pre>",
                        f"<p>Recommendation: {_escape(observation['recommendation'])}</p></li>",
                    ]
                )
            parts.append("</ul></details></article></li>")
        parts.append("</ol>")

    unknown = (lifecycle or {}).get("unverified", [])
    if unknown:
        parts.append('<div class="pending-rechecks"><h3>Rechecks still needed</h3><ul>')
        for item in unknown:
            parts.append(
                f"<li><strong>UNVERIFIED</strong> <code>{_escape(item['rule_id'])}</code> — "
                f"<code>{_escape(item['url'])}</code><br>"
                f"{_escape(item.get('reason', 'A successful recheck is required.'))}</li>"
            )
        parts.append("</ul></div>")
    parts.append(f'<p class="recheck-instructions">{_RECHECK_INSTRUCTIONS}</p></section>')
    return "".join(parts)


def render_action_plan_markdown(target: str, plan: dict, *, lifecycle: dict | None = None) -> str:
    lines = [
        "# Web Audit Pro — action plan",
        "",
        f"Target: {_markdown(target)}",
        "",
        _ORDER_EXPLANATION,
        "",
        "## Response coverage",
        "",
        _coverage_text(plan),
        "",
    ]
    for item in plan["coverage"]["incomplete_urls"]:
        lines.append(f"- {_markdown(item['url'])}: {_markdown('; '.join(item['reasons']))}")
    lines.extend(["", "## Tasks", ""])
    if not plan["tasks"]:
        lines.extend(
            [
                "No current findings to turn into tasks. "
                "This does not establish that the site is secure.",
                "",
            ]
        )
    for number, task in enumerate(plan["tasks"], 1):
        lines.extend(
            [
                f"### {number}. {_markdown(task['title'])}",
                "",
                f"Rule: {_markdown(task['rule_id'])}",
                "",
                f"Severity: {_markdown(task['severity'])} · "
                f"Confidence: {_markdown(', '.join(task['confidences']))}",
                "",
                f"Next step: {_ACTION_LABELS[task['next_step']]}",
                "",
                f"Why this order: {_markdown(task['priority_reason'])}",
                "",
            ]
        )
        if task["next_step"] == "validate":
            lines.extend(
                [
                    "Confirm the evidence in its response and application context "
                    "before choosing a change.",
                    "",
                ]
            )
        if task["next_step"] == "review":
            lines.extend(["Review whether this informational observation requires a change.", ""])
        lines.extend(["Recommended action:", ""])
        for recommendation in task["recommendations"]:
            lines.append(f"- {_markdown(recommendation)}")
        if not task["recommendations"]:
            lines.append("- Review the observation and agree on an appropriate change.")
        mode = (
            "Automatic condition recheck"
            if task["recheck_mode"] == "automatic"
            else "Manual verification"
        )
        lines.extend(
            ["", f"{mode}: {_markdown(task['recheck'])}", "", "Affected URLs and evidence:", ""]
        )
        for observation in task["observations"]:
            lines.extend(
                [
                    f"URL: {_markdown(observation['url'])}",
                    "",
                    f"Severity: {_markdown(observation['severity'])} · "
                    f"Confidence: {_markdown(observation['confidence'])}",
                    "",
                    _literal(observation["evidence"]),
                    "",
                    f"Recommendation: {_markdown(observation['recommendation'])}",
                    "",
                ]
            )
    unknown = (lifecycle or {}).get("unverified", [])
    if unknown:
        lines.extend(["## Rechecks still needed", ""])
        for item in unknown:
            lines.append(
                f"- UNVERIFIED: {_markdown(item['rule_id'])} — {_markdown(item['url'])}. "
                f"{_markdown(item.get('reason', 'A successful recheck is required.'))}"
            )
        lines.append("")
    lines.extend(["## Verify the result", "", _RECHECK_INSTRUCTIONS, ""])
    return "\n".join(lines)
