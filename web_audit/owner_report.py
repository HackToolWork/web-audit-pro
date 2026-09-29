"""Plain-language report for non-technical site owners.

The owner report reuses the action plan and lifecycle summary and adds a
traffic-light status and per-area coverage. Like the rest of the project it
fails closed: an area that did not run is shown as "not checked", never as OK.
"""

from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from pathlib import Path

from .action_plan import build_action_plan
from .models import CheckResult
from .owner_texts import LANGUAGES, UI, rule_text
from .ownership import OwnershipProof
from .reports import _atomic_write, logo_html
from .wordpress import parse_evidence

AREAS = ("tls", "email", "site", "cms", "js")
CoverageState = str  # "checked" | "failed" | "not_checked"

_FIXED_IN = re.compile(r"; fixed in ([^\s:]+):")
_SOURCE_MARKER = "Source: Wordfence Intelligence."
_CMS_EVIDENCE = re.compile(r"^Detected (.+?)(?: version ([^\s(]+))? \(")
_CHANGE_STATES = ("fixed", "new", "regressed", "changed", "present", "unverified")


def rule_area(rule_id: str) -> str:
    if rule_id.startswith("tls."):
        return "tls"
    if rule_id.startswith(("dns.spf.", "dns.dmarc.")):
        return "email"
    if rule_id.startswith(("cms.", "wordpress.")):
        return "cms"
    if rule_id.startswith("secret."):
        return "js"
    return "site"


def _site_checked(results: list[CheckResult]) -> bool:
    return any(
        r.status is not None and 200 <= r.status < 300 and not r.error and not r.truncated
        for r in results
    )


def build_owner_summary(
    results: list[CheckResult],
    *,
    coverage: dict[str, CoverageState] | None = None,
    lifecycle: dict | None = None,
    lang: str = "en",
    wp_vulns_checked_on: str | None = None,
    ownership: OwnershipProof | None = None,
) -> dict:
    """Build the language-specific data behind the owner report."""
    if lang not in LANGUAGES:
        raise ValueError(f"unsupported report language: {lang}")
    coverage = dict(coverage or {})
    coverage["site"] = "checked" if _site_checked(results) else "failed"

    plan = build_action_plan(results)
    items = []
    component_versions: dict[tuple[str, str], set[str | None]] = {}
    component_urls: set[str] = set()
    for task in plan["tasks"]:
        if task["rule_id"].startswith(("wordpress.plugin.", "wordpress.theme.")):
            # One inventory table instead of a card per plugin.
            component_urls.update(task["urls"])
            for observation in task["observations"]:
                parsed = parse_evidence(observation["evidence"])
                if parsed:
                    kind, slug, version = parsed
                    component_versions.setdefault((kind, slug), set()).add(version)
            continue
        if task["rule_id"].startswith("wordpress.vulnerable."):
            text = _vulnerable_text(task, lang)
        else:
            text = rule_text(task["rule_id"], lang)
        if text is None:
            recommendations = task["recommendations"]
            text = (task["title"], "", recommendations[0] if recommendations else "")
        title, why, todo = text
        items.append(
            {
                "rule_id": task["rule_id"],
                "level": task["severity"],
                "area": rule_area(task["rule_id"]),
                "title": title,
                "why": why,
                "todo": todo,
                # One confident observation confirms the issue; incomplete responses
                # elsewhere (redirects, errors) must not cast doubt on it.
                "needs_validation": "high" not in task["confidences"],
                "urls": task["urls"],
                "evidence": sorted({o["evidence"] for o in task["observations"]}),
            }
        )

    if component_versions:
        title, why, todo = rule_text("wordpress.components", lang)
        components = []
        for (kind, slug), versions in sorted(component_versions.items()):
            known = versions - {None}
            components.append((kind, slug, next(iter(known)) if len(known) == 1 else None))
        items.append(
            {
                "rule_id": "wordpress.components",
                "level": "info",
                "area": "cms",
                "title": title,
                "why": why,
                "todo": todo,
                "needs_validation": False,
                "urls": sorted(component_urls),
                "evidence": [],
                "components": components,
            }
        )

    areas = {}
    for area in AREAS:
        levels = {i["level"] for i in items if i["area"] == area} - {"info"}
        state = coverage.get(area, "not_checked")
        if "high" in levels:
            areas[area] = "urgent"
        elif levels:
            areas[area] = "issues"
        elif area == "cms" and state == "checked":
            # Detection is not a vulnerability check, so it never reads as "OK".
            areas[area] = "detected" if _cms_products(items) else "not_detected"
        else:
            areas[area] = {"checked": "ok"}.get(state, state)

    levels = {item["level"] for item in items}
    if "high" in levels:
        status = "red"
    elif coverage["site"] != "checked":
        status = "unknown"
    elif "medium" in levels:
        status = "yellow"
    else:
        status = "green"

    # Never present an incomplete check as "all good": plugin vulnerabilities are the
    # main risk for WordPress sites, and failed checks prove nothing either way.
    notices = []
    has_components = any(item["rule_id"] == "wordpress.components" for item in items)
    if has_components and not wp_vulns_checked_on:
        notices.append(UI[lang]["notice_wp_unchecked"])
    if any(areas[area] == "failed" for area in ("tls", "email")):
        notices.append(UI[lang]["notice_failed_checks"])
    if status == "green" and notices:
        status = "incomplete"

    changes = None
    if lifecycle is not None:
        changes = {}
        for state in _CHANGE_STATES:
            titles = []
            for entry in lifecycle.get(state, []):
                titles.append(_change_title(entry["rule_id"], lang))
            changes[state] = sorted(set(titles))

    attribution = []
    for item in items:
        if item["rule_id"].startswith("wordpress.vulnerable."):
            for evidence in item["evidence"]:
                _, _, notices = evidence.partition(_SOURCE_MARKER)
                if notices.strip():
                    attribution.append(notices.strip())
    area_descriptions = {}
    if wp_vulns_checked_on:
        area_descriptions["cms"] = UI[lang]["area_cms_desc_checked"].format(
            date=wp_vulns_checked_on
        )
        attribution.insert(0, UI[lang]["vuln_source"].format(date=wp_vulns_checked_on))

    return {
        "lang": lang,
        "status": status,
        "areas": areas,
        "area_notes": {"cms": _cms_notes(items, lang)},
        "area_descriptions": area_descriptions,
        "notices": notices,
        "items": items,
        "changes": changes,
        "attribution": list(dict.fromkeys(attribution)),
        "ownership": (
            {"method": ownership.method, "domain": ownership.domain}
            if ownership is not None and ownership.verified
            else None
        ),
    }


def _vulnerable_text(task: dict, lang: str) -> tuple[str, str, str] | None:
    ui = UI[lang]
    evidence = next((o["evidence"] for o in task["observations"]), "")
    parsed = parse_evidence(evidence)
    if parsed is None or parsed[2] is None:
        return None
    kind, slug, version = parsed
    title = ui["vuln_title"].format(kind=ui["kind_" + kind], name=slug, version=version)
    fixed = _FIXED_IN.search(evidence)
    todo = ui["vuln_todo_fixed"].format(version=fixed.group(1)) if fixed else ui["vuln_todo_nofix"]
    return title, ui["vuln_why"], todo


def _change_title(rule_id: str, lang: str) -> str:
    if rule_id.startswith("wordpress.vulnerable."):
        kind, _, slug = rule_id.removeprefix("wordpress.vulnerable.").partition(".")
        if kind in {"plugin", "theme"} and slug:
            return UI[lang]["vuln_change"].format(kind=UI[lang]["kind_" + kind], name=slug)
    kind, _, slug = rule_id.removeprefix("wordpress.").partition(".")
    if rule_id.startswith("wordpress.") and kind in {"plugin", "theme"} and slug:
        return f"{UI[lang]['kind_' + kind]} WordPress: {slug}"
    text = rule_text(rule_id, lang)
    return text[0] if text else rule_id


def _cms_notes(items: list[dict], lang: str) -> list[str]:
    notes = _cms_products(items)
    for item in items:
        if item.get("components"):
            notes.append(UI[lang]["components_count"].format(count=len(item["components"])))
    return notes


def _cms_products(items: list[dict]) -> list[str]:
    products = set()
    for item in items:
        if not item["rule_id"].startswith("cms.detected."):
            continue
        for evidence in item["evidence"]:
            match = _CMS_EVIDENCE.match(evidence)
            if match:
                products.add(" ".join(part for part in match.groups() if part))
    return sorted(products)


_STYLE = """
:root{--fg:#1d2433;--muted:#5b6475;--line:#e3e7ef;--bg:#f5f7fb;--card:#fff;
--red:#c62828;--yellow:#b26a00;--green:#2e7d32;--grey:#6b7280;--accent:#2457c5}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.55 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 48px}
header{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px}
.meta{color:var(--muted);font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;
margin:12px 0}
.status{border-left:8px solid var(--c);display:flex;gap:16px;align-items:center}
.status .dot{width:44px;height:44px;border-radius:50%;background:var(--c);flex:none}
.status h2{margin:0 0 4px;color:var(--c)}
.status p{margin:0}
.red{--c:var(--red)}.yellow{--c:var(--yellow)}.green{--c:var(--green)}
.unknown,.incomplete{--c:var(--grey)}
.status p.notice{margin-top:8px;font-weight:600}
.areas{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.areas .card{margin:0}
.pill{display:inline-block;padding:2px 10px;border-radius:10px;font-size:13px;font-weight:600;
color:#fff;background:var(--c)}
.area-ok{--c:var(--green)}.area-urgent{--c:var(--red)}.area-issues{--c:var(--yellow)}
.area-detected{--c:var(--accent)}.area-failed,.area-not_checked,.area-not_detected{--c:var(--grey)}
.level-high{--c:var(--red)}.level-medium{--c:var(--yellow)}.level-low{--c:var(--accent)}
.level-info{--c:var(--grey)}
.area-notes{font-weight:600;font-size:14px;margin-top:6px}
.item h3{margin:6px 0 8px;font-size:17px}
.item dt{font-weight:600;margin-top:8px}.item dd{margin:2px 0 0}
.note{background:#fff7e6;border-radius:8px;padding:8px 12px;margin-top:10px;font-size:14px}
details{margin-top:10px;font-size:14px;color:var(--muted)}
details code{word-break:break-all}
ul.changes{margin:0;padding-left:20px}
table.components{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}
table.components th,table.components td{text-align:left;padding:6px 8px;
border-bottom:1px solid var(--line)}
table.components td:nth-child(2){word-break:break-word}
footer{margin-top:40px;color:var(--muted);font-size:13px}
@media print{body{background:#fff}.card{break-inside:avoid}main{padding:0}}
"""


def render_owner_report_html(
    target: str,
    data: dict,
    *,
    company: str,
    logo_html: str = "",
    generated: datetime | None = None,
) -> str:
    ui = UI[data["lang"]]
    esc = html.escape
    generated = generated or datetime.now(UTC)
    status = data["status"]

    area_cards = []
    for area, state in data["areas"].items():
        notes = " · ".join(data["area_notes"].get(area, []))
        notes_html = f'<div class="area-notes">{esc(notes)}</div>' if notes else ""
        description = data["area_descriptions"].get(area) or ui[f"area_{area}_desc"]
        area_cards.append(
            f'<div class="card"><strong>{esc(ui[f"area_{area}"])}</strong><br>'
            f'<span class="pill area-{state}">{esc(ui[f"area_{state}"])}</span>'
            f'{notes_html}<div class="meta">{esc(description)}</div></div>'
        )

    changes_html = ""
    if data["changes"] is not None:
        rows = []
        for state, titles in data["changes"].items():
            if not titles:
                continue
            listed = "".join(f"<li>{esc(title)}</li>" for title in titles)
            rows.append(
                f"<p><strong>{esc(ui[f'changes_{state}'])}: {len(titles)}</strong></p>"
                f'<ul class="changes">{listed}</ul>'
            )
        if rows:
            changes_html = f'<h2>{esc(ui["changes"])}</h2><div class="card">{"".join(rows)}</div>'

    item_cards = []
    for item in data["items"]:
        parts = [
            f'<div class="card item"><span class="pill level-{item["level"]}">'
            f"{esc(ui['level_' + item['level']])}</span>",
            f"<h3>{esc(item['title'])}</h3><dl>",
        ]
        if item["why"]:
            parts.append(f"<dt>{esc(ui['why'])}</dt><dd>{esc(item['why'])}</dd>")
        if item["todo"]:
            parts.append(f"<dt>{esc(ui['todo'])}</dt><dd>{esc(item['todo'])}</dd>")
        parts.append("</dl>")
        if item.get("components"):
            rows = "".join(
                f"<tr><td>{esc(ui['kind_' + kind])}</td><td>{esc(slug)}</td>"
                f"<td>{esc(version or ui['version_unknown'])}</td></tr>"
                for kind, slug, version in item["components"]
            )
            parts.append(
                f'<table class="components"><thead><tr><th>{esc(ui["col_kind"])}</th>'
                f"<th>{esc(ui['col_name'])}</th><th>{esc(ui['col_version'])}</th></tr>"
                f"</thead><tbody>{rows}</tbody></table>"
            )
        if item["needs_validation"]:
            parts.append(f'<div class="note">{esc(ui["validate"])}</div>')
        details = "".join(f"<li><code>{esc(url)}</code></li>" for url in item["urls"])
        details += "".join(f"<li>{esc(evidence)}</li>" for evidence in item["evidence"])
        parts.append(
            f"<details><summary>{esc(ui['details'])} ({esc(ui['pages'])}: "
            f"{len(item['urls'])})</summary><p><code>{esc(item['rule_id'])}</code></p>"
            f"<ul>{details}</ul></details></div>"
        )
        item_cards.append("".join(parts))
    attribution = "".join(f"<p>{esc(line)}</p>" for line in data["attribution"])
    notices_html = "".join(f'<p class="notice">{esc(line)}</p>' for line in data["notices"])
    ownership_html = ""
    if data.get("ownership"):
        method = ui["ownership_" + data["ownership"]["method"]]
        domain = data["ownership"]["domain"]
        ownership_html = f"<br>{esc(ui['ownership_verified'])}: {esc(method)} ({esc(domain)})"
    actions_html = "".join(item_cards) or f'<div class="card">{esc(ui["no_actions"])}</div>'

    return f"""<!doctype html>
<html lang="{data["lang"]}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(ui["title"])} — {esc(target)}</title><style>{_STYLE}</style></head>
<body><main>
<header><div><h1>{esc(ui["title"])}</h1>
<div class="meta">{esc(target)} · {esc(ui["checked_on"])}: {generated:%Y-%m-%d}
 · {esc(ui["prepared_by"])}: {esc(company)}{ownership_html}</div></div>{logo_html}</header>
<div class="card status {status}"><div class="dot"></div><div>
<h2>{esc(ui["status_" + status])}</h2><p>{esc(ui["status_" + status + "_text"])}</p>
{notices_html}</div></div>
<h2>{esc(ui["areas"])}</h2><div class="areas">{"".join(area_cards)}</div>
{changes_html}
<h2>{esc(ui["actions"])}</h2>{actions_html}
<footer>{esc(ui["disclaimer"])}{attribution}</footer>
</main></body></html>
"""


def save_owner_report(
    target: str,
    results: list[CheckResult],
    path: Path,
    *,
    lang: str = "en",
    company: str = "Web Audit Pro",
    logo_path: Path | None = None,
    coverage: dict[str, CoverageState] | None = None,
    lifecycle: dict | None = None,
    wp_vulns_checked_on: str | None = None,
    ownership: OwnershipProof | None = None,
) -> None:
    data = build_owner_summary(
        results,
        coverage=coverage,
        lifecycle=lifecycle,
        lang=lang,
        wp_vulns_checked_on=wp_vulns_checked_on,
        ownership=ownership,
    )
    document = render_owner_report_html(
        target, data, company=company, logo_html=logo_html(logo_path, company)
    )
    _atomic_write(path, lambda file: file.write(document))
