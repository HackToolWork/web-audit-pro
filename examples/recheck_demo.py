"""Generate synthetic recheck reports offline, using the real scanner and reporting code.

Run from the repository root: python -m examples.recheck_demo
Only HTTP transport is replaced; no connections or DNS lookups are made.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

import requests

from web_audit.config import Settings
from web_audit.diffing import load_report
from web_audit.lifecycle_cli import render_lifecycle_summary
from web_audit.lifecycle_reporting import summarize_lifecycle
from web_audit.reports import save_html, save_json
from web_audit.scanner import Scanner

TARGET = "https://demo.example.test"


class DemoResponse:
    status_code = 200
    raw = None

    def __init__(self, *, fixed: bool):
        self.headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Frame-Options": "DENY",
        }
        if fixed:
            self.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def iter_content(self, chunk_size):
        yield b"<!doctype html><html><body>Synthetic demo page</body></html>"


def generate_demo(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    scanner = Scanner(
        Settings(
            paths=("/",),
            retries=0,
            requests_per_second=10000,
            dns_enabled=False,
            cms_enabled=False,
            scan_js=False,
        )
    )
    session = scanner._session()
    try:
        with patch.object(session, "get", return_value=DemoResponse(fixed=False)):
            baseline = scanner.check(TARGET + "/")
        with patch.object(session, "get", return_value=DemoResponse(fixed=True)):
            fixed = scanner.check(TARGET + "/")
        with patch.object(session, "get", side_effect=requests.Timeout("Synthetic demo timeout")):
            unavailable = scanner.check(TARGET + "/")
    finally:
        session.close()

    save_json(TARGET, [baseline], output_dir / "01-found.json")
    previous = load_report(output_dir / "01-found.json")
    scenarios = (
        ("01-found", baseline, {"target": TARGET, "results": []}),
        ("02-fixed", fixed, previous),
        ("03-unverified", unavailable, previous),
    )
    for name, result, before in scenarios:
        save_json(TARGET, [result], output_dir / f"{name}.json")
        current = load_report(output_dir / f"{name}.json")
        lifecycle = summarize_lifecycle(before, current)
        save_html(
            TARGET,
            [result],
            output_dir / f"{name}.html",
            company="Web Audit Pro · Synthetic demo",
            lifecycle=lifecycle,
        )
        print(f"\n{name}\n{render_lifecycle_summary(lifecycle)}")

    index = output_dir / "index.html"
    index.write_text(INDEX_HTML, encoding="utf-8")
    return index


INDEX_HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web Audit Pro — повторная проверка</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101820;color:#e9f0f5}
body{max-width:960px;margin:0 auto;padding:48px 24px;line-height:1.65}
.eyebrow{color:#79d7cb;letter-spacing:.12em;font-size:.8rem;font-weight:700}
h1{font-size:clamp(2rem,4vw,3rem);line-height:1.15;max-width:780px}
.lead{font-size:1.15rem;color:#c4d0da;max-width:770px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px;margin:32px 0}
article{border:1px solid #3b4b5a;border-radius:14px;padding:24px;background:#172430}
.status{font-weight:800;font-size:.85rem;letter-spacing:.08em}
.new{color:#a9cbff}.fixed{color:#7ae5b4}.unknown{color:#ffcf83}
h2{font-size:1.25rem;line-height:1.35}a{color:#a9cbff;text-underline-offset:4px}
.note{border-left:3px solid #79d7cb;padding:6px 18px;color:#c4d0da}
code{color:#d9e8ff}footer{color:#9cacba;font-size:.9rem;margin-top:32px}
</style></head><body>
<div class="eyebrow">WEB AUDIT PRO / OFFLINE DEMO</div>
<h1>Исправление должно быть подтверждено проверкой</h1>
<p class="lead">Одна находка, три результата. Отчёты сформированы настоящим кодом сканера
на искусственных HTTP-ответах. Подключений к сайтам не было.</p>
<div class="grid">
<article><div class="status new">01 · NEW</div><h2>Проблема найдена</h2>
<p>HTML-страница ответила 200. Заголовка Content-Security-Policy нет.</p>
<p><a href="01-found.html">Посмотреть исходный отчёт</a></p></article>
<article><div class="status fixed">02 · FIXED</div><h2>Исправление подтверждено</h2>
<p>Тот же URL ответил 200. Ответ получен полностью; заголовок CSP присутствует.</p>
<p><a href="02-fixed.html">Посмотреть повторную проверку</a></p></article>
<article><div class="status unknown">03 · UNVERIFIED</div><h2>Подтверждения нет</h2>
<p>Запрос завершился таймаутом. Находок нет, но считать проблему исправленной нельзя.</p>
<p><a href="03-unverified.html">Посмотреть неудачную проверку</a></p></article>
</div>
<p class="note">Сценарии 02 и 03 отдельно сравниваются с исходным отчётом 01.
Это две альтернативы повторной проверки. FIXED относится к отсутствовавшему заголовку;
качество политики CSP и безопасность всего сайта этим статусом не подтверждаются.</p>
<p>Та же осторожная логика применяется, если URL пропущен, ответ усечён,
правило исключено или старый отчёт не содержит данных о пройденных проверках.</p>
<footer>Демонстрационные данные · demo.example.test · Без внешних ресурсов и аналитики</footer>
</body></html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/recheck-demo"))
    args = parser.parse_args()
    print(f"\nDemo: {generate_demo(args.output_dir).resolve()}")


if __name__ == "__main__":
    main()
