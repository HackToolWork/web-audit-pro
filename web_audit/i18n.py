"""Terminal messages in English and Russian.

English strings are the historical CLI output; keep them stable because scripts
and tests match them. The language comes from --lang, the config, or the locale.
"""

from __future__ import annotations

MESSAGES: dict[str, dict[str, str]] = {
    "config_error": {
        "en": "Configuration error: {error}",
        "ru": "Ошибка конфигурации: {error}",
    },
    "scope_error": {
        "en": "Configuration/scope error: {error}",
        "ru": "Ошибка конфигурации или области проверки: {error}",
    },
    "cms_db_failed": {
        "en": "Vulnerability DB update failed: {error}",
        "ru": "Не удалось обновить базу уязвимостей: {error}",
    },
    "cms_db_updated": {
        "en": "[+] Local CMS advisory database updated: {count} records",
        "ru": "[+] Локальная база уязвимостей CMS обновлена, записей: {count}",
    },
    "cms_db_partial": {
        "en": "[i] {count} CMS source(s) could not be refreshed; existing data kept.",
        "ru": "[i] Не удалось обновить источников CMS: {count}; прежние данные сохранены.",
    },
    "database": {"en": "[i] Database: {path}", "ru": "[i] База данных: {path}"},
    "cms_db_missing": {
        "en": "[i] Local CMS advisory DB not found; run `web-audit --update-db` "
        "before using --cms-vuln-lookup.",
        "ru": "[i] Локальная база уязвимостей CMS не найдена; перед --cms-vuln-lookup "
        "выполните `web-audit --update-db`.",
    },
    "wp_db_fresh": {
        "en": "[i] The WordPress vulnerability database is fresh; Wordfence rate-limits "
        "downloads, so try again in {hours:.1f} hour(s). Database: {path}",
        "ru": "[i] База уязвимостей WordPress свежая; Wordfence ограничивает частоту "
        "скачиваний, попробуйте через {hours:.1f} ч. База: {path}",
    },
    "wp_db_failed": {
        "en": "WordPress vulnerability DB update failed: {error}",
        "ru": "Не удалось обновить базу уязвимостей WordPress: {error}",
    },
    "wp_db_kept": {
        "en": "[i] The existing local database, if any, was kept.",
        "ru": "[i] Имевшаяся локальная база (если была) сохранена.",
    },
    "wp_db_updated": {
        "en": "[+] WordPress vulnerability database updated: {count} records",
        "ru": "[+] База уязвимостей WordPress обновлена, записей: {count}",
    },
    "wp_db_source": {
        "en": "[i] Source: {source}; database: {path}",
        "ru": "[i] Источник: {source}; база: {path}",
    },
    "wp_db_missing": {
        "en": "[i] WordPress components found; run `web-audit --update-wp-db` to check them "
        "for known vulnerabilities.",
        "ru": "[i] Найдены плагины и темы WordPress; чтобы проверить их на известные "
        "уязвимости, выполните `web-audit --update-wp-db`.",
    },
    "wp_db_stale": {
        "en": "[i] WordPress vulnerability database is {days} days old; "
        "run `web-audit --update-wp-db`.",
        "ru": "[i] Базе уязвимостей WordPress уже {days} дн.; "
        "выполните `web-audit --update-wp-db`.",
    },
    "target_required": {
        "en": "Target is required unless --update-db or --update-wp-db is used.",
        "ru": "Укажите адрес сайта (без него работают только --update-db и --update-wp-db).",
    },
    "invalid_target": {"en": "Invalid target URL.", "ru": "Некорректный адрес сайта."},
    "ownership_key": {
        "en": "\n[i] Tokens are signed with {path}; keep this file, because replacing it "
        "invalidates every token already issued.",
        "ru": "\n[i] Коды подписаны ключом {path}; сохраните этот файл — его замена сделает "
        "недействительными все выданные коды.",
    },
    "ownership_verified": {
        "en": "[+] Ownership verified for {domain} via {detail}.",
        "ru": "[+] Владение {domain} подтверждено ({detail}).",
    },
    "ownership_failed": {
        "en": "[!] Ownership not verified: {detail}",
        "ru": "[!] Владение не подтверждено: {detail}",
    },
    "ownership_hint": {
        "en": "[i] Run with --ownership-token for instructions.",
        "ru": "[i] Инструкция по подтверждению: запустите с --ownership-token.",
    },
    "ownership_refused": {
        "en": "Refusing to scan: ownership of {host} is not verified. "
        "{detail} Run with --ownership-token for instructions.",
        "ru": "Проверка отменена: владение {host} не подтверждено. {detail} "
        "Инструкция: запустите с --ownership-token.",
    },
    "empty_company": {
        "en": "[i] Empty --company value; using the default company name: Web Audit Pro.",
        "ru": "[i] Пустое значение --company; используется название по умолчанию: Web Audit Pro.",
    },
    "authorization_refused": {
        "en": "Refusing to scan without authorization confirmation. "
        "Use --yes-i-am-authorized for systems you are permitted to test.",
        "ru": "Проверка отменена: нет подтверждения, что вам разрешено проверять этот сайт. "
        "Для таких сайтов добавьте --yes-i-am-authorized.",
    },
    "config_path": {"en": "[i] Config: {path}", "ru": "[i] Конфигурация: {path}"},
    "wordlist": {
        "en": "[*] Wordlist: {path} (max 500 paths)",
        "ru": "[*] Словарь: {path} (не более 500 путей)",
    },
    "no_wordlist": {
        "en": "[i] No system wordlist found; using the built-in safe path set.",
        "ru": "[i] Системный словарь не найден; используется встроенный безопасный набор путей.",
    },
    "target": {"en": "[*] Target: {target}", "ru": "[*] Сайт: {target}"},
    "paths": {
        "en": "[*] Paths: {paths} | Threads: {threads}",
        "ru": "[*] Адресов: {paths} | Потоков: {threads}",
    },
    "ct_added": {
        "en": "[*] CT discovery: {count} candidate host(s) added",
        "ru": "[*] Поиск поддоменов (CT): добавлено адресов: {count}",
    },
    "ct_warning": {
        "en": "CT discovery warning: {error}",
        "ru": "Предупреждение поиска поддоменов: {error}",
    },
    "dns_warning": {"en": "DNS warning: {error}", "ru": "Предупреждение DNS: {error}"},
    "tls_proxy": {
        "en": "[i] TLS certificate check skipped: a proxy is configured.",
        "ru": "[i] Проверка сертификата пропущена: настроен прокси.",
    },
    "tls_warning": {"en": "TLS warning: {error}", "ru": "Предупреждение TLS: {error}"},
    "diff": {
        "en": "DIFF: {path} | added={added} removed={removed}",
        "ru": "DIFF: {path} | добавлено={added} удалено={removed}",
    },
    "comparison_error": {
        "en": "Comparison error: {error}",
        "ru": "Ошибка сравнения: {error}",
    },
    "scan_complete": {"en": "Scan #{scan_id} complete", "ru": "Проверка №{scan_id} завершена"},
    "stats_urls": {
        "en": "URLs={total} | 2xx={ok} | 3xx={redirects} | 4xx={client} | 5xx={server} "
        "| errors={errors}",
        "ru": "Адресов={total} | 2xx={ok} | 3xx={redirects} | 4xx={client} | 5xx={server} "
        "| ошибок={errors}",
    },
    "stats_findings": {
        "en": "Findings={findings} | high={high} | medium={medium} | low={low} | info={info}",
        "ru": "Находок={findings} | срочно={high} | важно={medium} | рекомендуется={low} "
        "| к сведению={info}",
    },
    "status_line": {"en": "Status: {status}", "ru": "Итог: {status}"},
    "owner_report_line": {
        "en": "Owner report: {path}",
        "ru": "Отчёт для владельца: {path}",
    },
    "opened_report": {
        "en": "[*] Opened report: {path}",
        "ru": "[*] Отчёт открыт в браузере: {path}",
    },
    "open_failed": {
        "en": "[i] Could not open the report automatically; file: {path}",
        "ru": "[i] Не удалось открыть отчёт автоматически; файл: {path}",
    },
    "serve_local_only": {
        "en": "Refusing non-local dashboard bind without --serve-public.",
        "ru": "Панель не запущена: для доступа не с этого компьютера нужен --serve-public.",
    },
    "serve_token_required": {
        "en": "Public dashboard binding requires --serve-token.",
        "ru": "Для публичной панели нужен --serve-token.",
    },
    "dashboard_token": {"en": "Dashboard token: {token}", "ru": "Токен панели: {token}"},
    "dashboard_url": {"en": "Dashboard: {url}", "ru": "Панель: {url}"},
}

SEVERITY_LABELS = {
    "en": {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"},
    "ru": {"high": "СРОЧНО", "medium": "ВАЖНО", "low": "РЕКОМЕНДУЕТСЯ", "info": "К СВЕДЕНИЮ"},
}


def message(lang: str, key: str, **values: object) -> str:
    texts = MESSAGES[key]
    return texts.get(lang, texts["en"]).format(**values)
