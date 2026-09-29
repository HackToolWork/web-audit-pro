"""The audit pipeline as a library call, shared by the CLI and hosted services.

``run_audit`` scans the target (and any extra hosts), runs the target-level DNS,
TLS and WordPress checks, and reports which optional checks actually completed.
It prints nothing: progress messages go to ``notify``. Network-facing helpers are
parameters so callers and tests can replace them.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from urllib.parse import urlparse

from . import wp_vulndb
from .config import Settings
from .dns_audit import findings as dns_findings
from .dns_audit import inspect_domain as default_inspect_domain
from .i18n import message
from .models import CheckResult
from .scanner import Scanner
from .tls_audit import findings as tls_findings
from .tls_audit import inspect_certificate as default_inspect_certificate
from .wordpress import parse_evidence as parse_wordpress_evidence

Notify = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class AuditRun:
    target: str
    results: list[CheckResult]
    # Area -> "checked" | "failed" | "not_checked"; anything not checked must never
    # be presented as passing.
    coverage: dict[str, str]
    wp_vulns_checked_on: str | None


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def attach_to_primary(results: list, target: str, extra: tuple) -> list:
    """Attach target-level findings (DNS, TLS) to the result for the target root."""
    if not extra or not results:
        return results
    primary = next((r for r in results if r.url in {target, target + "/"}), results[0])
    updated = replace(primary, findings=(*primary.findings, *extra))
    return [updated if r is primary else r for r in results]


def match_wordpress_vulnerabilities(
    results: list, lang: str = "en", notify: Notify = lambda text: None
) -> tuple[list, str | None]:
    """Add offline vulnerability findings for WordPress components with known versions.

    Returns the updated results and the local database date when a check ran.
    """
    components = [
        (index, parsed)
        for index, result in enumerate(results)
        for finding in result.findings
        if finding.rule_id.startswith(("wordpress.plugin.", "wordpress.theme."))
        and (parsed := parse_wordpress_evidence(finding.evidence))
    ]
    if not components:
        return results, None
    db = wp_vulndb.load(wp_vulndb.default_path())
    if db is None:
        notify(message(lang, "wp_db_missing"))
        return results, None
    if db.age_days > wp_vulndb.STALE_AFTER_DAYS:
        notify(message(lang, "wp_db_stale", days=int(db.age_days)))
    updated = list(results)
    for index, (kind, slug, version) in components:
        if version is None:
            continue
        extra = wp_vulndb.component_findings(kind, slug, version, db)
        if extra:
            result = updated[index]
            updated[index] = replace(result, findings=(*result.findings, *extra))
    return updated, datetime.fromtimestamp(db.updated_at, UTC).strftime("%Y-%m-%d")


def run_audit(
    target: str,
    settings: Settings,
    *,
    proxy: str | None = None,
    lang: str = "en",
    extra_targets: Sequence[str] = (),
    ignore_rules: Iterable[str] = (),
    notify: Notify = lambda text: None,
    scan: Callable[[Scanner, str], list[CheckResult]] | None = None,
    scanner_factory: Callable[..., Scanner] = Scanner,
    inspect_domain: Callable = default_inspect_domain,
    inspect_certificate: Callable = default_inspect_certificate,
) -> AuditRun:
    """Audit ``target`` (a normalized URL) that the caller has already authorized."""
    scanner = scanner_factory(settings=settings, proxy=proxy)
    scan = scan or (lambda scanner, url: scanner.scan_target(url))
    results: list[CheckResult] = []
    for url in (target, *(t for t in extra_targets if t != target)):
        results.extend(scan(scanner, url))

    parsed = urlparse(target)
    host = parsed.hostname or ""
    # Mail records only exist for real domains, not IP literals or names like "localhost".
    host_is_domain = "." in host and not is_ip_literal(host)
    # CMS and JavaScript checks read page content: they only count as checked when at
    # least one complete 2xx page was fetched. A site that never answered is "failed".
    fetched = any(
        r.status is not None and 200 <= r.status < 300 and not r.error and not r.truncated
        for r in results
    )

    def content_check(enabled: bool) -> str:
        if not enabled:
            return "not_checked"
        return "checked" if fetched else "failed"

    coverage = {
        "cms": content_check(settings.cms_enabled),
        "js": content_check(settings.scan_js),
        "email": "not_checked",
        "tls": "not_checked",
    }
    if settings.dns_enabled and host_is_domain:
        try:
            results = attach_to_primary(results, target, dns_findings(inspect_domain(host)))
            coverage["email"] = "checked"
        except Exception as exc:
            coverage["email"] = "failed"
            notify(message(lang, "dns_warning", error=f"{type(exc).__name__}: {exc}"))
    if settings.tls_check_enabled and host and parsed.scheme == "https":
        if proxy:
            notify(message(lang, "tls_proxy"))
        else:
            try:
                certificate = inspect_certificate(
                    host, parsed.port or 443, timeout=settings.timeout
                )
                if certificate.connect_error:
                    coverage["tls"] = "failed"
                    notify(message(lang, "tls_warning", error=certificate.connect_error))
                else:
                    coverage["tls"] = "checked"
                results = attach_to_primary(results, target, tls_findings(certificate))
            except Exception as exc:
                coverage["tls"] = "failed"
                notify(message(lang, "tls_warning", error=f"{type(exc).__name__}: {exc}"))

    wp_vulns_checked_on = None
    if settings.cms_enabled:
        results, wp_vulns_checked_on = match_wordpress_vulnerabilities(results, lang, notify)

    ignored = set(ignore_rules)
    if ignored:
        results = [
            replace(
                result,
                findings=tuple(f for f in result.findings if f.rule_id not in ignored),
                verified_rules=tuple(rule for rule in result.verified_rules if rule not in ignored),
            )
            for result in results
        ]
    return AuditRun(target, results, coverage, wp_vulns_checked_on)
