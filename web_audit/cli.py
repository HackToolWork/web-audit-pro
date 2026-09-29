from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import subprocess
import sys
import uuid
import webbrowser
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from . import PROJECT_NAME, __version__, ownership, wp_vulndb
from .config import Settings, apply_cli_config, coerce_cli_types
from .database import Database
from .diffing import compare_reports, load_report, save_diff
from .dns_audit import findings as dns_findings
from .dns_audit import inspect_domain
from .lifecycle_cli import render_lifecycle_summary
from .lifecycle_reporting import summarize_lifecycle, summarize_lifecycle_history
from .logging import configure_logging, console_print, paint
from .owner_report import save_owner_report
from .ownership import OwnershipProof
from .reports import save_action_plan, save_csv, save_html, save_json, summary
from .sarif import save_sarif
from .scanner import Scanner
from .scope import load_scope, target_in_scope
from .serve import generate_token, run_server
from .subdomains import discover_from_crtsh
from .tls_audit import findings as tls_findings
from .tls_audit import inspect_certificate
from .utils import is_non_public_address, normalize_target, resolve_target_addresses
from .wordpress import parse_evidence as parse_wordpress_evidence

logger = logging.getLogger(__name__)
_SEVERITY_ORDER = {"none": 99, "info": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-audit",
        description="Low-impact HTTP audit tool for systems you are authorized to assess.",
    )
    parser.add_argument("target", nargs="?", help="Target URL or hostname")
    parser.add_argument("--config", type=Path, help="TOML configuration file")
    parser.add_argument(
        "--update-db",
        action="store_true",
        default=None,
        help="Refresh the local CMS advisory database from NVD and exit",
    )
    parser.add_argument(
        "--update-wp-db",
        action="store_true",
        default=None,
        help=(
            "Download the Wordfence Intelligence WordPress vulnerability feed "
            "(needs WORDFENCE_API_KEY) for offline plugin/theme checks, and exit"
        ),
    )
    parser.add_argument(
        "--ownership-token",
        action="store_true",
        default=None,
        help="Print DNS/file ownership verification instructions for the target and exit",
    )
    parser.add_argument(
        "--verify-ownership",
        action="store_true",
        default=None,
        help="Check whether the target's ownership token is published and exit",
    )
    parser.add_argument(
        "--require-ownership",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Refuse to scan unless ownership of the target is verified (default: off)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=None,
        help="Concurrent workers (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="HTTP timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=None,
        help="Maximum response bytes to read (default: 1048576)",
    )
    parser.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument(
        "--requests-per-second",
        type=float,
        default=None,
        help="Global request rate limit (default: 2/s)",
    )
    parser.add_argument(
        "--scope-file",
        type=Path,
        help="File of in-scope hosts; supports exact hosts and *.example.com",
    )
    parser.add_argument(
        "--compare", type=Path, default=None, help="Compare this run with an earlier report.json"
    )
    parser.add_argument(
        "--ignore-rule",
        action="append",
        default=None,
        help="Suppress a finding rule (repeatable)",
    )
    parser.add_argument("--output-dir", type=Path, default=None, help="Report directory")
    parser.add_argument("--paths", nargs="*", help="Override default paths")
    parser.add_argument(
        "--paths-file",
        type=Path,
        help="Read additional paths from a UTF-8 text file (one path per line; # comments allowed)",
    )
    parser.add_argument(
        "--insecure-tls",
        action="store_true",
        default=None,
        help="Disable TLS certificate verification (authorized lab/testing use only)",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        default=None,
        help=(
            "Permit targets resolving to non-public/reserved IP addresses "
            "(authorized internal use only)."
        ),
    )
    parser.add_argument(
        "--dns",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Run passive DNS checks (default: on)",
    )
    parser.add_argument(
        "--tls-check",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Check TLS certificate validity and expiry for HTTPS targets (default: on)",
    )
    parser.add_argument(
        "--cms",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Fingerprint common CMS from fetched content (default: on)",
    )
    parser.add_argument(
        "--scan-js",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Inspect same-origin JavaScript files for credential-like strings (default: on)",
    )
    parser.add_argument(
        "--max-js-files",
        type=int,
        default=None,
        help="Maximum same-origin JavaScript files to inspect (default: 20)",
    )
    parser.add_argument(
        "--discover-subdomains",
        action="store_true",
        default=None,
        help="Discover candidate in-domain hosts from Certificate Transparency",
    )
    parser.add_argument(
        "--cms-vuln-lookup",
        action="store_true",
        default=None,
        help="Enrich detected CMS versions with NVD CVE references",
    )
    parser.add_argument(
        "--nvd-timeout",
        type=float,
        default=None,
        help="NVD lookup timeout in seconds",
    )
    parser.add_argument(
        "--kali-wordlist",
        action="store_true",
        default=None,
        help="Explicitly use Kali dirb/common.txt when present",
    )
    parser.add_argument(
        "--tui", action="store_true", default=None, help="Show a Rich progress dashboard"
    )
    parser.add_argument(
        "--open",
        action="store_true",
        default=None,
        help="Open the generated HTML report in the default browser after the scan",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        default=None,
        help="Serve a read-only local dashboard after the scan",
    )
    parser.add_argument("--serve-host", default=None, help="Dashboard bind address")
    parser.add_argument("--serve-port", type=int, default=None, help="Dashboard port")
    parser.add_argument("--serve-token", help="Dashboard bearer/query token")
    parser.add_argument(
        "--serve-public",
        action="store_true",
        default=None,
        help="Permit non-local dashboard binding; requires an explicit token",
    )
    parser.add_argument("--version", action="version", version=f"{PROJECT_NAME} {__version__}")
    parser.add_argument(
        "--company",
        nargs="?",
        const="",
        default=None,
        metavar="NAME",
        help="Company name for HTML reports; defaults to Web Audit Pro when omitted",
    )
    parser.add_argument(
        "--theme",
        choices=("dark", "light", "cyberpunk"),
        default=None,
        help="HTML report theme",
    )
    parser.add_argument("--logo", type=Path, help="Optional PNG/JPEG logo embedded in HTML")
    parser.add_argument(
        "--lang",
        choices=("en", "ru"),
        default=None,
        help="Language of the plain-language owner report (default: from the system locale)",
    )
    parser.add_argument(
        "--user-agent-profile",
        choices=("stable", "browser"),
        default=None,
        help="Stable scanner UA profile",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "info", "low", "medium", "high"),
        default=None,
        help="Exit non-zero when findings meet this severity threshold.",
    )
    parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        help="Confirm you are authorized to audit the target.",
    )
    return parser


def _print_result(result) -> None:
    if result.status is None:
        console_print(paint(f"[-] ERR {result.url} — {result.error}", "31"))
    elif result.status < 300:
        console_print(paint(f"[+] {result.status} {result.url} ({result.elapsed_ms:.1f} ms)", "32"))
    elif result.status < 400:
        location = f" -> {result.location}" if result.location else ""
        console_print(paint(f"[>] {result.status} {result.url}{location}", "33"))
    elif result.status == 403:
        console_print(paint(f"[!] 403 {result.url}", "34"))
    else:
        console_print(paint(f"[-] {result.status} {result.url}", "31"))

    for finding in result.findings:
        label = f"    [{finding.severity.upper()}] {finding.title} ({finding.rule_id})"
        console_print(paint(label, "35"))


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _attach_to_primary(results: list, target: str, extra: tuple) -> list:
    """Attach target-level findings (DNS, TLS) to the result for the target root."""
    if not extra or not results:
        return results
    primary = next((r for r in results if r.url in {target, target + "/"}), results[0])
    updated = replace(primary, findings=(*primary.findings, *extra))
    return [updated if r is primary else r for r in results]


def _verify_ownership(args: argparse.Namespace, target: str) -> OwnershipProof:
    return ownership.verify(
        target,
        timeout=args.timeout,
        verify_tls=not args.insecure_tls,
        proxies={"http": args.proxy, "https": args.proxy} if args.proxy else None,
        allow_private=bool(args.allow_private),
    )


def _match_wordpress_vulnerabilities(results: list) -> tuple[list, str | None]:
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
    db_path = wp_vulndb.default_path()
    db = wp_vulndb.load(db_path)
    if db is None:
        console_print(
            "[i] WordPress components found; run `web-audit --update-wp-db` to check them "
            "for known vulnerabilities."
        )
        return results, None
    if db.age_days > wp_vulndb.STALE_AFTER_DAYS:
        console_print(
            f"[i] WordPress vulnerability database is {int(db.age_days)} days old; "
            "run `web-audit --update-wp-db`."
        )
    updated = list(results)
    for index, (kind, slug, version) in components:
        if version is None:
            continue
        extra = wp_vulndb.component_findings(kind, slug, version, db)
        if extra:
            result = updated[index]
            updated[index] = replace(result, findings=(*result.findings, *extra))
    return updated, datetime.fromtimestamp(db.updated_at, UTC).strftime("%Y-%m-%d")


def _meets_threshold(results, threshold: str) -> bool:
    if threshold == "none":
        return False
    required = _SEVERITY_ORDER[threshold]
    return any(
        _SEVERITY_ORDER[finding.severity] >= required
        for result in results
        for finding in result.findings
    )


_WORDLIST_CANDIDATES = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/dirb/wordlists/common.txt",
)


def _normalize_path_entry(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        raise ValueError("path entries must be relative paths, not full URLs")
    return value if value.startswith("/") else f"/{value}"


def _load_paths_file(path: Path, *, limit: int | None = None) -> tuple[str, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"could not read paths file: {exc}") from exc
    paths: list[str] = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        normalized = _normalize_path_entry(value)
        if normalized:
            paths.append(normalized)
            if limit is not None and len(paths) >= limit:
                break
    unique = tuple(dict.fromkeys(paths))
    if not unique:
        raise ValueError("paths file contains no paths")
    return unique


def _find_wordlist() -> Path | None:
    override = os.environ.get("WEB_AUDIT_WORDLIST", "").strip()
    candidates = ((override,) if override else ()) + _WORDLIST_CANDIDATES
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.R_OK):
            return path
    return None


def _open_report(path: Path) -> bool:
    """Open an HTML report without making report opening a scan failure."""
    absolute = path.expanduser().resolve(strict=False)
    try:
        if sys.platform.startswith("linux"):
            completed = subprocess.run(
                ["xdg-open", str(absolute)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            if completed.returncode == 0:
                return True
        elif sys.platform == "darwin":
            completed = subprocess.run(
                ["open", str(absolute)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            if completed.returncode == 0:
                return True
        elif os.name == "nt":
            os.startfile(absolute)
            return True
    except (OSError, subprocess.SubprocessError):
        pass

    try:
        return webbrowser.open(absolute.as_uri())
    except (OSError, TypeError, ValueError):
        return False


def _run_output_paths(settings: Settings, target: str, started: datetime) -> None:
    """Make default output files unique while preserving explicit filenames."""
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in target).strip("-")
    slug = (slug or "target")[:80]
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:10]
    run_id = uuid.uuid4().hex[:10]
    suffix = f"{slug}-{stamp}-{digest}-{run_id}"
    defaults = {
        "csv_name": f"results-{suffix}.csv",
        "html_name": f"report-{suffix}.html",
        "json_name": f"report-{suffix}.json",
        "sarif_name": f"report-{suffix}.sarif",
        "diff_name": f"diff-{suffix}.json",
        "owner_name": f"owner-report-{suffix}.html",
        "log_name": f"scanner-{suffix}.log",
    }
    for attr, value in defaults.items():
        if getattr(settings, attr) == Settings.__dataclass_fields__[attr].default:
            setattr(settings, attr, value)


_BUILTIN_DEFAULTS = {
    "threads": 10,
    "timeout": 5.0,
    "max_size": 1024 * 1024,
    "requests_per_second": 2.0,
    "scope_file": None,
    "output_dir": Path("reports"),
    "proxy": None,
    "insecure_tls": False,
    "allow_private": False,
    "dns": True,
    "tls_check": True,
    "cms": True,
    "scan_js": True,
    "max_js_files": 20,
    "content_scan_max_size": 512 * 1024,
    "discover_subdomains": False,
    "cms_vuln_lookup": False,
    "nvd_timeout": 12.0,
    "kali_wordlist": False,
    "tui": False,
    "open": False,
    "serve": False,
    "serve_host": "127.0.0.1",
    "serve_port": 8765,
    "serve_token": None,
    "serve_public": False,
    "company": "Web Audit Pro",
    "theme": "dark",
    "logo": None,
    "user_agent_profile": "stable",
    "fail_on": "none",
    "ignore_rule": None,
    "compare": None,
    "paths": None,
    "paths_file": None,
    "config": None,
    "update_db": False,
    "update_wp_db": False,
    "ownership_token": False,
    "verify_ownership": False,
    "require_ownership": False,
}


def _system_lang() -> str:
    """Report language from the locale (LC_ALL > LC_MESSAGES > LANG): ru or en."""
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.getenv(name, "").strip()
        if value:
            return "ru" if value.lower().startswith("ru") else "en"
    return "en"


_AUTHORIZATION_PROMPT = {
    "en": "Do you own {host} or have permission to test it? [y/N]: ",
    "ru": "Вы владелец сайта {host} или у вас есть разрешение на его проверку? [y/N]: ",
}


def _confirm_authorization(target: str, lang: str) -> bool:
    """Ask interactively; non-interactive runs still require --yes-i-am-authorized."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    host = urlparse(normalize_target(target) or target).hostname or target
    try:
        answer = input(_AUTHORIZATION_PROMPT[lang].format(host=host))
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes", "д", "да"}


def _prepare_args(args: argparse.Namespace) -> tuple[argparse.Namespace, Path | None]:
    config_path = apply_cli_config(args, args.config)
    for key, default in _BUILTIN_DEFAULTS.items():
        if getattr(args, key, None) is None:
            setattr(args, key, default)
    if args.ignore_rule is None:
        args.ignore_rule = []
    if args.lang is None:
        args.lang = _system_lang()
    coerce_cli_types(args)
    for attr in ("scope_file", "output_dir", "paths_file", "compare", "logo"):
        value = getattr(args, attr, None)
        if value is not None and not isinstance(value, Path):
            setattr(args, attr, Path(value).expanduser())
    return args, config_path


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    try:
        args, config_path = _prepare_args(args)
    except ValueError as exc:
        console_print(f"Configuration error: {exc}")
        return 2

    if args.update_db:
        from .vulndb import default_db_path, update_database

        db_path = default_db_path()
        try:
            updated, failed = update_database(db_path, timeout=args.nvd_timeout)
        except Exception as exc:
            console_print(f"Vulnerability DB update failed: {type(exc).__name__}: {exc}")
            return 1
        console_print(f"[+] Local CMS advisory database updated: {updated} records")
        if failed:
            console_print(f"[i] {failed} CMS source(s) could not be refreshed; existing data kept.")
        console_print(f"[i] Database: {db_path}")
        return 0

    if args.update_wp_db:
        db_path = wp_vulndb.default_path()
        wait_hours = wp_vulndb.hours_until_refresh_allowed(db_path)
        if wait_hours > 0:
            console_print(
                f"[i] The WordPress vulnerability database is fresh; Wordfence rate-limits "
                f"downloads, so try again in {wait_hours:.1f} hour(s). Database: {db_path}"
            )
            return 0
        try:
            records = wp_vulndb.update(db_path)
        except Exception as exc:
            console_print(f"WordPress vulnerability DB update failed: {type(exc).__name__}: {exc}")
            console_print("[i] The existing local database, if any, was kept.")
            return 1
        console_print(f"[+] WordPress vulnerability database updated: {records} records")
        console_print(f"[i] Source: {wp_vulndb.SOURCE}; database: {db_path}")
        return 0

    if not args.target:
        console_print("Target is required unless --update-db or --update-wp-db is used.")
        return 2

    if args.ownership_token or args.verify_ownership:
        target = normalize_target(args.target)
        if not target:
            console_print("Invalid target URL.")
            return 2
        if args.ownership_token:
            console_print(ownership.instructions(target, lang=args.lang))
            console_print(
                f"\n[i] Tokens are signed with {ownership.key_path()}; keep this file, "
                "because replacing it invalidates every token already issued."
            )
            return 0
        proof = _verify_ownership(args, target)
        if proof.verified:
            console_print(f"[+] Ownership verified for {proof.domain} via {proof.detail}.")
            return 0
        console_print(f"[!] Ownership not verified: {proof.detail}")
        console_print("[i] Run with --ownership-token for instructions.")
        return 1

    if not args.company.strip():
        console_print("[i] Empty --company value; using the default company name: Web Audit Pro.")
        args.company = "Web Audit Pro"

    if not args.yes_i_am_authorized and not _confirm_authorization(args.target, args.lang):
        console_print(
            "Refusing to scan without authorization confirmation. "
            "Use --yes-i-am-authorized for systems you are permitted to test."
        )
        return 2

    if config_path:
        console_print(f"[i] Config: {config_path}")

    target = normalize_target(args.target)
    if not target:
        console_print("Invalid target URL.")
        return 2

    try:
        configured_paths = tuple(_normalize_path_entry(value) for value in (args.paths or ()))
        configured_paths = tuple(path for path in configured_paths if path)
        file_paths = _load_paths_file(args.paths_file) if args.paths_file else ()
        selected_paths = tuple(dict.fromkeys((*file_paths, *configured_paths)))
        if args.kali_wordlist and not selected_paths:
            wordlist = _find_wordlist()
            if wordlist:
                selected_paths = _load_paths_file(wordlist, limit=500)
                console_print(f"[*] Wordlist: {wordlist} (max 500 paths)")
            else:
                console_print("[i] No system wordlist found; using the built-in safe path set.")
        if not selected_paths:
            selected_paths = Settings().paths
    except ValueError as exc:
        console_print(f"Configuration/scope error: {exc}")
        return 2

    settings = Settings(
        paths=selected_paths,
        timeout=args.timeout,
        max_size=args.max_size,
        threads=args.threads,
        output_dir=args.output_dir,
        allow_private=args.allow_private,
        verify_tls=not args.insecure_tls,
        requests_per_second=args.requests_per_second,
        scope_file=args.scope_file,
        dns_enabled=args.dns,
        tls_check_enabled=args.tls_check,
        cms_enabled=args.cms,
        scan_js=args.scan_js,
        max_js_files=args.max_js_files,
        content_scan_max_size=args.content_scan_max_size,
        company=args.company,
        theme=args.theme,
        report_lang=args.lang,
        logo_path=args.logo,
        ua_profile=args.user_agent_profile,
    )

    try:
        settings.validate()
        if settings.scope_file:
            scope = load_scope(settings.scope_file)
            if not target_in_scope(target, scope):
                raise ValueError("target is outside the supplied scope file")
        addresses = resolve_target_addresses(target)
        if not settings.allow_private:
            blocked = sorted(
                str(address) for address in addresses if is_non_public_address(address)
            )
            if blocked:
                raise ValueError(
                    "target resolves to non-public/reserved address(es): "
                    + ", ".join(blocked)
                    + "; use --allow-private only for authorized internal testing"
                )
        settings.output_dir.mkdir(parents=True, exist_ok=True)
        started = datetime.now(UTC)
        _run_output_paths(settings, target, started)
        configure_logging(
            settings.log_path,
            max_bytes=settings.log_max_bytes,
            backup_count=settings.log_backup_count,
        )
    except (OSError, ValueError) as exc:
        console_print(f"Configuration/scope error: {exc}")
        return 2

    proof: OwnershipProof | None = None
    if args.require_ownership:
        proof = _verify_ownership(args, target)
        if not proof.verified:
            console_print(
                f"Refusing to scan: ownership of {urlparse(target).hostname} is not verified. "
                f"{proof.detail} Run with --ownership-token for instructions."
            )
            return 2
        console_print(f"[+] Ownership verified for {proof.domain} via {proof.detail}.")

    logger.info("Scan started target=%s addresses=%s", target, sorted(map(str, addresses)))

    console_print(paint(f"[*] Target: {target}", "36;1"))
    console_print(paint(f"[*] Paths: {len(settings.paths)} | Threads: {settings.threads}", "36"))

    scanner = Scanner(settings=settings, proxy=args.proxy)
    targets = [target]
    if args.discover_subdomains:
        domain = urlparse(target).hostname or ""
        try:
            discovered = discover_from_crtsh(domain)
            targets = [
                normalize_target(f"{urlparse(target).scheme}://{name}") for name in discovered
            ]
            scoped_targets = [
                t
                for t in targets
                if t
                and (not settings.scope_file or target_in_scope(t, load_scope(settings.scope_file)))
            ]
            safe_targets = [target]
            for candidate in scoped_targets:
                try:
                    candidate_addresses = resolve_target_addresses(candidate)
                    if settings.allow_private or all(
                        not is_non_public_address(address) for address in candidate_addresses
                    ):
                        if candidate not in safe_targets:
                            safe_targets.append(candidate)
                except ValueError:
                    continue
            if proof is not None:
                # Only hosts the proof covers: a token file proves one host, DNS the zone.
                safe_targets = [t for t in safe_targets if proof.covers(urlparse(t).hostname or "")]
            targets = safe_targets
            if target not in targets:
                targets.insert(0, target)
            console_print(f"[*] CT discovery: {len(targets) - 1} candidate host(s) added")
        except Exception as exc:
            console_print(f"CT discovery warning: {type(exc).__name__}: {exc}")
    if args.tui:
        from .tui import run_with_progress

        results = []
        for discovered_target in targets:
            results.extend(
                run_with_progress(
                    lambda callback, target=discovered_target: scanner.scan_target(
                        target, progress_callback=callback
                    ),
                    total=len(settings.paths),
                    title=f"Scanning {discovered_target}",
                )
            )
    else:
        results = []
        for discovered_target in targets:
            results.extend(scanner.scan_target(discovered_target))
    parsed_target = urlparse(target)
    host = parsed_target.hostname or ""
    # Mail records only exist for real domains, not IP literals or names like "localhost".
    host_is_domain = "." in host and not _is_ip_literal(host)
    # Which optional checks actually completed, for the owner report. Anything not
    # recorded as "checked" is shown as unchecked rather than as passing.
    coverage = {
        "cms": "checked" if settings.cms_enabled else "not_checked",
        "js": "checked" if settings.scan_js else "not_checked",
        "email": "not_checked",
        "tls": "not_checked",
    }
    if settings.dns_enabled and host_is_domain:
        try:
            results = _attach_to_primary(results, target, dns_findings(inspect_domain(host)))
            coverage["email"] = "checked"
        except Exception as exc:
            coverage["email"] = "failed"
            console_print(f"DNS warning: {type(exc).__name__}: {exc}")
    if settings.tls_check_enabled and host and parsed_target.scheme == "https":
        if args.proxy:
            console_print("[i] TLS certificate check skipped: a proxy is configured.")
        else:
            try:
                certificate = inspect_certificate(
                    host, parsed_target.port or 443, timeout=settings.timeout
                )
                if certificate.connect_error:
                    coverage["tls"] = "failed"
                    console_print(f"TLS warning: {certificate.connect_error}")
                else:
                    coverage["tls"] = "checked"
                results = _attach_to_primary(results, target, tls_findings(certificate))
            except Exception as exc:
                coverage["tls"] = "failed"
                console_print(f"TLS warning: {type(exc).__name__}: {exc}")
    wp_db_date = None
    if settings.cms_enabled:
        results, wp_db_date = _match_wordpress_vulnerabilities(results)
    if args.ignore_rule:
        ignored = set(args.ignore_rule)
        results = [
            replace(
                result,
                findings=tuple(f for f in result.findings if f.rule_id not in ignored),
                verified_rules=tuple(rule for rule in result.verified_rules if rule not in ignored),
            )
            for result in results
        ]

    finished = datetime.now(UTC)
    with Database(settings.db_path) as db:
        scan_id = db.save_scan(
            target=target,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            results=results,
        )
        scan_history = db.load_scan_history(target)

    save_csv(results, settings.csv_path)
    if args.cms_vuln_lookup:
        from .vulndb import default_db_path, lookup_local

        vuln_db = default_db_path()
        enriched = []
        if not vuln_db.is_file():
            console_print(
                "[i] Local CMS advisory DB not found; run `web-audit --update-db` "
                "before using --cms-vuln-lookup."
            )
        for item in results:
            for finding in item.findings:
                if not finding.rule_id.startswith("cms.detected."):
                    continue
                product = finding.title.removeprefix("Possible ").removesuffix(
                    " installation detected"
                )
                version = None
                if " version " in finding.evidence:
                    version = finding.evidence.split(" version ", 1)[1].split(" (", 1)[0]
                cves = lookup_local(vuln_db, product, version)
                if cves:
                    enriched.append((product, cves))
        if enriched:
            advisory_path = settings.output_dir / f"{settings.json_path.stem}-cms-advisories.json"
            advisory_path.write_text(
                json.dumps(dict(enriched), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    save_json(target, results, settings.json_path)
    save_sarif(results, settings.sarif_path)
    lifecycle = None
    comparison_failed = False
    if args.compare:
        try:
            previous_report = load_report(args.compare)
            current_report = load_report(settings.json_path)

            diff = compare_reports(previous_report, current_report)
            save_diff(diff, settings.diff_path)

            console_print(
                f"DIFF: {settings.diff_path} | "
                f"added={diff['added_count']} removed={diff['removed_count']}"
            )

            lifecycle = summarize_lifecycle(previous_report, current_report)
            console_print(render_lifecycle_summary(lifecycle))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            console_print(f"Comparison error: {exc}")
            comparison_failed = True
    elif len(scan_history) >= 2:
        lifecycle = summarize_lifecycle_history(scan_history)
        console_print(render_lifecycle_summary(lifecycle))

    save_html(
        target,
        results,
        settings.html_path,
        company=settings.company,
        theme=settings.theme,
        logo_path=settings.logo_path,
        lifecycle=lifecycle,
    )
    action_plan_path = settings.json_path.with_name(f"{settings.json_path.stem}-actions.md")
    save_action_plan(target, results, action_plan_path, lifecycle=lifecycle)
    save_owner_report(
        target,
        results,
        settings.owner_path,
        lang=settings.report_lang,
        company=settings.company,
        logo_path=settings.logo_path,
        coverage=coverage,
        lifecycle=lifecycle,
        wp_vulns_checked_on=wp_db_date,
        ownership=proof,
    )
    if comparison_failed:
        console_print(f"HTML: {settings.html_path}")
        console_print(f"PLAN: {action_plan_path}")
        console_print(f"OWNER: {settings.owner_path}")
        return 2

    for result in results:
        _print_result(result)

    stats = summary(results)
    console_print("")
    console_print(paint(f"Scan #{scan_id} complete", "32;1"))
    console_print(
        f"URLs={stats['total']} | 2xx={stats['2xx']} | 3xx={stats['3xx']} "
        f"| 4xx={stats['4xx']} | 5xx={stats['5xx']} | errors={stats['errors']}"
    )
    console_print(
        f"Findings={stats['findings']} | high={stats['high']} | medium={stats['medium']} "
        f"| low={stats['low']} | info={stats['info']}"
    )
    console_print(f"CSV : {settings.csv_path}")
    console_print(f"HTML: {settings.html_path}")
    console_print(f"PLAN: {action_plan_path}")
    console_print(f"OWNER: {settings.owner_path}")
    console_print(f"JSON: {settings.json_path}")
    console_print(f"SARIF: {settings.sarif_path}")
    console_print(f"DB  : {settings.db_path}")
    console_print(f"LOG : {settings.log_path}")
    if args.open:
        if _open_report(settings.html_path):
            console_print(f"[*] Opened report: {settings.html_path.resolve()}")
        else:
            console_print(
                f"[i] Could not open the report automatically; file: {settings.html_path.resolve()}"
            )
    if args.cms_vuln_lookup:
        console_print(f"NVD : {settings.output_dir / 'cms-advisories.json'}")

    logger.info(
        "Scan finished target=%s results=%d findings=%d",
        target,
        len(results),
        stats["findings"],
    )
    if args.serve:
        if args.serve_host != "127.0.0.1" and not args.serve_public:
            console_print("Refusing non-local dashboard bind without --serve-public.")
            return 2
        token = args.serve_token or generate_token()
        if args.serve_host != "127.0.0.1" and not args.serve_token:
            console_print("Public dashboard binding requires --serve-token.")
            return 2
        console_print(f"Dashboard token: {token}")
        console_print(
            f"Dashboard: http://{args.serve_host}:{args.serve_port}/?access_token={token}"
        )
        run_server(settings.db_path, host=args.serve_host, port=args.serve_port, token=token)
    return 1 if _meets_threshold(results, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
