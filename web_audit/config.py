from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_PATHS = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/health",
    "/status",
    "/version",
)

CONFIG_FILES = ("web-audit.toml",)

_CONFIG_VALUE_TYPES: dict[str, tuple[type, ...]] = {
    "threads": (int,),
    "timeout": (int, float),
    "max_size": (int,),
    "requests_per_second": (int, float),
    "proxy": (str,),
    "scope_file": (str, Path),
    "output_dir": (str, Path),
    "paths": (list, tuple),
    "paths_file": (str, Path),
    "allow_private": (bool,),
    "insecure_tls": (bool,),
    "user_agent_profile": (str,),
    "dns": (bool,),
    "cms": (bool,),
    "scan_js": (bool,),
    "max_js_files": (int,),
    "content_scan_max_size": (int,),
    "discover_subdomains": (bool,),
    "cms_vuln_lookup": (bool,),
    "kali_wordlist": (bool,),
    "tui": (bool,),
    "company": (str,),
    "theme": (str,),
    "logo": (str, Path),
    "open": (bool,),
    "compare": (str, Path),
    "fail_on": (str,),
    "ignore_rule": (list, tuple),
    "serve": (bool,),
    "serve_host": (str,),
    "serve_port": (int,),
    "serve_token": (str,),
    "serve_public": (bool,),
    "nvd_timeout": (int, float),
}


@dataclass(slots=True)
class Settings:
    paths: tuple[str, ...] = field(default_factory=lambda: DEFAULT_PATHS)
    timeout: float = 5.0
    max_size: int = 1024 * 1024
    threads: int = 10
    retries: int = 2
    backoff_factor: float = 0.3
    requests_per_second: float = 2.0
    output_dir: Path = Path("reports")
    database: str = "audit_results.db"
    csv_name: str = "results.csv"
    html_name: str = "report.html"
    json_name: str = "report.json"
    sarif_name: str = "report.sarif"
    diff_name: str = "diff.json"
    log_name: str = "scanner.log"
    log_max_bytes: int = 5 * 1024 * 1024
    log_backup_count: int = 5
    verify_tls: bool = True
    user_agent: str = "Web-Audit-Pro/4.0"
    allow_private: bool = False
    scope_file: Path | None = None
    scan_js: bool = True
    max_js_files: int = 20
    content_scan_max_size: int = 512 * 1024
    dns_enabled: bool = True
    cms_enabled: bool = True
    ua_profile: str = "stable"
    company: str = "Web Audit Pro"
    theme: str = "dark"
    logo_path: Path | None = None

    def validate(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        if self.max_size <= 0:
            raise ValueError("max_size must be > 0")
        if self.threads < 1:
            raise ValueError("threads must be >= 1")
        if self.retries < 0:
            raise ValueError("retries must be >= 0")
        if self.backoff_factor < 0:
            raise ValueError("backoff_factor must be >= 0")
        if self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        if self.log_max_bytes <= 0:
            raise ValueError("log_max_bytes must be > 0")
        if self.log_backup_count < 1:
            raise ValueError("log_backup_count must be >= 1")
        if self.max_js_files < 0:
            raise ValueError("max_js_files must be >= 0")
        if self.content_scan_max_size <= 0:
            raise ValueError("content_scan_max_size must be > 0")
        if self.ua_profile not in {"stable", "browser"}:
            raise ValueError("ua_profile must be stable or browser")
        if self.theme not in {"dark", "light", "cyberpunk"}:
            raise ValueError("theme must be dark, light, or cyberpunk")
        if not self.paths:
            raise ValueError("at least one path is required")
        if any(not isinstance(path, str) or not path.strip() for path in self.paths):
            raise ValueError("paths must contain non-empty strings")
        if any("\r" in path or "\n" in path for path in self.paths):
            raise ValueError("paths must not contain CR/LF")

    @property
    def csv_path(self) -> Path:
        return self.output_dir / self.csv_name

    @property
    def html_path(self) -> Path:
        return self.output_dir / self.html_name

    @property
    def json_path(self) -> Path:
        return self.output_dir / self.json_name

    @property
    def sarif_path(self) -> Path:
        return self.output_dir / self.sarif_name

    @property
    def diff_path(self) -> Path:
        return self.output_dir / self.diff_name

    @property
    def log_path(self) -> Path:
        return self.output_dir / self.log_name

    @property
    def db_path(self) -> Path:
        return self.output_dir / self.database


def discover_config(explicit: Path | None = None) -> Path | None:
    if explicit:
        return explicit.expanduser()
    for candidate in CONFIG_FILES:
        path = Path(candidate)
        if path.is_file():
            return path
    config_home = Path.home() / ".config" / "web-audit"
    for candidate in CONFIG_FILES:
        path = config_home / candidate
        if path.is_file():
            return path
    return None


def _section_map() -> dict[str, dict[str, str]]:
    return {
        "scan": {
            "threads": "threads", "timeout": "timeout", "max_size": "max_size",
            "requests_per_second": "requests_per_second", "proxy": "proxy",
            "scope_file": "scope_file", "output_dir": "output_dir",
            "paths": "paths", "paths_file": "paths_file", "allow_private": "allow_private",
            "insecure_tls": "insecure_tls", "user_agent_profile": "user_agent_profile",
        },
        "features": {
            "dns": "dns", "cms": "cms", "scan_js": "scan_js",
            "max_js_files": "max_js_files", "content_scan_max_size": "content_scan_max_size",
            "discover_subdomains": "discover_subdomains", "cms_vuln_lookup": "cms_vuln_lookup",
            "kali_wordlist": "kali_wordlist", "tui": "tui",
        },
        "report": {
            "company": "company", "theme": "theme", "logo": "logo", "open": "open",
            "compare": "compare", "fail_on": "fail_on", "ignore_rule": "ignore_rule",
        },
        "dashboard": {
            "serve": "serve", "serve_host": "serve_host", "serve_port": "serve_port",
            "serve_token": "serve_token", "serve_public": "serve_public",
        },
        "nvd": {"nvd_timeout": "nvd_timeout"},
    }


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"could not read config file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("config root must be a TOML table")
    return data


def flatten_for_cli(data: dict[str, Any]) -> dict[str, Any]:
    mapping = _section_map()
    result: dict[str, Any] = {}
    unknown: list[str] = []
    for section, values in data.items():
        if section not in mapping or not isinstance(values, dict):
            unknown.append(section)
            continue
        for key, value in values.items():
            dest = mapping[section].get(key)
            if dest is None:
                unknown.append(f"{section}.{key}")
                continue
            result[dest] = value
    if unknown:
        raise ValueError("unknown config option(s): " + ", ".join(sorted(unknown)))
    return result


def _validate_cli_values(values: dict[str, Any]) -> None:
    for key, value in values.items():
        expected = _CONFIG_VALUE_TYPES.get(key)
        if expected is None:
            continue
        if isinstance(value, bool) and bool not in expected:
            raise ValueError(f"config option {key} has an invalid type")
        if not isinstance(value, expected):
            expected_names = ", ".join(item.__name__ for item in expected)
            raise ValueError(
                f"config option {key} must be of type {expected_names}; "
                f"got {type(value).__name__}"
            )
    if "paths" in values and any(not isinstance(item, str) for item in values["paths"]):
        raise ValueError("config option paths must contain strings")
    if "ignore_rule" in values and any(
        not isinstance(item, str) for item in values["ignore_rule"]
    ):
        raise ValueError("config option ignore_rule must contain strings")


def coerce_cli_types(namespace: Any) -> None:
    """Normalize values at the config/CLI boundary before core execution."""
    integer_fields = {"threads", "max_size", "max_js_files", "content_scan_max_size", "serve_port"}
    numeric_fields = {"timeout", "requests_per_second", "nvd_timeout"}
    boolean_fields = {
        "insecure_tls", "allow_private", "dns", "cms", "scan_js", "discover_subdomains",
        "cms_vuln_lookup", "kali_wordlist", "tui", "open", "serve", "serve_public",
        "update_db",
    }
    for key in integer_fields:
        value = getattr(namespace, key, None)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            try:
                setattr(namespace, key, int(value))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"CLI option {key} must be an integer") from exc
    for key in numeric_fields:
        value = getattr(namespace, key, None)
        if value is not None and not isinstance(value, (int, float)):
            try:
                setattr(namespace, key, float(value))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"CLI option {key} must be numeric") from exc
    for key in boolean_fields:
        value = getattr(namespace, key, None)
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"CLI option {key} must be boolean")


def apply_cli_config(namespace: Any, path: Path | None) -> Path | None:
    config_path = discover_config(path)
    if not config_path:
        return None
    values = flatten_for_cli(load_toml(config_path))
    _validate_cli_values(values)
    relative_path_fields = {"scope_file", "output_dir", "paths_file", "compare", "logo"}
    for key in relative_path_fields:
        value = values.get(key)
        if isinstance(value, str) and value and not Path(value).expanduser().is_absolute():
            values[key] = str((config_path.parent / value).resolve())
    for key, value in values.items():
        if getattr(namespace, key, None) is None:
            setattr(namespace, key, value)
    coerce_cli_types(namespace)
    namespace._config_path = config_path
    return config_path
