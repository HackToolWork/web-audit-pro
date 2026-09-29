"""Offline WordPress plugin/theme vulnerability matching (Wordfence Intelligence).

``update`` downloads the Wordfence Intelligence V3 feed once (explicit, keyed),
normalizes it and stores a compact local copy. Scans only read that copy.
Matching is conservative: a component is reported as vulnerable only when its
detected version is known and falls inside an affected range.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import requests

from .models import Finding, Severity
from .vulndb import DOCKER_ENV_FILE, _writer_lock

FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
ENV_API_KEY = "WORDFENCE_API_KEY"
ENV_DB_PATH = "WEB_AUDIT_WP_VULN_DB"
DEFAULT_DOCKER_PATH = Path("/app/reports/wp-vulndb.json")
MAX_FEED_BYTES = 512 * 1024 * 1024
STALE_AFTER_DAYS = 7
# Wordfence rate-limits the V3 feed and warns that keys which keep exceeding the
# limit may be suspended: download at most every half day, and after an HTTP 429
# make no request at all until the cooldown has passed.
MIN_REFRESH_HOURS = 12
RATE_LIMIT_COOLDOWN_HOURS = 12
SOURCE = "Wordfence Intelligence"

_RATING_SEVERITY: dict[str, Severity] = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
}
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def default_path() -> Path:
    override = os.getenv(ENV_DB_PATH, "").strip()
    if override:
        return Path(override).expanduser()
    if DOCKER_ENV_FILE.is_file():
        return DEFAULT_DOCKER_PATH
    cache_home = os.getenv("XDG_CACHE_HOME", "").strip()
    base = Path(cache_home).expanduser() if cache_home else Path.home() / ".cache"
    return base / "web-audit-pro" / "wp-vulndb.json"


def version_key(version: str) -> tuple[int, ...] | None:
    """Numeric release key; pre-release suffixes are ignored, unparseable is None."""
    match = re.match(r"\s*v?(\d+(?:\.\d+)*)", version or "")
    if not match:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


@dataclass(frozen=True, slots=True)
class VersionRange:
    from_version: str  # "*" means no lower bound
    from_inclusive: bool
    to_version: str  # "*" means no upper bound
    to_inclusive: bool

    def contains(self, version: str) -> bool | None:
        key = version_key(version)
        if key is None:
            return None
        if self.from_version != "*":
            low = version_key(self.from_version)
            if low is None:
                return None
            if key < low or (key == low and not self.from_inclusive):
                return False
        if self.to_version != "*":
            high = version_key(self.to_version)
            if high is None:
                return None
            if key > high or (key == high and not self.to_inclusive):
                return False
        return True


@dataclass(frozen=True, slots=True)
class Vulnerability:
    id: str
    title: str
    cve: str
    cvss_score: float | None
    cvss_rating: str
    ranges: tuple[VersionRange, ...]
    patched_versions: tuple[str, ...]
    reference: str
    copyright: str

    def affects(self, version: str) -> bool:
        # Unparseable bounds never count as a match: absence of proof is not a finding.
        return any(r.contains(version) is True for r in self.ranges)


def _bool(value: object) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def normalize_record(record: dict) -> list[tuple[str, str, dict]]:
    """Map one feed record to ``(kind, slug, compact vulnerability)`` entries.

    This is the only place that knows the feed's field names.
    """
    if not isinstance(record, dict) or _bool(record.get("informational")):
        return []
    cvss = record.get("cvss") if isinstance(record.get("cvss"), dict) else {}
    references = record.get("references") if isinstance(record.get("references"), list) else []
    notices = []
    copyrights = record.get("copyrights")
    if isinstance(copyrights, dict):
        for holder in copyrights.values():
            if isinstance(holder, dict) and isinstance(holder.get("notice"), str):
                notices.append(holder["notice"].strip())
    base = {
        "id": str(record.get("id", "")),
        "title": str(record.get("title", "")).strip(),
        "cve": str(record.get("cve") or ""),
        "cvss_score": cvss.get("score") if isinstance(cvss.get("score"), (int, float)) else None,
        "cvss_rating": str(cvss.get("rating") or ""),
        "reference": next((str(r) for r in references if isinstance(r, str)), ""),
        "copyright": " ".join(dict.fromkeys(n for n in notices if n)),
    }
    entries = []
    for software in record.get("software") or []:
        if not isinstance(software, dict):
            continue
        kind = str(software.get("type", "")).lower()
        slug = str(software.get("slug", "")).lower()
        affected = software.get("affected_versions")
        if kind not in {"plugin", "theme"} or not slug or not isinstance(affected, dict):
            continue
        ranges = [
            [
                str(item.get("from_version") or "*"),
                _bool(item.get("from_inclusive")),
                str(item.get("to_version") or "*"),
                _bool(item.get("to_inclusive")),
            ]
            for item in affected.values()
            if isinstance(item, dict)
        ]
        if not ranges:
            continue
        patched = software.get("patched_versions")
        entries.append(
            (
                kind,
                slug,
                {
                    **base,
                    "ranges": ranges,
                    "patched_versions": [str(v) for v in patched]
                    if isinstance(patched, list)
                    else [],
                },
            )
        )
    return entries


def normalize_feed(feed: object) -> tuple[dict[str, list[dict]], int]:
    records = feed.values() if isinstance(feed, dict) else feed if isinstance(feed, list) else []
    index: dict[str, list[dict]] = {}
    count = 0
    for record in records:
        for kind, slug, vulnerability in normalize_record(record):
            index.setdefault(f"{kind}:{slug}", []).append(vulnerability)
            count += 1
    return index, count


class RateLimitedError(RuntimeError):
    """Wordfence answered HTTP 429; retrying immediately only extends the wait."""


def _download(api_key: str, destination: Path, *, timeout: float) -> None:
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    with requests.get(FEED_URL, headers=headers, timeout=timeout, stream=True) as response:
        if response.status_code == 401:
            raise PermissionError("Wordfence rejected the API key (HTTP 401).")
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "").strip()
            raise RateLimitedError(
                "Wordfence rate limit reached (HTTP 429). "
                + (f"Retry after {retry_after} seconds. " if retry_after.isdigit() else "")
                + "Wait a few hours before trying again; every attempt counts toward the limit."
            )
        response.raise_for_status()
        size = 0
        with destination.open("wb") as file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                size += len(chunk)
                if size > MAX_FEED_BYTES:
                    raise ValueError("Wordfence feed exceeds the size limit.")
                file.write(chunk)


def _cooldown_marker(path: Path) -> Path:
    return path.with_name(path.name + ".rate-limited")


def cooldown_hours_left(path: Path) -> float:
    """Hours until another request is allowed after an HTTP 429; 0 when none is pending."""
    try:
        limited_at = float(_cooldown_marker(path).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0.0
    return max(0.0, RATE_LIMIT_COOLDOWN_HOURS - (time.time() - limited_at) / 3600)


def hours_until_refresh_allowed(path: Path) -> float:
    """Hours left before another download is worthwhile; 0 when none is stored."""
    db = load(path)
    if db is None:
        return 0.0
    return max(0.0, MIN_REFRESH_HOURS - db.age_days * 24)


def update(path: Path, *, api_key: str | None = None, timeout: float = 60.0) -> int:
    """Download, normalize and atomically replace the local database.

    The existing database is kept if anything fails or the feed yields no records.
    """
    api_key = (api_key or os.getenv(ENV_API_KEY, "")).strip()
    if not api_key:
        raise PermissionError(f"Set {ENV_API_KEY} to a Wordfence Intelligence API key.")
    wait = cooldown_hours_left(path)
    if wait > 0:
        raise RateLimitedError(
            f"Wordfence rate-limited the previous attempt; no request was sent. "
            f"Try again in {wait:.1f} hour(s) (marker: {_cooldown_marker(path)})."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=path.parent) as workdir:
        raw = Path(workdir) / "feed.json"
        try:
            _download(api_key, raw, timeout=timeout)
        except RateLimitedError:
            _cooldown_marker(path).write_text(str(time.time()), encoding="utf-8")
            raise
        with raw.open("rb") as file:
            feed = json.load(file)
        index, count = normalize_feed(feed)
        if count == 0:
            raise ValueError("The Wordfence feed contained no plugin or theme records.")
        payload = {"source": SOURCE, "updated_at": time.time(), "records": count, "index": index}
        staged = Path(workdir) / "db.json"
        staged.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        with _writer_lock(path):
            os.replace(staged, path)
    _cooldown_marker(path).unlink(missing_ok=True)
    return count


@dataclass(frozen=True, slots=True)
class LocalDatabase:
    updated_at: float
    index: dict[str, list[dict]]

    @property
    def age_days(self) -> float:
        return max(0.0, (time.time() - self.updated_at) / 86400)

    def lookup(self, kind: str, slug: str) -> list[Vulnerability]:
        return [
            Vulnerability(
                id=item["id"],
                title=item["title"],
                cve=item["cve"],
                cvss_score=item["cvss_score"],
                cvss_rating=item["cvss_rating"],
                ranges=tuple(VersionRange(*bounds) for bounds in item["ranges"]),
                patched_versions=tuple(item["patched_versions"]),
                reference=item["reference"],
                copyright=item["copyright"],
            )
            for item in self.index.get(f"{kind}:{slug}", [])
        ]


def load(path: Path) -> LocalDatabase | None:
    """Return the local database, or None when it is missing or unreadable."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        updated_at = float(payload["updated_at"])
        index = payload["index"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(index, dict):
        return None
    return LocalDatabase(updated_at, index)


def _severity(vulnerabilities: list[Vulnerability]) -> Severity:
    severities = [_RATING_SEVERITY.get(v.cvss_rating.lower(), "medium") for v in vulnerabilities]
    return max(severities, key=_SEVERITY_ORDER.__getitem__)


def _fixed_in(vulnerabilities: list[Vulnerability]) -> str:
    """Lowest version that is patched for every matched vulnerability, if known."""
    candidates = []
    for vulnerability in vulnerabilities:
        keys = [(version_key(v), v) for v in vulnerability.patched_versions]
        keys = [(k, v) for k, v in keys if k is not None]
        if not keys:
            return ""
        candidates.append(min(keys))
    return max(candidates)[1] if candidates else ""


def component_findings(
    kind: str, slug: str, version: str, db: LocalDatabase
) -> tuple[Finding, ...]:
    matched = [v for v in db.lookup(kind, slug) if v.affects(version)]
    if not matched:
        return ()
    matched.sort(key=lambda v: (-(v.cvss_score or 0.0), v.title))
    fixed_in = _fixed_in(matched)
    listed = "; ".join(
        f"{v.title}" + (f" ({v.cve}, CVSS {v.cvss_score})" if v.cve else "") for v in matched[:5]
    )
    more = f"; and {len(matched) - 5} more" if len(matched) > 5 else ""
    notices = " ".join(dict.fromkeys(v.copyright for v in matched if v.copyright))
    evidence = (
        f"WordPress {kind} {slug} version {version} matches {len(matched)} known "
        f"vulnerabilit{'y' if len(matched) == 1 else 'ies'}"
        + (f"; fixed in {fixed_in}" if fixed_in else "")
        + f": {listed}{more}. Source: {SOURCE}."
        + (f" {notices}" if notices else "")
    )
    return (
        Finding(
            rule_id=f"wordpress.vulnerable.{kind}.{slug}",
            title=f"Vulnerable WordPress {kind}: {slug} {version}",
            severity=_severity(matched),
            category="vulnerable_component",
            evidence=evidence,
            recommendation=(
                f"Update {slug} to {fixed_in} or later."
                if fixed_in
                else f"No fixed version is listed; replace or remove {slug} if possible."
            )
            + " The version was inferred from page assets; confirm it in the WordPress admin.",
            confidence="medium",
        ),
    )
