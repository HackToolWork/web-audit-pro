from __future__ import annotations

import email.utils
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PUBLIC_INTERVAL = 6.0
_KEYED_INTERVAL = 0.75
_MAX_RETRY_AFTER = 300.0
_RATE_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0


def _nvd_api_key() -> str | None:
    value = os.getenv("NVD_API_KEY", "").strip()
    return value or None


def _wait_for_rate_limit(interval: float) -> None:
    global _NEXT_REQUEST_AT
    with _RATE_LOCK:
        now = time.monotonic()
        wait = max(0.0, _NEXT_REQUEST_AT - now)
        if wait:
            time.sleep(wait)
            now = time.monotonic()
        _NEXT_REQUEST_AT = max(_NEXT_REQUEST_AT, now) + interval


def _retry_after(response: requests.Response) -> float:
    """Return a bounded Retry-After delay from seconds or an HTTP date."""
    value = response.headers.get("Retry-After", "").strip()
    if not value:
        return _PUBLIC_INTERVAL
    try:
        delay = float(value)
    except ValueError:
        try:
            retry_at = email.utils.parsedate_to_datetime(value).timestamp()
        except (TypeError, ValueError, OverflowError):
            return _PUBLIC_INTERVAL
        delay = retry_at - time.time()
    return min(_MAX_RETRY_AFTER, max(0.0, delay))


def lookup_cves(
    product: str,
    version: str | None,
    *,
    timeout: float = 12.0,
    limit: int = 20,
    max_attempts: int = 3,
) -> list[dict[str, str]]:
    if not product.strip():
        raise ValueError("product must not be empty")
    if timeout <= 0:
        raise ValueError("timeout must be > 0")
    if limit < 1:
        raise ValueError("limit must be >= 1")
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    query = product if not version else f"{product} {version}"
    api_key = _nvd_api_key()
    headers = {
        "Accept": "application/json",
        "User-Agent": "Web-Audit-Pro-NVD/5.0",
    }
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(max_attempts):
        _wait_for_rate_limit(_KEYED_INTERVAL if api_key else _PUBLIC_INTERVAL)
        try:
            response = requests.get(
                NVD_URL,
                params={"keywordSearch": query, "resultsPerPage": min(limit, 20)},
                headers=headers,
                timeout=timeout,
            )
        except requests.RequestException:
            if attempt + 1 == max_attempts:
                raise
            time.sleep(min(2.0 * (2**attempt), 10.0))
            continue

        if response.status_code == 429:
            if attempt + 1 == max_attempts:
                raise requests.HTTPError(
                    "NVD rate limit persisted after retry budget", response=response
                )
            time.sleep(_retry_after(response))
            continue

        response.raise_for_status()
        payload = response.json()
        rows: list[dict[str, str]] = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = str(cve.get("id", ""))
            descriptions = cve.get("descriptions", [])
            description = next(
                (x.get("value", "") for x in descriptions if x.get("lang") == "en"),
                "",
            )
            published = str(cve.get("published", ""))
            if cve_id:
                rows.append(
                    {
                        "id": cve_id,
                        "description": description[:500],
                        "published": published,
                    }
                )
        return rows
    raise RuntimeError("NVD lookup exhausted retries")


def cache_lookup(
    path: Path,
    product: str,
    version: str | None,
    *,
    timeout: float = 12.0,
    ttl: float = 86400.0,
) -> list[dict[str, str]]:
    if ttl < 0:
        raise ValueError("ttl must be >= 0")
    key = f"{product}|{version or ''}"
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=30.0) as conn:
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS nvd_cache ("
            "cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, cached_at REAL NOT NULL)"
        )
        row = conn.execute(
            "SELECT payload, cached_at FROM nvd_cache WHERE cache_key=?", (key,)
        ).fetchone()
        if row and time.time() - float(row[1]) < ttl:
            return json.loads(row[0])

        rows = lookup_cves(product, version, timeout=timeout)
        conn.execute(
            "INSERT OR REPLACE INTO nvd_cache(cache_key,payload,cached_at) VALUES (?,?,?)",
            (key, json.dumps(rows), time.time()),
        )
        conn.commit()
        return rows
