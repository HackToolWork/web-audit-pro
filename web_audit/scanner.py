from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .cms import findings as cms_findings, fingerprint as fingerprint_cms
from .config import Settings
from .js_audit import analyze_js, discover_script_urls
from .models import CheckResult
from .security import analyze_response
from .utils import build_url

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, settings: Settings, proxy: str | None = None) -> None:
        settings.validate()
        self.settings = settings
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self._local = threading.local()
        self._rate_lock = threading.Lock()
        self._next_request_at = 0.0

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session
        session = requests.Session()
        user_agent = self.settings.user_agent
        if self.settings.ua_profile == "browser":
            user_agent = (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/140.0 Safari/537.36"
            )
        session.headers.update({
            "User-Agent": user_agent,
            "Accept": "*/*",
        })
        retry = Retry(
            total=self.settings.retries,
            connect=self.settings.retries,
            read=self.settings.retries,
            status=self.settings.retries,
            backoff_factor=self.settings.backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=2, pool_maxsize=2)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._local.session = session
        return session

    def _pace(self) -> None:
        interval = 1.0 / self.settings.requests_per_second
        with self._rate_lock:
            now = time.monotonic()
            wait = max(0.0, self._next_request_at - now)
            if wait:
                time.sleep(wait)
                now = time.monotonic()
            self._next_request_at = max(self._next_request_at, now) + interval

    def check(self, url: str, request_target: str | None = None) -> CheckResult:
        started = time.perf_counter()
        scanned_at = datetime.now(UTC)
        size = 0
        truncated = False
        location = ""
        content = bytearray()
        discovered_urls: tuple[str, ...] = ()
        try:
            self._pace()
            with self._session().get(
                url,
                timeout=(self.settings.timeout, self.settings.timeout),
                proxies=self.proxy,
                stream=True,
                allow_redirects=False,
                verify=self.settings.verify_tls,
            ) as response:
                location = response.headers.get("Location", "")
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    remaining = self.settings.max_size - size
                    if len(chunk) > remaining:
                        size = self.settings.max_size
                        truncated = True
                        break
                    size += len(chunk)
                    if len(content) < self.settings.content_scan_max_size:
                        content.extend(
                            chunk[: self.settings.content_scan_max_size - len(content)]
                        )
                body = bytes(content)
                findings = analyze_response(
                    url=url, status=response.status_code, headers=response.headers,
                    raw_headers=getattr(response.raw, "headers", None),
                    request_target=request_target,
                )
                content_type = response.headers.get("Content-Type", "").lower()
                if body and "text/html" in content_type:
                    discovered_urls = (
                        discover_script_urls(
                            url, body, max_files=self.settings.max_js_files
                        ) if self.settings.scan_js else ()
                    )
                    matches = (
                        fingerprint_cms(url, response.headers, body)
                        if self.settings.cms_enabled else ()
                    )
                    if matches:
                        findings = tuple((*findings, *cms_findings(matches)))
                elif body and (
                    "javascript" in content_type
                    or urlparse(url).path.lower().endswith((".js", ".mjs"))
                ):
                    findings = tuple((*findings, *analyze_js(url, body)))
                return CheckResult(
                    url=url, status=response.status_code, size=size,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    scanned_at=scanned_at,
                    truncated=truncated, location=location, findings=findings,
                    discovered_urls=discovered_urls,
                )
        except requests.RequestException as exc:
            return CheckResult(
                url=url,
                status=None,
                size=size,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                scanned_at=scanned_at,
                error=f"{type(exc).__name__}: {exc}",
            )

    def scan_target(
        self,
        target: str,
        paths: Iterable[str] | None = None,
        progress_callback=None,
    ) -> list[CheckResult]:
        selected_paths = tuple(paths or self.settings.paths)
        urls = [build_url(target, path) for path in selected_paths]
        if not urls:
            return []
        results: list[CheckResult] = []
        with ThreadPoolExecutor(max_workers=min(self.settings.threads, len(urls))) as pool:
            futures = {pool.submit(self.check, url, target): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    if progress_callback:
                        progress_callback(result)
                except Exception as exc:
                    logger.exception("Unexpected scanner worker failure url=%s", url)
                    results.append(CheckResult(url=url, status=None, size=0, elapsed_ms=0.0,
                                               scanned_at=datetime.now(UTC),
                                               error=f"InternalError: {type(exc).__name__}: {exc}"))
        js_urls = tuple(dict.fromkeys(u for result in results for u in result.discovered_urls))
        if self.settings.scan_js and js_urls:
            with ThreadPoolExecutor(max_workers=min(self.settings.threads, len(js_urls))) as pool:
                futures = {pool.submit(self.check, url, target): url for url in js_urls}
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        logger.exception("Unexpected JS worker failure url=%s", url)
                        result = CheckResult(
                            url=url, status=None, size=0, elapsed_ms=0.0,
                            scanned_at=datetime.now(UTC),
                            error=f"InternalError: {type(exc).__name__}: {exc}",
                        )
                    results.append(result)
                    if progress_callback:
                        progress_callback(result)
        return sorted(results, key=lambda item: item.url)
