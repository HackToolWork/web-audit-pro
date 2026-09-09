from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from .models import Finding

_SECRET_PATTERNS = (
    (
        "secret.aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS access key identifier",
    ),
    (
        "secret.google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{30,45}\b"),
        "Google API key",
    ),
    (
        "secret.yandex_api_key",
        re.compile(r"\bAQVN[0-9A-Za-z_-]{20,80}\b"),
        "Yandex API key-like token",
    ),
    (
        "secret.jwt",
        re.compile(
            r"\beyJ[a-zA-Z0-9_-]{8,}\."
            r"[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"
        ),
        "JWT-like token",
    ),
    (
        "secret.generic_token",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key)\b"
            r"\s*[:=]\s*[\"\'][^\"\']{12,}[\"\']"
        ),
        "generic credential-like assignment",
    ),
    (
        "secret.private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "private key material",
    ),
)
_SCRIPT_RE = re.compile(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", re.I)


def discover_script_urls(page_url: str, body: bytes, *, max_files: int = 20) -> tuple[str, ...]:
    text = body.decode("utf-8", errors="replace")
    urls: list[str] = []
    host = urlparse(page_url).hostname
    for raw in _SCRIPT_RE.findall(text):
        candidate = urljoin(page_url, raw.strip())
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        if host and parsed.hostname.lower() != host.lower():
            continue
        if candidate not in urls:
            urls.append(candidate)
        if len(urls) >= max_files:
            break
    return tuple(urls)


def analyze_js(url: str, body: bytes) -> tuple[Finding, ...]:
    text = body.decode("utf-8", errors="replace")
    findings: list[Finding] = []
    for rule_id, pattern, label in _SECRET_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        start = max(0, match.start() - 24)
        end = min(len(text), match.end() + 24)
        snippet = text[start:end].replace("\n", " ").replace("\r", " ")
        redacted = re.sub(
            r"(?i)(apikey|api-key|token|secret|password)\s*[:=]\s*[\"']"
            r"([^\"']+)[\"']",
            r"\1=***REDACTED***",
            snippet,
        )
        redacted = redacted[:180]
        findings.append(
            Finding(
                rule_id=rule_id,
                title=f"Potential {label} exposed in JavaScript",
                severity="high" if "private_key" in rule_id else "medium",
                category="client_secrets",
                evidence=f"Matched in {url}: {redacted}",
                recommendation=(
                    "Treat the value as exposed, verify whether it is actually privileged, "
                    "rotate/revoke it if sensitive, and move secrets to a server-side secret store."
                ),
                confidence="medium",
            )
        )
    return tuple(findings)
