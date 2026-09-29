"""Domain ownership verification before scanning.

A site owner proves control by publishing a token either as a DNS TXT record
(which covers the domain and its subdomains) or in a file at
``/.well-known/webaudit-verify.txt`` (which covers that exact host only).
Tokens are an HMAC of the domain under a local secret, so they cannot be
guessed or reused for another domain.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import dns.resolver
import requests

from .dns_audit import _parent_candidates, _resolve
from .utils import is_non_public_address, resolve_target_addresses

ENV_KEY_FILE = "WEB_AUDIT_OWNERSHIP_KEY_FILE"
TOKEN_PREFIX = "webaudit-verify="
DNS_LABEL = "_webaudit"
FILE_PATH = "/.well-known/webaudit-verify.txt"
MAX_FILE_BYTES = 4096


def key_path() -> Path:
    override = os.getenv(ENV_KEY_FILE, "").strip()
    if override:
        return Path(override).expanduser()
    config_home = os.getenv("XDG_CONFIG_HOME", "").strip()
    base = Path(config_home).expanduser() if config_home else Path.home() / ".config"
    return base / "web-audit-pro" / "ownership.key"


def _secret() -> bytes:
    """Load the local signing secret, creating it (mode 0600) on first use."""
    path = key_path()
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        value = None
    if value is not None:
        if len(value) < 32:
            # Never replace silently: a new key invalidates every token already issued.
            raise ValueError(f"ownership key file {path} is invalid; restore it or delete it")
        return value.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(32)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        file.write(value + "\n")
    return value.encode()


def normalize_domain(value: str) -> str:
    host = urlsplit(value).hostname if "://" in value else value
    return (host or "").strip().rstrip(".").lower()


def token_for(domain: str) -> str:
    digest = hmac.new(_secret(), normalize_domain(domain).encode(), hashlib.sha256).hexdigest()
    return f"{TOKEN_PREFIX}{digest[:32]}"


@dataclass(frozen=True, slots=True)
class OwnershipProof:
    verified: bool
    method: str = ""  # "dns" | "file"
    domain: str = ""  # domain or host the proof was found for
    detail: str = ""

    def covers(self, host: str) -> bool:
        host = normalize_domain(host)
        if not self.verified:
            return False
        if self.method == "file":
            return host == self.domain
        return host == self.domain or host.endswith("." + self.domain)


_INSTRUCTIONS = {
    "en": {
        "title": "Ownership verification for {host}",
        "dns": "Option 1: DNS TXT record (in your domain registrar or DNS hosting panel)",
        "name": "Name",
        "or": "or",
        "type": "Type",
        "value": "Value",
        "zone": "Covers this domain and all its subdomains.",
        "host": "Covers this host only.",
        "file": "Option 2: a file on the site",
        "url": "URL",
        "content": "Content",
        "delay": "DNS changes can take up to a few hours to appear.",
    },
    "ru": {
        "title": "Подтверждение владения сайтом {host}",
        "dns": "Способ 1: TXT-запись в DNS (в панели регистратора домена или DNS-хостинга)",
        "name": "Имя",
        "or": "или",
        "type": "Тип",
        "value": "Значение",
        "zone": "Подтверждает домен и все его поддомены.",
        "host": "Подтверждает только этот адрес.",
        "file": "Способ 2: файл на сайте",
        "url": "Адрес",
        "content": "Содержимое",
        "delay": "Изменения в DNS могут появиться в течение нескольких часов.",
    },
}


def instructions(target: str, lang: str = "en") -> str:
    """Plain instructions to forward to a site owner."""
    text = _INSTRUCTIONS[lang]
    host = normalize_domain(target)
    candidates = _parent_candidates(host)
    lines = [text["title"].format(host=host), "", text["dns"]]
    for domain in (candidates[-1], host) if len(candidates) > 1 else (host,):
        lines += [
            f"  {text['name']}: {domain}  ({text['or']} {DNS_LABEL}.{domain})",
            f"  {text['type']}: TXT",
            f"  {text['value']}: {token_for(domain)}",
            f"  {text['zone'] if domain != host else text['host']}",
            "",
        ]
    lines += [
        text["file"],
        f"  {text['url']}: https://{host}{FILE_PATH}",
        f"  {text['content']}: {token_for(host)}",
        f"  {text['host']}",
        "",
        text["delay"],
    ]
    return "\n".join(lines)


def verify_dns(host: str) -> OwnershipProof:
    resolver = dns.resolver.Resolver()
    for domain in _parent_candidates(normalize_domain(host)):
        expected = token_for(domain)
        for name in (domain, f"{DNS_LABEL}.{domain}"):
            records = _resolve(resolver, name, "TXT")
            if any(record.strip().strip('"').strip() == expected for record in records):
                return OwnershipProof(True, "dns", domain, f"TXT record at {name}")
    return OwnershipProof(False, detail="No matching TXT record was found.")


def verify_file(
    target: str,
    *,
    timeout: float = 5.0,
    verify_tls: bool = True,
    proxies: dict[str, str] | None = None,
    allow_private: bool = False,
) -> OwnershipProof:
    parts = urlsplit(target if "://" in target else f"https://{target}")
    host = normalize_domain(parts.hostname or "")
    if not host:
        return OwnershipProof(False, detail="The target has no host name.")
    if not allow_private:
        try:
            addresses = resolve_target_addresses(f"{parts.scheme}://{parts.netloc}")
        except ValueError as exc:
            return OwnershipProof(False, detail=f"Host could not be resolved: {exc}")
        if any(is_non_public_address(address) for address in addresses):
            return OwnershipProof(False, detail="Host resolves to a non-public address.")
    url = f"{parts.scheme}://{parts.netloc}{FILE_PATH}"
    try:
        with requests.get(
            url,
            timeout=timeout,
            verify=verify_tls,
            proxies=proxies,
            allow_redirects=False,  # a redirect could point at a file on another site
            stream=True,
        ) as response:
            if response.status_code != 200:
                return OwnershipProof(False, detail=f"{url} returned HTTP {response.status_code}.")
            body = b""
            for chunk in response.iter_content(chunk_size=1024):
                body += chunk
                if len(body) >= MAX_FILE_BYTES:
                    break
    except requests.RequestException as exc:
        return OwnershipProof(False, detail=f"{url} could not be fetched: {type(exc).__name__}")
    content = body[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    if token_for(host) in {line.strip() for line in content.splitlines()}:
        return OwnershipProof(True, "file", host, f"token file at {url}")
    return OwnershipProof(False, detail=f"{url} does not contain the expected token.")


def verify(target: str, **file_options) -> OwnershipProof:
    """Try DNS first (covers subdomains), then the token file."""
    proof = verify_dns(normalize_domain(target))
    if proof.verified:
        return proof
    file_proof = verify_file(target, **file_options)
    if file_proof.verified:
        return file_proof
    return OwnershipProof(False, detail=f"{proof.detail} {file_proof.detail}")
