from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse


def normalize_target(target: str) -> str | None:
    value = target.strip()
    if not value:
        return None
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.netloc or parsed.username or parsed.password:
        return None
    if parsed.fragment or parsed.params or parsed.query:
        return None
    hostname = parsed.hostname
    if not hostname or any(char.isspace() for char in hostname):
        return None
    try:
        host_ascii = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host_for_url = f"[{host_ascii}]" if ":" in host_ascii else host_ascii
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    netloc = host_for_url if port is None or default_port else f"{host_for_url}:{port}"
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path.rstrip("/"), "", "", "")) or (
        f"{parsed.scheme.lower()}://{netloc}"
    )


def build_url(base: str, path: str) -> str:
    normalized_path = path.strip() or "/"
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"
    return f"{base.rstrip('/')}{normalized_path}"


def resolve_target_addresses(target: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    parsed = urlparse(target)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("target hostname is missing")
    try:
        literal = ipaddress.ip_address(hostname)
        return {literal}
    except ValueError:
        pass
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"could not resolve target hostname: {exc}") from exc
    return {ipaddress.ip_address(info[4][0]) for info in infos}


def is_non_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not address.is_global
