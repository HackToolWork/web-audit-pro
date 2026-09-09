from __future__ import annotations

import re
from urllib.parse import quote

import requests


_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$", re.I)


def discover_from_crtsh(domain: str, *, timeout: float = 10.0, limit: int = 200) -> tuple[str, ...]:
    if not _DOMAIN_RE.fullmatch(domain) or "." not in domain:
        raise ValueError("subdomain discovery requires a DNS domain name")
    url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": "Web-Audit-Pro-CT/1.0", "Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()
    names: set[str] = set()
    suffix = domain.lower().rstrip(".")
    for row in payload if isinstance(payload, list) else []:
        for raw in str(row.get("name_value", "")).splitlines():
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            if name == suffix or name.endswith("." + suffix):
                names.add(name)
    return tuple(sorted(names)[:limit])
