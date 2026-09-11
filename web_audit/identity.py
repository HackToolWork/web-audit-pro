from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .models import Finding


def _normalize_locator(value: str) -> str:
    value = value.strip()
    if not value:
        return ""

    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return value.lower().rstrip(".")

    hostname = parsed.hostname or ""
    scheme = parsed.scheme.lower()

    if parsed.port is not None:
        is_default_port = (scheme == "http" and parsed.port == 80) or (
            scheme == "https" and parsed.port == 443
        )
        host = hostname if is_default_port else f"{hostname}:{parsed.port}"
    else:
        host = hostname

    path = parsed.path or "/"

    return urlunsplit(
        (
            scheme,
            host,
            path,
            parsed.query,
            "",
        )
    )


@dataclass(frozen=True, slots=True)
class FindingIdentity:
    """Stable logical identity for a finding across audit observations."""

    rule_id: str
    target: str
    location: str = ""
    discriminator: str = ""

    @property
    def key(self) -> str:
        """Return a deterministic, collision-resistant serialized identity."""
        return json.dumps(
            {
                "discriminator": self.discriminator,
                "location": self.location,
                "rule_id": self.rule_id,
                "target": self.target,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def build_finding_identity(
    finding: Finding,
    *,
    target: str,
    location: str = "",
    discriminator: str = "",
) -> FindingIdentity:
    """Build the stable identity of a logical finding.

    Severity, title, evidence, recommendation, confidence, and timestamps
    intentionally do not participate in identity.
    """
    return FindingIdentity(
        rule_id=finding.rule_id.strip(),
        target=_normalize_locator(target),
        location=_normalize_locator(location),
        discriminator=discriminator.strip(),
    )
