from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Severity = Literal["info", "low", "medium", "high"]
Confidence = Literal["high", "medium", "low"]


@dataclass(slots=True, frozen=True)
class Finding:
    """A deterministic, low-impact security observation tied to a response."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    evidence: str
    recommendation: str
    confidence: Confidence = "high"


@dataclass(slots=True, frozen=True)
class CheckResult:
    url: str
    status: int | None
    size: int
    elapsed_ms: float
    scanned_at: datetime
    truncated: bool = False
    location: str = ""
    error: str = ""
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    discovered_urls: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_http_response(self) -> bool:
        return self.status is not None
