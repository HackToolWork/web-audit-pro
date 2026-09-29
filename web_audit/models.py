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

    def __post_init__(self) -> None:
        # Findings are persisted and rendered as text; catch malformed values (for
        # example a stray trailing comma creating a tuple) where they are created.
        for name in ("rule_id", "title", "severity", "category", "evidence", "recommendation"):
            if not isinstance(getattr(self, name), str):
                raise TypeError(
                    f"Finding.{name} must be str, got {type(getattr(self, name)).__name__}"
                )
        if self.severity not in {"info", "low", "medium", "high"}:
            raise ValueError(f"unknown severity: {self.severity!r}")
        if self.confidence not in {"high", "medium", "low"}:
            raise ValueError(f"unknown confidence: {self.confidence!r}")


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
    # Positive per-rule checks used for conservative absence verification.
    # Version zero denotes legacy/unknown coverage, never a successful recheck.
    verified_rules: tuple[str, ...] = field(default_factory=tuple)
    verification_version: int = 0

    @property
    def is_http_response(self) -> bool:
        return self.status is not None
