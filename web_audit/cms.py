from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files

from .models import Confidence, Finding


@dataclass(frozen=True, slots=True)
class CMSMatch:
    product: str
    version: str | None
    evidence: str
    confidence: Confidence
    advisory_url: str = ""


_VERSION_PATTERNS = {
    "WordPress": (
        re.compile(
            r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\s+([^\"']+)",
            re.I,
        ),
        re.compile(r"/wp-includes/[^\"']+?ver=([0-9][\w.\-]+)", re.I),
    ),
    "Drupal": (
        re.compile(r"<meta[^>]+name=[\"']Generator[\"'][^>]+content=[\"']Drupal\s+([^\"']+)", re.I),
        re.compile(r"Drupal\s+([0-9][\w.\-]+)", re.I),
    ),
    "Joomla": (
        re.compile(
            r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla!\s*-?\s*([^\"']*)",
            re.I,
        ),
    ),
    "Magento": (re.compile(r"Magento(?:\s|/)([0-9][\w.\-]+)", re.I),),
    "PrestaShop": (
        re.compile(
            r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']PrestaShop\s+([^\"']+)",
            re.I,
        ),
    ),
    "Ghost": (
        re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Ghost\s+([^\"']+)", re.I),
    ),
}


def _db() -> list[dict]:
    resource = files("web_audit.data").joinpath("cms_fingerprints.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def fingerprint(url: str, headers: Mapping[str, str], body: bytes) -> tuple[CMSMatch, ...]:
    text = body.decode("utf-8", errors="replace")
    lowered = text.lower()
    matches: list[CMSMatch] = []
    for entry in _db():
        product = entry["product"]
        score = 0
        evidence: list[str] = []
        for marker in entry.get("body_markers", []):
            if marker.lower() in lowered:
                score += 1
                evidence.append(f"body:{marker}")
        for header_name, marker in entry.get("header_markers", {}).items():
            value = next((v for k, v in headers.items() if k.lower() == header_name.lower()), "")
            if marker.lower() in value.lower():
                score += 2
                evidence.append(f"header:{header_name}={value}")
        for path_marker in entry.get("path_markers", []):
            if path_marker.lower() in url.lower() or path_marker.lower() in lowered:
                score += 1
                evidence.append(f"path:{path_marker}")
        if score < int(entry.get("min_score", 1)):
            continue
        version: str | None = None
        for pattern in _VERSION_PATTERNS.get(product, ()):
            match = pattern.search(text)
            if match:
                version = match.group(1).strip() or None
                break
        confidence: Confidence = "high" if score >= 3 else "medium"
        matches.append(
            CMSMatch(
                product,
                version,
                "; ".join(evidence[:3]),
                confidence,
                entry.get("advisory_url", ""),
            )
        )
    return tuple(matches)


def findings(matches: tuple[CMSMatch, ...]) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            rule_id=f"cms.detected.{match.product.lower().replace(' ', '_')}",
            title=f"Possible {match.product} installation detected",
            severity="info",
            category="technology",
            evidence=(
                f"Detected {match.product}"
                + (f" version {match.version}" if match.version else "")
                + f" ({match.evidence})."
            ),
            recommendation=(
                "Verify the detected product and exact installed version, then review "
                "the vendor security advisories and supported release policy."
                + (f" Advisory source: {match.advisory_url}" if match.advisory_url else "")
            ),
            confidence=match.confidence,
        )
        for match in matches
    )
