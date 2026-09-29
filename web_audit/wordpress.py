"""Passive WordPress plugin and theme inventory from already-fetched HTML.

Components are read from asset references such as
``/wp-content/plugins/<slug>/style.css?ver=1.2.3``; no extra requests are made.
Versions are conservative: WordPress appends its own core version to assets
enqueued without one, and many sites use timestamps for cache busting, so
anything ambiguous is reported as an unknown version rather than guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding

MAX_COMPONENTS = 60

_ASSET_RE = re.compile(r"/wp-content/(plugins|themes)/([A-Za-z0-9_-]{1,100})/([^\"'\s<>)]*)")
_VER_RE = re.compile(r"(?:\?|&|&amp;|&#0?38;)ver=([^&\"'\s#<>]+)", re.I)
_VERSION_RE = re.compile(r"\d{1,4}(?:\.\d{1,5}){1,3}")
_EVIDENCE_RE = re.compile(
    r"^WordPress (plugin|theme) ([a-z0-9_-]+) (?:version (\S+)|with unknown version) "
)


@dataclass(frozen=True, slots=True)
class Component:
    kind: str  # "plugin" | "theme"
    slug: str
    version: str | None
    asset: str


def detect_components(html: str, *, core_version: str | None = None) -> tuple[Component, ...]:
    versions: dict[tuple[str, str], set[str | None]] = {}
    assets: dict[tuple[str, str], str] = {}
    for match in _ASSET_RE.finditer(html):
        kind = match.group(1).lower().removesuffix("s")
        key = (kind, match.group(2).lower())
        if key not in versions and len(versions) >= MAX_COMPONENTS:
            continue
        assets.setdefault(key, match.group(0)[:200])
        version_match = _VER_RE.search(match.group(3))
        version = version_match.group(1) if version_match else None
        if version is not None and (not _VERSION_RE.fullmatch(version) or version == core_version):
            version = None
        versions.setdefault(key, set()).add(version)

    components = []
    for (kind, slug), seen in sorted(versions.items()):
        known = seen - {None}
        # Conflicting versions for one component are ambiguous, not a choice to make.
        version = next(iter(known)) if len(known) == 1 else None
        components.append(Component(kind, slug, version, assets[(kind, slug)]))
    return tuple(components)


def findings(components: tuple[Component, ...]) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            rule_id=f"wordpress.{component.kind}.{component.slug}",
            title=f"WordPress {component.kind} detected: {component.slug}",
            severity="info",
            category="technology",
            evidence=(
                f"WordPress {component.kind} {component.slug} "
                + (
                    f"version {component.version} "
                    if component.version
                    else "with unknown version "
                )
                + f"(asset {component.asset})."
            ),
            recommendation=(
                f"Keep this {component.kind} updated or remove it if unused, and check the "
                "vendor changelog and WordPress vulnerability databases for this version. "
                "Asset versions are a hint and may differ from the installed version."
            ),
            confidence="medium",
        )
        for component in components
    )


def parse_evidence(evidence: str) -> tuple[str, str, str | None] | None:
    """Recover ``(kind, slug, version)`` from evidence written by :func:`findings`."""
    match = _EVIDENCE_RE.match(evidence)
    if not match:
        return None
    return match.group(1), match.group(2), match.group(3)
