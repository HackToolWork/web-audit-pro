from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


def load_scope(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"could not read scope file: {exc}") from exc
    patterns = [
        line.strip().lower() for line in lines if line.strip() and not line.lstrip().startswith("#")
    ]
    if not patterns:
        raise ValueError("scope file contains no hosts")
    return patterns


def target_in_scope(target: str, patterns: list[str]) -> bool:
    host = (urlparse(target).hostname or "").lower().rstrip(".")
    for raw in patterns:
        pattern = raw.removeprefix("*.").rstrip(".")
        if raw.startswith("*."):
            if host == pattern or host.endswith("." + pattern):
                return True
        elif host == pattern:
            return True
    return False
