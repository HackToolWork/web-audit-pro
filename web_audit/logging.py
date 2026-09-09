from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import sys
import threading
from pathlib import Path

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_CONSOLE_LOCK = threading.Lock()


def configure_logging(
    path: Path, *, max_bytes: int = 5 * 1024 * 1024, backup_count: int = 5
) -> None:
    """Configure bounded file logging safely for concurrent scanner workers."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be > 0")
    if backup_count < 1:
        raise ValueError("backup_count must be >= 1")

    path.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    root.addHandler(handler)


def paint(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def console_print(text: str) -> None:
    """Serialize writes so future worker-side status output cannot interleave."""
    with _CONSOLE_LOCK:
        print(text)


def info(text: str) -> None:
    console_print(paint(text, "36"))


def ok(text: str) -> None:
    console_print(paint(text, "32"))


def warn(text: str) -> None:
    console_print(paint(text, "33"))


def err(text: str) -> None:
    console_print(paint(text, "31"))
