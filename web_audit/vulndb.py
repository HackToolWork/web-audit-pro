from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .cms import _db
from .nvd import lookup_cves

DOCKER_ENV_FILE = Path("/.dockerenv")
ENV_VULN_DB = "WEB_AUDIT_VULN_DB"
DEFAULT_DOCKER_VULN_DB = Path("/app/reports/vulndb.sqlite3")
_LOCK_SUFFIX = ".lock"
_LOCK_TIMEOUT = 30.0


def default_db_path() -> Path:
    """Return the persistent local advisory DB path for the current runtime."""
    override = os.getenv(ENV_VULN_DB, "").strip()
    if override:
        return Path(override).expanduser()
    if DOCKER_ENV_FILE.is_file():
        return DEFAULT_DOCKER_VULN_DB
    cache_home = os.getenv("XDG_CACHE_HOME", "").strip()
    base = Path(cache_home).expanduser() if cache_home else Path.home() / ".cache"
    return base / "web-audit-pro" / "vulndb.sqlite3"


SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    product TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    version_hint TEXT NOT NULL,
    description TEXT NOT NULL,
    published TEXT NOT NULL,
    source TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY(product, cve_id, version_hint)
)
"""


def init_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=30.0) as conn:
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        conn.commit()


def lookup_local(path: Path, product: str, version: str | None) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    uri = path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA query_only = ON")
        rows = conn.execute(
            "SELECT cve_id, description, published FROM advisories "
            "WHERE lower(product)=lower(?) AND (version_hint='' OR version_hint=?) "
            "ORDER BY published DESC",
            (product, version or ""),
        ).fetchall()
    return [{"id": row[0], "description": row[1], "published": row[2]} for row in rows]


@contextmanager
def _writer_lock(path: Path):
    lock_path = path.with_name(path.name + _LOCK_SUFFIX)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+")
    deadline = time.monotonic() + _LOCK_TIMEOUT
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise TimeoutError("timed out waiting for vulnerability DB lock") from None
                time.sleep(0.25)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def update_database(path: Path, *, timeout: float = 12.0) -> tuple[int, int]:
    products = sorted({str(item["product"]) for item in _db() if item.get("product")})
    downloaded: list[tuple[str, list[dict[str, str]]]] = []
    failed = 0
    for product in products:
        try:
            downloaded.append((product, lookup_cves(product, None, timeout=timeout)))
        except Exception:
            failed += 1

    updated = 0
    with _writer_lock(path):
        init_db(path)
        with sqlite3.connect(path, timeout=30.0) as conn:
            conn.execute("PRAGMA busy_timeout = 30000")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            for product, rows in downloaded:
                for row in rows:
                    conn.execute(
                        "INSERT OR REPLACE INTO advisories "
                        "(product,cve_id,version_hint,description,published,source,updated_at) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (product, row["id"], "", row["description"], row["published"], "NVD", now),
                    )
                    updated += 1
            conn.commit()
    return updated, failed


def export_metadata(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"path": str(path), "records": 0}
    with sqlite3.connect(path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        latest = conn.execute("SELECT MAX(updated_at) FROM advisories").fetchone()[0]
    return {"path": str(path), "records": int(count), "updated_at": latest}
