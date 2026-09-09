from __future__ import annotations

import html
import secrets
import sqlite3
from pathlib import Path


def generate_token() -> str:
    return secrets.token_urlsafe(24)


def create_app(db_path: Path, token: str):
    try:
        from fastapi import Depends, FastAPI, HTTPException, Query
        from fastapi.responses import HTMLResponse, JSONResponse
        from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Install project dependencies with: python -m pip install -r requirements.txt"
        ) from exc

    app = FastAPI(title="Web Audit Pro", docs_url=None, redoc_url=None)
    bearer = HTTPBearer(auto_error=False)

    def auth(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
        access_token: str | None = Query(None),
    ) -> None:
        supplied = credentials.credentials if credentials else access_token
        if not supplied or not secrets.compare_digest(supplied, token):
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/", response_class=HTMLResponse)
    def index(_: None = Depends(auth)) -> str:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            scans = conn.execute(
                "SELECT id,target,started_at,finished_at,result_count "
                "FROM scans ORDER BY id DESC LIMIT 100"
            ).fetchall()
            counts = conn.execute(
                "SELECT severity, COUNT(*) AS total FROM findings "
                "GROUP BY severity"
            ).fetchall()
        severity = {row["severity"]: row["total"] for row in counts}
        rows = "".join(
            f"<tr><td>{row['id']}</td><td>{html.escape(row['target'])}</td>"
            f"<td>{html.escape(row['started_at'])}</td>"
            f"<td>{row['result_count']}</td></tr>"
            for row in scans
        )
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Web Audit Pro</title>
<style>
body{{font-family:system-ui,sans-serif;margin:0;background:#0c1220;color:#eaf0ff}}
main{{max-width:1200px;margin:auto;padding:28px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
.card{{padding:18px;border:1px solid #2a3450;border-radius:12px;background:#121a2b}}
.card strong{{display:block;font-size:28px;margin-top:4px}}
table{{width:100%;border-collapse:collapse;margin-top:20px}}
th,td{{padding:10px;border-bottom:1px solid #2a3450;text-align:left}}
</style></head><body><main>
<h1>Web Audit Pro</h1>
<div class="grid">
<div class="card">High<strong>{severity.get('high', 0)}</strong></div>
<div class="card">Medium<strong>{severity.get('medium', 0)}</strong></div>
<div class="card">Low<strong>{severity.get('low', 0)}</strong></div>
<div class="card">Info<strong>{severity.get('info', 0)}</strong></div>
</div>
<table><thead><tr><th>ID</th><th>Target</th><th>Started</th><th>Results</th></tr>
</thead><tbody>{rows}</tbody></table></main></body></html>"""

    @app.get("/api/scans", response_class=JSONResponse)
    def scans(_: None = Depends(auth)) -> list[dict]:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id,target,started_at,finished_at,result_count "
                "FROM scans ORDER BY id DESC LIMIT 100"
            ).fetchall()
        return [dict(row) for row in rows]

    return app


def run_server(db_path: Path, *, host: str, port: int, token: str) -> None:
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Install project dependencies with: python -m pip install -r requirements.txt"
        ) from exc
    uvicorn.run(create_app(db_path, token), host=host, port=port, log_level="info")
