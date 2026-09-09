## 5.0.0 — Licensing and release hygiene

- License: Apache-2.0.
- SPDX identifier: Apache-2.0.
- Package metadata and documentation are aligned with the repository license.

# Web Audit Pro 5.0.0

## Release highlights

### Persistent configuration

Use `web-audit.toml` for repeatable scan, feature, report, dashboard, and NVD settings.
Command-line arguments always override configuration values.

### Reproducible dependencies

Runtime, development, and build dependencies are pinned to exact versions in both
`requirements*.txt` and `pyproject.toml`.

### Offline CMS advisory enrichment

`web-audit --update-db` explicitly refreshes a local SQLite advisory database from NVD.
Normal scans with `--cms-vuln-lookup` read that local cache and do not contact NVD.

### Persistent advisory DB in Docker

Docker uses `/app/reports/vulndb.sqlite3` by default (also configurable with `WEB_AUDIT_VULN_DB`), so mounting `/app/reports` preserves advisory data between container runs.

### Developer workflow

`make test`, `make lint`, `make compile`, and `make check` continue to use an active
`VIRTUAL_ENV` when present, otherwise they bootstrap the repository `.venv`.
The CI matrix now includes Python 3.14.

## Installation

```bash
sudo ./install.sh
web-audit --version
```

For contributors:

```bash
make install-dev
make check
```

## 5.0.0

Reliability release: bounded NVD rate-limit recovery, read-only local advisory lookups, lock-safe advisory DB updates, and collision-safe per-run reports/logs for concurrent containers and CI jobs.
