## Licensing review

The public release license is Apache-2.0. The repository contains the full canonical license text in `LICENSE`, and package metadata declares `Apache-2.0`. Historical release notes are preserved as historical records.

# Web Audit Pro 5.0.0 Audit Report

## Release scope

This release focuses on deterministic configuration, dependency reproducibility, and
offline CMS advisory enrichment while preserving the existing low-impact scan model.

## Key changes

- Added TOML configuration with explicit precedence: CLI > config > built-in defaults.
- Added strict config validation and config-relative path resolution.
- Pinned direct runtime, development, and build dependencies to exact versions.
- Added `web-audit --update-db` to refresh a local CMS advisory cache from NVD.
- `--cms-vuln-lookup` reads only the local advisory cache during a normal scan.
- Added CLI controls for JavaScript scanning and JS file limits that were previously only
  available through internal settings.
- Extended CI coverage to Python 3.14.
- Added regression coverage for config parsing, precedence, offline advisory lookup, and
  dependency pinning.

## Safety model

The scanner remains GET-only, requires explicit authorization acknowledgement, blocks
non-public/reserved destinations by default, supports independent scope files, bounds
response reads, and applies a global request-rate limiter. CVE data refresh is an
explicit maintenance action rather than a hidden network side effect during scanning.

## Verification

- `pytest -q`: 106 passed in the current source environment.
- `python -m compileall -q web_audit tests`: passed.
- Release-tree imports and CLI metadata checks: passed.
- TOML parsing/config validation tests: passed.
- Offline CMS advisory lookup tests: passed.
- Release archive hygiene and ZIP integrity: verified.

The current execution environment does not contain Ruff, Hatchling, or the Docker CLI, and
has no package-index network access. Those external quality gates remain configured in GitHub
Actions and are not claimed as locally executed here.


## Release 5.0.0 reliability baseline

- NVD `Retry-After` accepts both delay-seconds and HTTP-date formats with a hard upper bound, preventing unbounded sleeps.
- Vulnerability DB updates perform network fetches before taking the SQLite write lock, then commit results in one WAL transaction.
- Local advisory lookups open SQLite in read-only mode.
- Default JSON, SARIF, HTML, CSV, log, and diff filenames include a unique per-run identifier to prevent concurrent overwrite.
