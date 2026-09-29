# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

The Makefile uses an active `VIRTUAL_ENV`, otherwise the repo-local `.venv` (created by `make install-dev`). The system Python has no pytest/ruff, so call tools through `.venv/bin/`.

```bash
make install-dev                 # create/update .venv, install requirements-dev + editable package
make check                       # lint + format check + compileall + tests (mirrors CI)
.venv/bin/python -m pytest -q    # full suite (~5s)
.venv/bin/python -m pytest tests/test_lifecycle.py::test_name -q   # single test
.venv/bin/ruff check .           # lint (E, F, I, B, UP; line length 100)
.venv/bin/ruff format --check .  # CI fails on unformatted code; drop --check to apply
```

CI (`.github/workflows/ci.yml`) runs the same steps on Python 3.11–3.14, plus `bash -n install.sh`, a wheel build + `web-audit --help`, and a Docker build. Code must stay 3.11-compatible (`target-version = "py311"`).

CLI entry point: `web-audit` → `web_audit.cli:main` (also `python -m web_audit`). Real scans need `--yes-i-am-authorized`.

## Architecture

**Scan pipeline (`cli.main`)**: settings are merged with precedence CLI > TOML (`config.py`, `web-audit.toml`) > defaults → target normalized and checked for scope/private addresses (`utils`, `scope`) → `Scanner` fetches URLs with rate limiting and bounded response size → `security.analyze_response` produces `Finding`s per response, plus optional CMS (`cms`, plus WordPress plugin/theme inventory in `wordpress`), JS (`js_audit`), DNS/SPF/DMARC (`dns_audit`), TLS certificate (`tls_audit`) and CT subdomain (`subdomains`) modules. Target-level findings (DNS, TLS) are attached to the target root result via `cli._attach_to_primary` → results saved to SQLite (`database.Database`) and to CSV/JSON/SARIF/HTML/action-plan Markdown (`reports`, `sarif`) → lifecycle comparison against scan history.

**Core models (`models.py`)**: `Finding` (rule_id, severity, evidence, recommendation, confidence) and `CheckResult` (one per URL). Both are frozen slot dataclasses and form the contract between all modules. Reports serialize them to JSON dicts, and lifecycle/diffing code works on those **dicts** (reloaded reports or `Database.load_scan_history`), not on the dataclasses.

**Finding lifecycle** (the area under active development) spans several modules:
- `identity.py`: `FindingIdentity` = (rule_id, normalized target, normalized URL location, discriminator). Severity, title and evidence are deliberately excluded, so a severity change reads as "changed", not as a new finding.
- `lifecycle.py`: pure state classification (`new`, `present`, `fixed`, `changed`, `regressed`, `unverified`) across two reports or a full history.
- `lifecycle_reporting.py`: builds summaries from report dicts. A finding counts as **fixed only when its absence is positively verified**: same target, the URL was rechecked with a 2xx, non-truncated response, `verification_version == 1`, the rule is in `security.SUPPORTED_VERIFICATION_RULES`, and it appears in that result's `verified_rules`. Otherwise it is `unverified`.
- `security.verified_response_rules` produces `CheckResult.verified_rules`. When adding a rule to `SUPPORTED_VERIFICATION_RULES`, a positive check for it must also be implemented there. `verification_version = 0` means legacy/unknown coverage and must never count as verified.
- `remediation.py`: `RemediationProof`, with evidence digests for verified fixes.
- `owner_report.py` / `owner_texts.py`: plain-language owner report built on the action plan and lifecycle summary. `cli.main` passes a `coverage` dict recording which optional checks actually completed; anything missing is rendered as "not checked", never OK. Every rule ID emitted by the scanner needs an entry in `owner_texts.RULE_TEXTS` in both languages (enforced by `tests/test_owner_report.py`).
- `action_plan.py` / `action_plan_rendering.py`: group findings by rule into remediation tasks (with coverage/incomplete reasons), rendered into the HTML report and `*-actions.md`. `lifecycle_cli.py` renders the terminal summary.

This fail-closed design is intentional: damaged, missing or unknown verification data (see `database._verified_rules_from_json`) degrades to "unknown", never to "fixed". Preserve it in any change.

**Other pieces**: `vulndb.py`/`nvd.py` keep a local CVE cache, and network access happens only with `--update-db`. `ownership.py` implements DNS/file ownership proofs (`--ownership-token`, `--verify-ownership`, `--require-ownership`); `cli.main` checks it before scanning and filters discovered subdomains with `OwnershipProof.covers`. `wp_vulndb.py` does the same for WordPress plugins/themes with the Wordfence feed (`--update-wp-db`, needs `WORDFENCE_API_KEY`); `wp_vulndb.normalize_record` is the only code that knows the feed's field names, and `cli._match_wordpress_vulnerabilities` applies the local copy after scanning. Normal audits read it offline. `serve.py` is a token-protected, read-only FastAPI dashboard over the scan DB. `tui.py` is an optional `rich` progress UI. `diffing.py` produces simple report-to-report diffs.

## Conventions

- Tests never touch the network or local caches. `tests/conftest.py` stubs `cli.inspect_certificate` and points `WEB_AUDIT_WP_VULN_DB` and `WEB_AUDIT_OWNERSHIP_KEY_FILE` at temp paths for every test (override it in-test to exercise the TLS path); otherwise tests monkeypatch `scanner._session().get` with fake responses (see `tests/test_scanner.py`) or build `CheckResult`/report dicts directly. `tests/test_regression.py` and `tests/test_verification_pipeline.py` pin lifecycle edge cases.
- Report files are written via `reports._atomic_write`.
- Safety model (from CONTRIBUTING/README): GET-only, low-impact, rate-limited requests. No credential attacks, destructive requests, unrestricted crawling, takeover attempts or authorization bypasses. Changes to network behavior, scope handling, rate limiting, storage, redaction or reporting need an explanation in the PR.
- User-facing docs exist in two languages: update both `README.md` and `README.ru.md`, plus `CHANGELOG.md`.
