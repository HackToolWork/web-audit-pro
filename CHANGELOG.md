# Changelog

## Unreleased

- Terminal messages are available in English and Russian and follow the report
  language (system locale or `--lang`); Russian runs show plain-language finding
  titles. English output is unchanged.
- Scans end with a colour-coded status line from the owner report and the
  owner report path. On an interactive desktop the owner report opens
  automatically; `--open`/`--no-open` override this. `--open` now opens the
  owner report instead of the technical HTML report.
- Fixed a crash when saving any scan that detected a CMS: the CMS finding's
  recommendation was a tuple, which SQLite cannot store (since 5.0.0).
  `Finding` now validates its field types, severity and confidence on creation.
- Fixed false Magento and PrestaShop detections on WordPress sites (`image/`
  matched `mage/`, and `/wp-content/themes/` matched `/themes/`); both now need
  two platform-specific markers.
- Fixed CMS detections triggered by merely naming a platform in page text
  ("WordPress", "Joomla!", "ghost.org"); fingerprints now rely on asset paths,
  markup attributes and the generator meta tag.
- SPF/DMARC checks are skipped for single-label hosts such as `localhost`.
- The owner report no longer shows "no serious issues" when WordPress plugins
  were not checked against a vulnerability database or a TLS/email check
  failed: the status becomes "incomplete" with an explanation, and the plugin
  notice stays visible with any status. Findings confirmed by at least one
  high-confidence observation are no longer marked as needing validation.
- The owner report language now follows the system locale (`LC_ALL`,
  `LC_MESSAGES`, `LANG`) unless `--lang` or `lang` in the config is set.
- Without `--yes-i-am-authorized`, interactive runs ask for confirmation
  (`y`/`да`, default no); non-interactive runs still refuse to scan.
- Added a local WordPress test lab (`lab/wordpress/start.sh`) with a
  deliberately outdated plugin, bound to 127.0.0.1, for end-to-end testing.
- Added domain ownership verification. `--ownership-token` prints DNS TXT and
  `/.well-known/webaudit-verify.txt` instructions (English or Russian via
  `--lang`), `--verify-ownership` checks them, and `--require-ownership` (or
  `require_ownership = true`) refuses unverified targets and skips discovered
  subdomains the proof does not cover. Tokens are HMACs under a local secret; the
  file check never follows redirects or fetches non-public addresses. The owner
  report states how ownership was verified.
- Added offline WordPress plugin and theme vulnerability checks against the
  Wordfence Intelligence feed. `web-audit --update-wp-db` downloads it with
  `WORDFENCE_API_KEY`; audits then use the local copy automatically and warn when
  it is older than seven days. Only unambiguously detected versions inside an
  affected range produce `wordpress.vulnerable.<kind>.<slug>` findings, whose
  severity follows the highest CVSS rating. Failed updates keep the existing
  database. To protect the API key from suspension, `--update-wp-db` makes no
  request while the local copy is under 12 hours old or for 12 hours after an
  HTTP 429 response. Reports credit the source and include the required copyright notices.
- Added a passive WordPress plugin and theme inventory from `/wp-content/`
  asset references in already-fetched HTML (`wordpress.plugin.<slug>` and
  `wordpress.theme.<slug>` info findings). Versions are reported only when
  unambiguous: the WordPress core version appended to unversioned assets,
  cache-busting timestamps, and conflicting versions become unknown. The owner
  report lists all components in one table.
- Fixed a false "SPF record was not found" for web hosts such as
  `www.example.com`: SPF and MX now fall back to the parent domain like DMARC,
  so DMARC severity also accounts for the parent domain's mail servers.
- Added a plain-language owner report (`owner-report-*.html`) for non-technical
  site owners: traffic-light status, per-area coverage, changes since the last
  scan, and "what it means / what to do" for each issue, in English or Russian
  (`--lang ru` or `[report] lang = "ru"`). Uses `--company` and `--logo` for
  white-label branding. Areas that did not run are shown as not checked, and CMS
  detection is never presented as a passed vulnerability check.
- Fixed double-backslash line continuations in README command examples.
- Added DMARC checks: missing record (medium when the domain has MX records),
  multiple records, missing or invalid `p=` policy, and monitor-only `p=none`.
  Subdomain targets fall back to the parent domain's `_dmarc` record.
- Added a TLS certificate check for HTTPS targets: validation failures and
  expiry within 30 days (high within 14). One verified TLS 1.2+ handshake per target;
  disable with `--no-tls-check` or `tls_check = false`. Skipped when `--proxy`
  is set so no direct connection bypasses the proxy.
- Fixed DNS checks being silently skipped for domains containing digits
  (for example `site24.ru`); only IP-literal targets are now skipped.
- CLI tests no longer make real network connections.
- Added an action plan to HTML reports and automatic `*-actions.md` CLI exports.
  Tasks group evidence and URLs by rule and sort by severity, distinct URL count,
  and rule ID; uncertain findings require validation first, while informational
  findings are marked for review. Coverage gaps and unverified rechecks remain visible.
- Added an offline action-plan demonstration using the real response analysis
  and report functions: `python -m examples.action_plan_demo --output-dir reports/action-plan-demo`.
  It writes an HTML report, a Markdown checklist, and supporting JSON without network access.
- Added `UNVERIFIED` lifecycle results with reasons in CLI and HTML reports.
  Missing findings become `FIXED` only after an explicit passed recheck of a
  supported rule on a complete, error-free `2xx` response for the same target
  and normalized URL. Inconclusive history no longer establishes regressions.
- Added verified closure for nine selected HTTP header, CORS, and disclosure
  rules. Cookie, body-content, DNS, CMS, JavaScript, and redirect findings remain
  unverified when absent.
- Added per-result verification metadata in JSON schema 4.1 and an additive
  SQLite migration. Legacy reports and stored scans remain readable; absence
  without verification metadata cannot establish a fix or regression.
- Added an offline recheck demonstration with simulated responses and HTML
  scenario reports: `python -m examples.recheck_demo --output-dir reports/recheck-demo`.
- Kept scanning, local history, comparison, report exports, and branding free.

## 5.0.1

- Fixed Makefile development-tool checks so an active virtual environment is
  validated by its actual `pytest` executable.
- Updated regression coverage for missing development tools.
- CI passes across Python 3.11, 3.12, 3.13, and 3.14, including package and Docker jobs.

## 5.0.0

- Switched the project license from MIT to Apache-2.0 before public release.
- Added SPDX-aligned packaging metadata and a canonical Apache License 2.0 `LICENSE` file.
- Added persistent TOML configuration with CLI-over-config precedence and strict validation.
- Pinned direct runtime, development, and build dependencies for reproducible installations.
- Added explicit local vulnerability-database updates and offline CMS advisory lookup.
- Added JavaScript scan controls, bounded file handling, dashboard authentication, and regression coverage.
- Added Python 3.14 coverage to the CI matrix and hardened release/build workflows.
- Added lock-safe advisory DB updates and collision-safe report/log filenames.

## 4.3.8

- Hardened report auto-open with absolute paths and graceful fallback.
- Empty `--company` now selects the default company name without aborting a scan.
- Missing optional system wordlists are informational when explicitly requested.
