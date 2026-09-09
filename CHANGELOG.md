## 5.0.0

- Switched the project license from MIT to Apache-2.0 before public release.
- Added SPDX-aligned packaging metadata and a canonical Apache License 2.0 `LICENSE` file.

## 5.0.0

- Quality fixes and release hardening for developer environments and Docker persistence.

- Added `web-audit.toml` configuration with CLI-over-config precedence.
- Added strict TOML type/option validation and config-relative path resolution.
- Pinned direct runtime/dev/build dependencies for reproducible installations.
- Added explicit `--update-db` maintenance command for the local CMS advisory cache.
- `--cms-vuln-lookup` is now offline during normal scans and reads the local advisory DB.
- Added CLI controls for JavaScript scan enablement and file limits.
- Expanded CI test matrix to Python 3.14.
- Added regression coverage for configuration, offline advisory lookup, and pinning.

## 4.3.8

- Hardened report auto-open with absolute paths and graceful fallback.
- Empty `--company` now selects the default company name without aborting a scan.
- Missing optional system wordlists are informational when explicitly requested.
