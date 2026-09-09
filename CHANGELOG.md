# Changelog

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
