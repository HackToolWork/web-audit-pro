# Web Audit Pro 5.2.0

Library APIs for hosted checks, used by the Sitozor web service (https://sitozor.ru).

## Highlights

- `web_audit.audit.run_audit()` runs the whole audit (scan, DNS/TLS/WordPress
  checks, coverage) as a library call. It prints nothing; messages go to a
  `notify` callback and network helpers can be injected. The CLI uses it, so
  output is unchanged.
- Ownership verification accepts a `token` callable. Multi-user services must
  bind tokens to each request: with domain-only tokens, anyone asking about a
  domain would receive the owner's published token and pass verification.

## Installation

```bash
pipx install web-audit-pro
```

---

# Web Audit Pro 5.1.0

Plain-language security reports for site owners, in English and Russian.
Project site: https://sitozor.ru

## Release highlights

### Owner report

Every scan writes `owner-report-*.html`: a traffic-light status, which areas were
checked, what changed since the last scan, and "what it means / what to do" for
each issue. Areas that did not run are shown as not checked, and a scan with
unchecked WordPress plugins is never presented as all clear. White-label with
`--company` and `--logo`. On an interactive desktop the report opens
automatically.

### New checks

- TLS certificate validity and expiry (TLS 1.2+ handshake).
- DMARC; SPF, MX and DMARC fall back to the parent domain for hosts such as
  `www.example.com`.
- Passive WordPress plugin and theme inventory, and offline matching against the
  Wordfence Intelligence vulnerability feed (`--update-wp-db`).
- Domain ownership verification via DNS TXT or a `/.well-known` file
  (`--ownership-token`, `--verify-ownership`, `--require-ownership`).

### English and Russian

Reports and terminal messages follow the system locale or `--lang en|ru`.
Without `--yes-i-am-authorized`, an interactive run asks for confirmation.

### Fixes

- Scans of any site with a detected CMS crashed while saving results (since 5.0.0).
- False Magento, PrestaShop, WordPress, Joomla and Ghost detections from generic
  paths or from merely naming a platform in page text.
- DNS checks skipped domains containing digits; mail checks ran for `localhost`.

## Installation

```bash
pipx install web-audit-pro
web-audit https://example.com
```

From source: `sudo ./install.sh`. For contributors: `make install-dev && make check`.

## Verification

CI runs Ruff, compile checks and the test suite on Python 3.11–3.14, plus package
and Docker builds. The release workflow smoke-tests the wheel in a clean
environment before publishing to PyPI through Trusted Publishing.
