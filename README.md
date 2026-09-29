# web-audit-pro

[![CI](https://github.com/HackToolWork/web-audit-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/HackToolWork/web-audit-pro/actions/workflows/ci.yml)
[![CodeQL](https://github.com/HackToolWork/web-audit-pro/actions/workflows/codeql.yml/badge.svg)](https://github.com/HackToolWork/web-audit-pro/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-responsible%20use-green.svg)](SECURITY.md)

**English** | [Русский](README.ru.md)

> **Web Audit Pro is a low-impact, auditable toolkit for authorized web security assessment, security engineering, and bug-bounty triage.**

It combines deterministic HTTP checks, passive DNS and JavaScript analysis, CMS fingerprinting, local vulnerability enrichment, scope enforcement, rate limiting, scan history, reproducible reports, SARIF output, an optional TUI, and a local read-only dashboard.

**Use it only on systems you own or are explicitly authorized to assess.** The authorization flag is an acknowledgement, not legal permission. Without it, an interactive run asks for confirmation; scripts and CI must pass `--yes-i-am-authorized`.

---

## 60-second start

### Kali Linux / Debian / Ubuntu

```bash
git clone https://github.com/HackToolWork/web-audit-pro.git
cd web-audit-pro
sudo ./install.sh
web-audit example.com --yes-i-am-authorized
```

### Docker

```bash
docker build -t web-audit-pro:local .
mkdir -p reports
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD/reports:/app/reports" \
  web-audit-pro:local example.com --yes-i-am-authorized
```

### Windows / macOS / other Python environments

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
web-audit example.com --yes-i-am-authorized
```

For development, use `make install-dev` and `make check`.

---

## Why this project exists

Web security tools often fall into one of two extremes: tiny one-off scripts with fragile output, or large scanners that are difficult to audit and easy to run too aggressively.

Web Audit Pro is intentionally in the middle:

- **Low impact:** conservative request rate, bounded responses, GET-only assessment logic, and no automatic takeover or exploit delivery.
- **Auditable:** every finding has a rule ID, severity, evidence, confidence, and remediation guidance.
- **Automation-first:** stable JSON/CSV/HTML/SARIF/SQLite outputs work in CI, cron, containers, and local workflows.
- **Portable:** no developer-specific paths; configuration and cache locations follow portable user-directory conventions.
- **Offline-friendly:** CMS/CVE enrichment can use the local advisory database after an explicit update.
- **Scope-aware:** private targets, subdomain discovery, and custom path sources are explicit and controllable.

A finding is a **lead for human verification**, not automatic proof of exploitability.

---

## What it can do

| Area | Capability | Default behavior |
|---|---|---|
| HTTP | Status, latency, response size, redirects, request errors | Enabled |
| Headers | HSTS, CSP, `nosniff`, Referrer-Policy, clickjacking controls | Enabled |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, unsafe `SameSite=None` | Enabled |
| CORS | Wildcard / credential combinations | Enabled |
| Disclosure | `Server`, `X-Powered-By` | Enabled |
| JavaScript | Same-origin credential-like pattern detection with redaction | Optional (`--scan-js`) |
| DNS | A/AAAA, MX, TXT, SPF and DMARC (both with parent-domain fallback), CNAME observations | Optional / configurable |
| TLS certificate | Validation failures, expiry within 30 days (high within 14) | Enabled for HTTPS targets (`--no-tls-check` to disable; skipped with `--proxy`) |
| CMS | Fingerprinting and advisory references | Optional / configurable |
| WordPress | Plugin and theme inventory with versions from already-fetched HTML (no extra requests; ambiguous versions reported as unknown) | With CMS detection |
| Vulnerability DB | Local CVE/advisory lookup | Offline after `--update-db` |
| Subdomains | Certificate Transparency candidates | Optional (`--discover-subdomains`) |
| History | Scan-to-scan comparison | Available |
| Reports | HTML, JSON, CSV, SARIF, SQLite | Available |
| Terminal UI | Live progress and high-severity alerts | Optional (`--tui`) |
| Dashboard | Local read-only web UI | Optional (`--serve`) |

---

## Common workflows

### 1. Standard authorized assessment

```bash
web-audit example.com --yes-i-am-authorized
```

### 2. Passive JavaScript review

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --scan-js
```

JavaScript findings redact sensitive values in stored evidence. The module is intended to identify credential-like material that should be manually validated and rotated where appropriate.

### 3. Passive subdomain inventory

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --discover-subdomains
```

Certificate Transparency output is treated as candidate inventory, not proof that a host is live or in scope.

### 4. CMS + offline advisory enrichment

Update the local database explicitly:

```bash
web-audit --update-db
```

Then use the local cache during an audit:

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --cms-vuln-lookup
```

Normal audits do not contact NVD just because CMS enrichment is enabled.

#### WordPress plugins and themes

Detected WordPress plugin and theme versions can be checked offline against the
[Wordfence Intelligence](https://www.wordfence.com/threat-intel/) vulnerability
feed, which is free for commercial use but requires a free API key from a
Wordfence account. Download it explicitly:

```bash
export WORDFENCE_API_KEY=your-key
web-audit --update-wp-db
```

Later audits use the local copy automatically without contacting Wordfence and
warn when it is older than seven days. Wordfence rate-limits the feed and may
suspend keys that keep exceeding the limit, so `--update-wp-db` sends no request
while the local copy is under 12 hours old or for 12 hours after an HTTP 429. A component is reported as vulnerable
only when its version was detected unambiguously and falls inside an affected
range. Reports show the data source and the copyright notices required by the
feed's terms. `WEB_AUDIT_WP_VULN_DB` overrides the database location.

### 5. Internal laboratory target

For a private RFC1918, loopback, or other explicitly non-public target in an authorized lab:

```bash
web-audit internal.example \
  --yes-i-am-authorized \
  --allow-private
```

### 6. CI gate

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --fail-on medium
```

### 7. Open the owner report

After an interactive scan on a desktop, the owner report opens in the browser
automatically. `--open` forces it (for example over SSH with X forwarding) and
`--no-open` turns it off:

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --no-open
```

Terminal messages use the same language as the report (system locale or `--lang`).

### 8. Plain-language owner report

Every run also writes `owner-report-*.html`: a short report for non-technical site
owners with a traffic-light status, which areas were checked, what changed since the
previous scan, and what to do for each issue. Use `--company` and `--logo` for your
own branding. The language follows the system locale (Russian on a Russian
system); `--lang en|ru` overrides it:

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --lang ru \
  --company "Example Studio" \
  --logo logo.png
```

Areas that did not run are shown as "not checked", never as OK. The report is a
single HTML file that prints cleanly to PDF from a browser.

### 9. Local dashboard

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --serve
```

The dashboard is read-only and intended for local or explicitly controlled environments.

---

## Configuration

Web Audit Pro supports a TOML configuration file so repeated options do not have to be typed on every run.

Create one from the supplied template:

```bash
cp web-audit.toml.example web-audit.toml
```

### Precedence

```text
CLI arguments > TOML configuration > built-in defaults
```

This means explicit command-line choices always win.

### Minimal configuration

```toml
[scan]
threads = 10
requests_per_second = 2.0
timeout = 5.0
output_dir = "reports"

[features]
dns = true
cms = true
scan_js = true
tui = false

[report]
company = "Security Assessment Team"
theme = "dark"

[nvd]
nvd_timeout = 12.0
```

The example intentionally uses a neutral company name. Change it for your own reports.

### Configuration file locations

The tool can use a repository/local configuration file or the standard user configuration directory. Use `--config /path/to/file.toml` when you need deterministic selection.

Relative paths are resolved using the configuration context rather than a developer-specific home directory.

---

## Ownership verification

`--yes-i-am-authorized` is an acknowledgement. When you scan sites for other
people, have them prove ownership first:

```bash
web-audit https://www.example.com --ownership-token --lang ru   # instructions to forward
web-audit https://www.example.com --verify-ownership            # check the proof
web-audit https://www.example.com --yes-i-am-authorized --require-ownership
```

The owner publishes a token either as a DNS TXT record (at the domain or
`_webaudit.<domain>`; covers the domain and its subdomains) or in
`/.well-known/webaudit-verify.txt` (covers that host only; redirects are not
followed and non-public addresses are never fetched). With `--require-ownership`
or `require_ownership = true` in `[scan]`, unverified targets are refused and
discovered subdomains outside the proof are skipped. The owner report states how
ownership was verified.

Tokens are an HMAC of the domain under a local secret in
`~/.config/web-audit-pro/ownership.key` (override with
`WEB_AUDIT_OWNERSHIP_KEY_FILE`). Back it up: replacing it invalidates every token
already issued.

## Scope control

Scope control is a core safety feature, not an optional afterthought.

Example scope file:

```text
example.com
*.example.com
```

Run with:

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --scope-file examples/scope.txt
```

For bug-bounty work, keep a copy of the program's written scope next to your project configuration and translate only the relevant in-scope hosts into the scope file.

---

## Paths and wordlists

You can supply an explicit path list:

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --paths-file examples/paths.txt
```

On systems with compatible security wordlists, you can opt into system discovery:

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --kali-wordlist
```

The tool does not require Kali wordlists and safely falls back to its built-in path set when none are available.

---

## Reports

The scanner can produce:

- **HTML** for people and client-facing review;
- **Markdown action plan** for a prioritized checklist with evidence and affected URLs;
- **JSON** for automation and scan comparison;
- **CSV** for spreadsheets and triage;
- **SARIF 2.1.0** for security tooling and CI integrations;
- **SQLite** for local history and dashboard access.

By default, generated files include a run identifier so parallel containers do not overwrite one another.

### Work through the action plan

Each scan includes an action plan in its HTML report and automatically writes
a companion `*-actions.md` file. Findings are grouped by rule, ordered by severity,
then by the number of distinct affected URLs, then by rule ID. Each task keeps
the evidence, URLs, recommendation, and guidance for checking the result again.
Findings with uncertain confidence or incomplete responses need validation
first; informational findings are marked for review.

This order is a triage aid, not proof of exploitability or business impact.
Request errors, incomplete coverage, and `UNVERIFIED` rechecks remain visible;
an empty finding list does not establish that the site is secure.
Reports include captured evidence and URLs; review that content before sharing it.

After a change, rerun the same URLs with the same scan settings and compare the
results. Automatic confirmation applies only to the supported response rules
listed below. Other rules require manual verification, and a passed header
presence check does not validate the policy's effectiveness.

To see a complete example without contacting a site, run from the repository
root with dependencies installed:

```bash
python -m examples.action_plan_demo --output-dir reports/action-plan-demo
```

Open `reports/action-plan-demo/index.html` for the real HTML report, or
`action-plan.md` in the same directory for the checklist. `report.json` contains
the supporting observations. The synthetic data includes a disabled HSTS policy,
missing CSP on two URLs, informational server headers, and a timeout that leaves
a previous finding unverified. The demo makes no network connections.

### Compare two scans

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --compare reports/previous.json
```

The CLI and HTML report show finding lifecycle changes. Without `--compare`,
previous scans for the same target in the local database provide the history.

- **FIXED** means a supported rule explicitly passed on a complete, successful
  `2xx` response for the same target and normalized URL, without a request error.
- **UNVERIFIED** means a finding is absent but its resolution could not be
  confirmed: for example, the URL was skipped, the request failed, the response
  was truncated, the rule was ignored, or verification metadata is unavailable.
  The report includes the reason. An inconclusive check does not establish a
  fix or make the next observed finding a regression.

Verified closure currently covers these nine response rules:
`headers.hsts`, `headers.hsts_disabled`, `headers.content_type_options`,
`headers.csp`, `headers.csp_report_only`, `headers.referrer_policy`,
`headers.clickjacking`, `cors.wildcard_credentials`, and `info.stack_headers`.
Passing conditions must be present in the response; simply losing a finding is
insufficient. Absence of cookie, body-content, DNS, TLS certificate, CMS, JavaScript, or redirect
findings is not automatically marked fixed. A passed rule describes that
response at that time, not the security of the whole application.
For CSP and Referrer-Policy this checks for a nonempty header; policy syntax,
valid values, and effectiveness are not validated. In particular, FIXED for
`headers.csp` confirms that the header is no longer missing, not that CSP is
configured correctly.

JSON schema **4.1** adds per-result `verification_version` and `verified_rules`.
Existing JSON reports remain readable. SQLite databases receive an additive
migration that preserves earlier scans; old rows have no verification metadata.
Historical absence without this metadata cannot establish a fix or regression.
The scanner, local history, comparison, report exports, and branding remain
free; this change adds no subscription or account requirement.

### Try the recheck demo offline

From the repository root, with dependencies installed:

```bash
python -m examples.recheck_demo --output-dir reports/recheck-demo
```

Open `reports/recheck-demo/index.html` to compare the generated scenario reports.
The demo uses simulated HTTP responses, opens no sockets, and does not scan a site.

### SARIF in CI

SARIF is designed for machine-readable findings and can be uploaded to compatible security tooling. The report is intentionally evidence-oriented: the presence of a result is not a claim that exploitation was performed.

---

## Vulnerability database

The vulnerability workflow is deliberately split into two operations:

```text
web-audit --update-db
        ↓
local advisory database
        ↓
web-audit ... --cms-vuln-lookup
```

This avoids coupling every scan to a live vulnerability API.

The local database path can be overridden with:

```bash
export WEB_AUDIT_VULN_DB=/path/to/vulndb.sqlite3
```

The supplied Docker image uses `/app/reports/vulndb.sqlite3` so the database can persist in a mounted directory.

---

## Docker notes

The image is built as a multi-stage container and runs without root privileges.

For persistent reports and the local advisory DB:

```bash
mkdir -p reports
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD/reports:/app/reports" \
  web-audit-pro:local --help
```

If you run multiple containers against the same mounted output directory, report names remain unique by default. SQLite writers use a bounded lock strategy; ordinary advisory lookups use read-only access.

---

## Development

Recommended developer workflow:

```bash
make install-dev
make check
```

`make` respects an already active `VIRTUAL_ENV`. If none is active, it creates the repository-local `.venv` as needed.

Useful targets:

```text
make test
make lint
make compile
make check
make build
make docker-build
make clean
```

If an active virtual environment is missing a required developer tool such as `pytest`, the Makefile reports the installation command instead of silently replacing the environment.

---

## Project layout

```text
web-audit-pro/
├── .github/              # CI, CodeQL, Dependabot, issue/PR templates
├── examples/             # sample scope/path/target files
├── tests/                # unit and integration tests
├── web_audit/            # application package
│   ├── data/              # packaged CMS fingerprint data
│   ├── scanner.py         # HTTP scanning engine
│   ├── dns_audit.py       # passive DNS analysis
│   ├── tls_audit.py       # TLS certificate validity and expiry
│   ├── js_audit.py        # passive JavaScript analysis
│   ├── cms.py             # CMS fingerprinting
│   ├── wordpress.py       # passive WordPress plugin/theme inventory
│   ├── wp_vulndb.py       # offline Wordfence vulnerability matching
│   ├── ownership.py       # DNS/file domain ownership verification
│   ├── vulndb.py          # local advisory DB
│   ├── nvd.py             # explicit advisory DB update client
│   ├── reports.py         # HTML/JSON/CSV reporting
│   ├── owner_report.py    # plain-language owner report (texts in owner_texts.py)
│   ├── sarif.py           # SARIF output
│   ├── serve.py            # read-only dashboard
│   └── tui.py              # terminal UI
├── Dockerfile
├── Makefile
├── install.sh
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── web-audit.toml.example
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## Responsible use

Web Audit Pro is built for authorized security work.

It intentionally does **not** provide:

- credential attacks or password spraying;
- brute-force authentication workflows;
- exploit payload delivery;
- destructive requests;
- unrestricted crawling;
- automatic service takeover attempts;
- stealth features intended to defeat access controls.

Before testing a public program, read its rules, identify the exact in-scope hosts, respect its rate limits, and keep evidence sufficient to reproduce findings without exposing secrets unnecessarily.

See [SECURITY.md](SECURITY.md) for the project's security policy and reporting process.

---

## Threat model and limitations

Web Audit Pro is a **low-impact assessment and triage tool**, not a full penetration-testing replacement.

It does not guarantee detection of a vulnerability, exploitability, business impact, or program eligibility. Network controls, WAFs, authentication barriers, application state, and scope rules can all change what a scan observes.

Security findings should be manually validated before disclosure, remediation, or a bug-bounty submission.

---

## Contributing

Contributions are welcome.

Before opening a pull request:

```bash
make install-dev
make check
```

Please keep changes focused, add regression tests for bug fixes, avoid developer-specific paths, and preserve the project's low-impact and scope-aware design.

Read:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

---

## Release process

Releases use annotated Git tags:

```text
vX.Y.Z
```

The release workflow verifies tag/package version alignment, installs the pinned development toolchain, runs linting and tests, builds Python distributions, generates SHA-256 checksums, and publishes the release assets.

The repository also runs CodeQL and dependency review through GitHub Actions.

---

## Support and community

- **Repository:** https://github.com/HackToolWork/web-audit-pro
- **Security:** [SECURITY.md](SECURITY.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Support:** [SUPPORT.md](SUPPORT.md)
- **License:** [Apache-2.0](LICENSE)

### Sponsorship

Web Audit Pro is open source. Sponsorship can support maintenance, documentation, security research, testing, and new defensive capabilities.

---

## License

Web Audit Pro is licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE).
