# web-audit-pro

[![CI](https://github.com/HackToolWork/web-audit-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/HackToolWork/web-audit-pro/actions/workflows/ci.yml)
[![CodeQL](https://github.com/HackToolWork/web-audit-pro/actions/workflows/codeql.yml/badge.svg)](https://github.com/HackToolWork/web-audit-pro/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-responsible%20use-green.svg)](SECURITY.md)

**English** | [Русский](README.ru.md)

> **Web Audit Pro is a low-impact, auditable toolkit for authorized web security assessment, security engineering, and bug-bounty triage.**

It combines deterministic HTTP checks, passive DNS and JavaScript analysis, CMS fingerprinting, local vulnerability enrichment, scope enforcement, rate limiting, scan history, reproducible reports, SARIF output, an optional TUI, and a local read-only dashboard.

**Use it only on systems you own or are explicitly authorized to assess.** The authorization flag is an acknowledgement, not legal permission.

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
docker run --rm \\
  -u "$(id -u):$(id -g)" \\
  -v "$PWD/reports:/app/reports" \\
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
| DNS | A/AAAA, MX, TXT, SPF, CNAME observations | Optional / configurable |
| CMS | Fingerprinting and advisory references | Optional / configurable |
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

### 7. Open the generated report

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --open
```

### 8. Local dashboard

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
- **JSON** for automation and scan comparison;
- **CSV** for spreadsheets and triage;
- **SARIF 2.1.0** for security tooling and CI integrations;
- **SQLite** for local history and dashboard access.

By default, generated files include a run identifier so parallel containers do not overwrite one another.

### Compare two scans

```bash
web-audit example.com \
  --yes-i-am-authorized \
  --compare reports/previous.json
```

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
docker run --rm \\
  -u "$(id -u):$(id -g)" \\
  -v "$PWD/reports:/app/reports" \\
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
│   ├── js_audit.py        # passive JavaScript analysis
│   ├── cms.py             # CMS fingerprinting
│   ├── vulndb.py          # local advisory DB
│   ├── nvd.py             # explicit advisory DB update client
│   ├── reports.py         # HTML/JSON/CSV reporting
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
