# Security Policy

## Intended use

Web Audit Pro is designed for authorized security assessments, defensive audits, and responsible bug-bounty work. Users are responsible for obtaining permission and following the target's published scope, rate limits and rules of engagement.

## Project vulnerabilities

Do not publish exploitable details in a public issue. Use the repository's private vulnerability-reporting mechanism when available, or contact maintainers privately.

## Safe operation

The application requires an explicit authorization flag and blocks non-public/reserved destinations by default. A scope file can add host-level allowlisting, and a global request-rate limit is enabled by default.

These controls reduce accidental misuse but do not establish authorization. DNS can change after a validation step, proxies can alter routing, and a scanner cannot prove that an operator is inside legal scope. Re-check scope at the time of testing.

The project intentionally focuses on low-impact HTTP observations. It does not provide exploit payloads, credential attacks, brute force, destructive methods, or automatic redirect following.

## Reporting scanner findings

Treat scanner findings as leads until manually validated. In a bug-bounty program, reproduce only within the exact allowed scope and follow the program's disclosure and rate-limit rules.


## Network-safety design in 4.0

The JavaScript module only follows same-origin script URLs discovered in already-fetched HTML, reads a bounded response body, and redacts credential-like values before findings are persisted.

DNS analysis is read-only and performs DNS lookups only. Potential dangling-CNAME observations are deliberately low-confidence and never attempt service registration or takeover.

Certificate Transparency discovery is opt-in. Returned hostnames are treated as candidate inventory, filtered to the target domain, checked against the supplied scope, and subjected to the same public-address safety guardrails before HTTP requests are sent.

The optional NVD integration is reference enrichment only. Keyword matches are not proof that the detected software is vulnerable; researchers must validate the exact product, version, configuration, affected-version range, and vendor advisory.

The optional dashboard is read-only, binds to localhost by default, and requires a random token. Non-local binding requires an explicit token and explicit `--serve-public` acknowledgement.
