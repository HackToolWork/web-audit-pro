from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urljoin, urlparse

from .models import Confidence, Finding, Severity


def _get_header(headers: Mapping[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value.strip()
    return ""


def _cookie_headers(headers: Mapping[str, str], raw_headers: object | None) -> list[str]:
    if raw_headers is not None:
        getlist = getattr(raw_headers, "getlist", None)
        if callable(getlist):
            values = getlist("Set-Cookie")
            if values:
                return [str(value) for value in values]
    combined = _get_header(headers, "Set-Cookie")
    return [combined] if combined else []


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    evidence: str,
    recommendation: str,
    confidence: Confidence = "high",
) -> Finding:
    return Finding(rule_id, title, severity, category, evidence, recommendation, confidence)


def analyze_response(
    *,
    url: str,
    status: int | None,
    headers: Mapping[str, str],
    raw_headers: object | None = None,
    request_target: str | None = None,
) -> tuple[Finding, ...]:
    """Run passive/low-impact checks; never inject payloads or mutate state."""
    if status is None:
        return ()
    findings: list[Finding] = []
    parsed = urlparse(url)
    is_https = parsed.scheme.lower() == "https"
    content_type = _get_header(headers, "Content-Type").lower()

    hsts = _get_header(headers, "Strict-Transport-Security")
    if is_https and not hsts:
        findings.append(
            _finding(
                "headers.hsts",
                "HSTS header is missing",
                "low",
                "security_headers",
                "HTTPS response does not include Strict-Transport-Security.",
                "Enable HSTS after confirming HTTPS is correctly deployed across the host.",
            )
        )
    elif is_https and "max-age=0" in hsts.replace(" ", "").lower():
        findings.append(
            _finding(
                "headers.hsts_disabled",
                "HSTS is explicitly disabled",
                "medium",
                "security_headers",
                f"Strict-Transport-Security: {hsts}",
                "Use a positive max-age after validating HTTPS coverage.",
            )
        )

    if not _get_header(headers, "X-Content-Type-Options"):
        findings.append(
            _finding(
                "headers.content_type_options",
                "MIME sniffing protection is missing",
                "low",
                "security_headers",
                "X-Content-Type-Options is absent.",
                "Send X-Content-Type-Options: nosniff where appropriate.",
            )
        )

    if "text/html" in content_type:
        csp = _get_header(headers, "Content-Security-Policy")
        if not csp:
            if _get_header(headers, "Content-Security-Policy-Report-Only"):
                findings.append(
                    _finding(
                        "headers.csp_report_only",
                        "CSP is report-only",
                        "low",
                        "security_headers",
                        "Content-Security-Policy-Report-Only is present without enforcing CSP.",
                        "Move toward an enforcing CSP after validating compatibility.",
                    )
                )
            else:
                findings.append(
                    _finding(
                        "headers.csp",
                        "Content Security Policy is missing",
                        "low",
                        "security_headers",
                        "HTML response lacks Content-Security-Policy.",
                        "Deploy a restrictive CSP tailored to the application's resources.",
                        "medium",
                    )
                )
        if not _get_header(headers, "Referrer-Policy"):
            findings.append(
                _finding(
                    "headers.referrer_policy",
                    "Referrer-Policy is missing",
                    "low",
                    "security_headers",
                    "Referrer-Policy is absent.",
                    "Set an explicit Referrer-Policy such as strict-origin-when-cross-origin.",
                )
            )
        frame_header = _get_header(headers, "X-Frame-Options")
        if not frame_header and "frame-ancestors" not in csp.lower():
            findings.append(
                _finding(
                    "headers.clickjacking",
                    "Clickjacking protection is not declared",
                    "low",
                    "security_headers",
                    ("Neither X-Frame-Options nor CSP frame-ancestors is present "
                     "on an HTML response."),
                    "Set an appropriate X-Frame-Options policy or CSP frame-ancestors directive.",
                )
            )
    elif not _get_header(headers, "Referrer-Policy"):
        findings.append(
            _finding(
                "headers.referrer_policy",
                "Referrer-Policy is missing",
                "low",
                "security_headers",
                "Referrer-Policy is absent.",
                ("Set an explicit Referrer-Policy when the resource handles "
                 "sensitive navigation context."),
                "medium",
            )
        )

    cors_origin = _get_header(headers, "Access-Control-Allow-Origin")
    cors_credentials = _get_header(headers, "Access-Control-Allow-Credentials").lower()
    if cors_origin == "*" and cors_credentials == "true":
        findings.append(
            _finding(
                "cors.wildcard_credentials",
                "CORS wildcard is combined with credentials",
                "medium",
                "cors",
                "Access-Control-Allow-Origin is '*' while credentials are enabled.",
                "Allow credentials only for an explicit, trusted origin allowlist.",
            )
        )

    for cookie in _cookie_headers(headers, raw_headers):
        attributes = {
            part.strip().split("=", 1)[0].lower() for part in cookie.split(";")
        }
        cookie_name = cookie.split("=", 1)[0].strip() or "unknown"
        if is_https and "secure" not in attributes:
            findings.append(
                _finding(
                    "cookies.secure",
                    "HTTPS cookie is missing Secure",
                    "medium",
                    "cookies",
                    f"Cookie '{cookie_name}' does not contain Secure.",
                    "Mark sensitive cookies Secure so browsers send them only over HTTPS.",
                )
            )
        if "httponly" not in attributes:
            findings.append(
                _finding(
                    "cookies.httponly",
                    "Cookie is missing HttpOnly",
                    "low",
                    "cookies",
                    f"Cookie '{cookie_name}' does not contain HttpOnly.",
                    "Use HttpOnly for cookies that do not need client-side JavaScript access.",
                )
            )
        samesite = next(
            (
                part.strip().lower()
                for part in cookie.split(";")
                if part.strip().lower().startswith("samesite=")
            ),
            "",
        )
        if not samesite:
            findings.append(
                _finding(
                    "cookies.samesite",
                    "Cookie is missing SameSite",
                    "low",
                    "cookies",
                    f"Cookie '{cookie_name}' does not declare SameSite.",
                    "Set SameSite explicitly according to cross-site requirements.",
                )
            )
        elif samesite.endswith("=none") and "secure" not in attributes:
            findings.append(
                _finding(
                    "cookies.samesite_none_insecure",
                    "SameSite=None cookie is not Secure",
                    "medium",
                    "cookies",
                    f"Cookie '{cookie_name}' uses SameSite=None without Secure.",
                    "Pair SameSite=None with Secure to meet modern browser requirements.",
                )
            )

    server = _get_header(headers, "Server")
    powered_by = _get_header(headers, "X-Powered-By")
    if server or powered_by:
        details = []
        if server:
            details.append(f"Server={server}")
        if powered_by:
            details.append(f"X-Powered-By={powered_by}")
        findings.append(
            _finding(
                "info.stack_headers",
                "Technology-identifying response headers are exposed",
                "info",
                "information_disclosure",
                "; ".join(details),
                "Minimize unnecessary platform/version disclosure in HTTP response headers.",
            )
        )

    if status in {301, 302, 303, 307, 308} and _get_header(headers, "Location"):
        location = urljoin(url, _get_header(headers, "Location"))
        if request_target:
            target_host = urlparse(request_target).hostname
            location_host = urlparse(location).hostname
            if target_host and location_host and target_host.lower() != location_host.lower():
                findings.append(
                    _finding(
                        "redirect.external",
                        "Redirect leaves the assessed host",
                        "info",
                        "redirects",
                        f"Location points to {location}",
                        "Review whether the cross-origin redirect is intentional and documented.",
                    )
                )

    return tuple(findings)
