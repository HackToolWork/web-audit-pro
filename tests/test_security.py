import pytest

from web_audit.security import (
    SUPPORTED_VERIFICATION_RULES,
    analyze_response,
    verified_response_rules,
)


def test_security_headers_findings():
    findings = analyze_response(
        url="https://example.com/",
        status=200,
        headers={"Server": "nginx/1.2", "Content-Type": "text/html; charset=utf-8"},
    )
    ids = {finding.rule_id for finding in findings}
    assert {"headers.hsts", "headers.csp", "headers.clickjacking", "info.stack_headers"} <= ids


def test_cors_wildcard_with_credentials_is_flagged():
    findings = analyze_response(
        url="https://example.com/",
        status=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Strict-Transport-Security": "max-age=31536000",
        },
    )
    assert any(f.rule_id == "cors.wildcard_credentials" for f in findings)


def test_cookie_flags_are_checked():
    class RawHeaders:
        def getlist(self, name):
            assert name == "Set-Cookie"
            return ["session=abc; Path=/"]

    findings = analyze_response(
        url="https://example.com/login",
        status=200,
        headers={},
        raw_headers=RawHeaders(),
    )
    ids = {finding.rule_id for finding in findings}
    assert {"cookies.secure", "cookies.httponly", "cookies.samesite"} <= ids


def test_selected_conditions_are_verified_on_a_protected_html_response():
    rules = verified_response_rules(
        url="https://example.com/",
        status=200,
        headers={
            "content-type": "text/html; charset=utf-8",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "referrer-policy": "strict-origin-when-cross-origin",
            "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Lax",
        },
    )
    assert set(rules) == SUPPORTED_VERIFICATION_RULES
    assert rules == tuple(sorted(rules))
    assert not any(rule.startswith("cookies.") for rule in rules)


@pytest.mark.parametrize(
    "hsts",
    [
        "",
        "max-age=0",
        'max-age="0"',
        "max-age=-1",
        "max-age=broken",
        "includeSubDomains",
        "max-age=300; max-age=0",
        "max-age=300; max-age=600",
        "max-age=300, max-age=600",
    ],
)
def test_absent_disabled_or_ambiguous_hsts_is_not_verification(hsts):
    rules = verified_response_rules(
        url="https://example.com/", status=200, headers={"Strict-Transport-Security": hsts}
    )
    assert "headers.hsts" not in rules
    assert "headers.hsts_disabled" not in rules


def test_hsts_on_plain_http_is_not_verification():
    rules = verified_response_rules(
        url="http://example.com/",
        status=200,
        headers={"Strict-Transport-Security": "max-age=31536000"},
    )
    assert "headers.hsts" not in rules
    assert "headers.hsts_disabled" not in rules


def test_report_only_csp_does_not_verify_either_csp_finding():
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy-Report-Only": "default-src 'self'; frame-ancestors 'none'",
    }
    findings = analyze_response(url="https://example.com/", status=200, headers=headers)
    assert "headers.csp" not in {finding.rule_id for finding in findings}
    rules = verified_response_rules(url="https://example.com/", status=200, headers=headers)
    assert not {"headers.csp", "headers.csp_report_only", "headers.clickjacking"} & set(rules)


@pytest.mark.parametrize(
    "content_type", ["", "text/plain", "application/json", "text/html-invalid"]
)
def test_html_rules_are_not_verified_for_other_content_types(content_type):
    rules = verified_response_rules(
        url="https://example.com/",
        status=200,
        headers={
            "Content-Type": content_type,
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
        },
    )
    assert not {"headers.csp", "headers.csp_report_only", "headers.clickjacking"} & set(rules)


@pytest.mark.parametrize(
    ("frame_header", "csp", "expected"),
    [
        ("DENY", "", True),
        ("sameorigin", "", True),
        ("DENY", "frame-ancestors *", False),
        ("ALLOW-FROM https://example.com", "", False),
        ("invalid", "", False),
        ("", "frame-ancestors 'self'", True),
        ("", "frame-ancestors https://trusted.example", True),
        ("", "frame-ancestors *", False),
        ("", "frame-ancestors https:", False),
        ("", "frame-ancestors", False),
        ("", "frame-ancestors 'none' *", False),
        ("", "frame-ancestors https://[broken", False),
        ("", "frame-ancestors https://trusted.example:broken", False),
        ("", "report-uri /frame-ancestors", False),
        ("", "frame-ancestors *; frame-ancestors 'none'", False),
    ],
)
def test_clickjacking_verification_requires_a_supported_frame_policy(frame_header, csp, expected):
    rules = verified_response_rules(
        url="https://example.com/",
        status=200,
        headers={
            "Content-Type": "text/html",
            "X-Frame-Options": frame_header,
            "Content-Security-Policy": csp,
        },
    )
    assert ("headers.clickjacking" in rules) is expected


def test_invalid_nosniff_and_disclosed_stack_are_not_verified():
    rules = verified_response_rules(
        url="https://example.com/",
        status=200,
        headers={
            "X-Content-Type-Options": "invalid",
            "Server": "nginx",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert "headers.content_type_options" not in rules
    assert "info.stack_headers" not in rules
    assert "cors.wildcard_credentials" not in rules


@pytest.mark.parametrize("status", [None, 101, 301, 403, 404, 429, 503])
def test_unsuccessful_responses_never_verify_rules(status):
    assert verified_response_rules(url="https://example.com/", status=status, headers={}) == ()
