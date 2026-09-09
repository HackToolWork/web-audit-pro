from web_audit.security import analyze_response


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
