from web_audit.identity import build_finding_identity
from web_audit.models import Finding


def make_finding(
    rule_id: str = "headers.csp",
    *,
    severity: str = "low",
    evidence: str = "evidence",
) -> Finding:
    return Finding(
        rule_id,
        "Test finding",
        severity,
        "test",
        evidence,
        "fix",
    )


def test_same_logical_finding_has_same_identity():
    first = build_finding_identity(
        make_finding(),
        target="https://example.com",
        location="https://example.com/",
    )
    second = build_finding_identity(
        make_finding(severity="medium", evidence="different evidence"),
        target="https://example.com/",
        location="HTTPS://EXAMPLE.COM:443/#ignored-fragment",
    )

    assert first == second
    assert first.key == second.key


def test_severity_change_does_not_change_identity():
    low = build_finding_identity(
        make_finding(severity="low"),
        target="https://example.com",
        location="https://example.com/",
    )
    high = build_finding_identity(
        make_finding(severity="high"),
        target="https://example.com",
        location="https://example.com/",
    )

    assert low == high


def test_evidence_change_does_not_change_identity():
    first = build_finding_identity(
        make_finding(evidence="old evidence"),
        target="https://example.com",
        location="https://example.com/",
    )
    second = build_finding_identity(
        make_finding(evidence="new evidence"),
        target="https://example.com",
        location="https://example.com/",
    )

    assert first == second


def test_location_change_creates_new_identity():
    first = build_finding_identity(
        make_finding(),
        target="https://example.com",
        location="https://example.com/",
    )
    second = build_finding_identity(
        make_finding(),
        target="https://example.com",
        location="https://example.com/login",
    )

    assert first != second


def test_rule_change_creates_new_identity():
    first = build_finding_identity(
        make_finding("headers.csp"),
        target="https://example.com",
        location="https://example.com/",
    )
    second = build_finding_identity(
        make_finding("headers.hsts"),
        target="https://example.com",
        location="https://example.com/",
    )

    assert first != second


def test_cookie_name_change_creates_new_identity():
    first = build_finding_identity(
        make_finding("cookies.httponly"),
        target="https://example.com",
        location="https://example.com/",
        discriminator="cookie:session",
    )
    second = build_finding_identity(
        make_finding("cookies.httponly"),
        target="https://example.com",
        location="https://example.com/",
        discriminator="cookie:analytics",
    )

    assert first != second


def test_dns_context_change_creates_new_identity():
    first = build_finding_identity(
        make_finding("dns.cname.potential_takeover"),
        target="example.com",
        discriminator="cname:example.github.io",
    )
    second = build_finding_identity(
        make_finding("dns.cname.potential_takeover"),
        target="example.com",
        discriminator="cname:example.herokapp.com",
    )

    assert first != second


def test_js_resource_change_creates_new_identity():
    first = build_finding_identity(
        make_finding("secret.jwt"),
        target="https://example.com",
        location="https://example.com/static/app.js",
    )
    second = build_finding_identity(
        make_finding("secret.jwt"),
        target="https://example.com",
        location="https://example.com/static/vendor.js",
    )

    assert first != second


def test_cms_target_change_creates_new_identity():
    first = build_finding_identity(
        make_finding("cms.detected.wordpress"),
        target="https://example.com",
    )
    second = build_finding_identity(
        make_finding("cms.detected.wordpress"),
        target="https://other.example.com",
    )

    assert first != second


def test_default_https_port_and_fragment_do_not_change_identity():
    first = build_finding_identity(
        make_finding(),
        target="https://example.com",
        location="https://example.com/",
    )
    second = build_finding_identity(
        make_finding(),
        target="HTTPS://EXAMPLE.COM:443/#fragment",
        location="https://example.com:443/#another-fragment",
    )

    assert first == second


def test_hostname_case_does_not_change_identity():
    first = build_finding_identity(
        make_finding(),
        target="https://example.com",
        location="https://example.com/",
    )
    second = build_finding_identity(
        make_finding(),
        target="https://EXAMPLE.COM",
        location="https://EXAMPLE.COM/",
    )

    assert first == second


def test_non_url_target_is_normalized_as_hostname():
    first = build_finding_identity(
        make_finding("dns.spf.missing"),
        target="EXAMPLE.COM.",
    )
    second = build_finding_identity(
        make_finding("dns.spf.missing"),
        target="example.com",
    )

    assert first == second


def test_query_string_is_part_of_identity():
    first = build_finding_identity(
        make_finding(),
        target="https://example.com",
        location="https://example.com/search?q=one",
    )
    second = build_finding_identity(
        make_finding(),
        target="https://example.com",
        location="https://example.com/search?q=two",
    )

    assert first != second


def test_identity_key_is_deterministic():
    first = build_finding_identity(
        make_finding(),
        target="https://example.com",
        location="https://example.com/",
        discriminator="cookie:session",
    )
    second = build_finding_identity(
        make_finding(severity="high", evidence="changed"),
        target="HTTPS://EXAMPLE.COM:443",
        location="https://example.com:443/#fragment",
        discriminator="cookie:session",
    )

    assert first.key == second.key
    assert first.key == (
        '{"discriminator":"cookie:session",'
        '"location":"https://example.com/",'
        '"rule_id":"headers.csp",'
        '"target":"https://example.com/"}'
    )
