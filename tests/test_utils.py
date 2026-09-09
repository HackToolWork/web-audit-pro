from ipaddress import ip_address

from web_audit.utils import build_url, is_non_public_address, normalize_target


def test_normalize_hostname():
    assert normalize_target("example.com") == "https://example.com"


def test_normalize_https():
    assert normalize_target("HTTPS://EXAMPLE.COM/") == "https://example.com"


def test_reject_credentials():
    assert normalize_target("https://user:pass@example.com") is None


def test_reject_invalid_port():
    assert normalize_target("https://example.com:bad") is None


def test_build_url():
    assert build_url("https://example.com/", "/health") == "https://example.com/health"


def test_public_address_policy():
    assert is_non_public_address(ip_address("10.0.0.1")) is True
    assert is_non_public_address(ip_address("8.8.8.8")) is False
