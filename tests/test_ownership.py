import ipaddress
import os
import stat
from datetime import UTC, datetime

import pytest

from web_audit import cli, ownership
from web_audit.models import CheckResult
from web_audit.ownership import OwnershipProof, token_for


def test_key_is_created_private_and_tokens_are_stable():
    first = token_for("Example.COM.")
    assert first.startswith("webaudit-verify=") and len(first) == len("webaudit-verify=") + 32
    assert stat.S_IMODE(os.stat(ownership.key_path()).st_mode) == 0o600
    assert token_for("https://example.com/path") == first
    assert token_for("www.example.com") != first


def test_tokens_depend_on_the_local_secret(monkeypatch, tmp_path):
    original = token_for("example.com")
    monkeypatch.setenv(ownership.ENV_KEY_FILE, str(tmp_path / "other.key"))
    assert token_for("example.com") != original


def test_invalid_key_file_is_never_replaced(monkeypatch, tmp_path):
    key = tmp_path / "broken.key"
    key.write_text("short", encoding="utf-8")
    monkeypatch.setenv(ownership.ENV_KEY_FILE, str(key))
    with pytest.raises(ValueError, match="invalid"):
        token_for("example.com")
    assert key.read_text(encoding="utf-8") == "short"


def test_instructions_offer_parent_dns_host_dns_and_file():
    text = ownership.instructions("https://www.example.com/")
    assert token_for("example.com") in text
    assert token_for("www.example.com") in text
    assert "https://www.example.com/.well-known/webaudit-verify.txt" in text
    assert "all its subdomains" in text


def test_instructions_in_russian(capsys):
    assert cli.main(["https://www.example.com", "--ownership-token", "--lang", "ru"]) == 0
    output = capsys.readouterr().out
    assert "Подтверждение владения сайтом www.example.com" in output
    assert "Подтверждает домен и все его поддомены." in output
    assert token_for("example.com") in output


def test_proof_coverage():
    dns = OwnershipProof(True, "dns", "example.com")
    assert dns.covers("example.com") and dns.covers("shop.example.com")
    assert not dns.covers("evilexample.com")
    file = OwnershipProof(True, "file", "www.example.com")
    assert file.covers("WWW.example.com") and not file.covers("shop.example.com")
    assert not OwnershipProof(False).covers("example.com")


def _dns(monkeypatch, records):
    monkeypatch.setattr(
        ownership, "_resolve", lambda resolver, name, record_type: records.get(name, ())
    )


@pytest.mark.parametrize("name", ["example.com", "_webaudit.example.com"])
def test_dns_record_at_parent_verifies_subdomain(monkeypatch, name):
    _dns(monkeypatch, {name: ("unrelated", f'"{token_for("example.com")}"')})
    proof = ownership.verify_dns("shop.example.com")
    assert (proof.verified, proof.method, proof.domain) == (True, "dns", "example.com")


def test_dns_rejects_token_for_another_domain(monkeypatch):
    _dns(monkeypatch, {"example.com": (token_for("other.com"),)})
    assert not ownership.verify_dns("example.com").verified


class _Response:
    def __init__(self, status=200, body=b""):
        self.status_code = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start : start + chunk_size]


def _http(monkeypatch, response, addresses=("93.184.216.34",)):
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return response

    monkeypatch.setattr(ownership.requests, "get", get)
    monkeypatch.setattr(
        ownership,
        "resolve_target_addresses",
        lambda target: {ipaddress.ip_address(a) for a in addresses},
    )
    return calls


def test_file_proof_verifies_exact_host_without_redirects(monkeypatch):
    calls = _http(monkeypatch, _Response(body=f"\n{token_for('www.example.com')}\n".encode()))
    proof = ownership.verify_file("https://www.example.com/shop")
    assert (proof.verified, proof.method, proof.domain) == (True, "file", "www.example.com")
    ((url, kwargs),) = calls
    assert url == "https://www.example.com/.well-known/webaudit-verify.txt"
    assert kwargs["allow_redirects"] is False


@pytest.mark.parametrize(
    "response",
    [
        _Response(status=301),
        _Response(status=404),
        _Response(body=b"webaudit-verify=0000"),
    ],
)
def test_file_proof_rejections(monkeypatch, response):
    _http(monkeypatch, response)
    assert not ownership.verify_file("https://example.com").verified


def test_file_proof_reads_only_the_first_kilobytes(monkeypatch):
    body = b"x" * 5000 + b"\n" + token_for("example.com").encode()
    _http(monkeypatch, _Response(body=body))
    assert not ownership.verify_file("https://example.com").verified


def test_file_proof_never_fetches_private_addresses(monkeypatch):
    calls = _http(
        monkeypatch, _Response(body=token_for("intranet.example").encode()), ("10.0.0.5",)
    )
    proof = ownership.verify_file("https://intranet.example")
    assert not proof.verified and "non-public" in proof.detail
    assert calls == []
    assert ownership.verify_file("https://intranet.example", allow_private=True).verified


def test_verify_prefers_dns_then_file(monkeypatch):
    _dns(monkeypatch, {})
    _http(monkeypatch, _Response(body=token_for("example.com").encode()))
    assert ownership.verify("https://example.com").method == "file"
    _dns(monkeypatch, {"example.com": (token_for("example.com"),)})
    assert ownership.verify("https://example.com").method == "dns"


def test_cli_prints_token_without_authorization_flag(capsys):
    assert cli.main(["https://www.example.com", "--ownership-token"]) == 0
    output = capsys.readouterr().out
    assert token_for("example.com") in output
    assert str(ownership.key_path()) in output


@pytest.mark.parametrize(("verified", "code"), [(True, 0), (False, 1)])
def test_cli_verify_ownership_exit_codes(monkeypatch, capsys, verified, code):
    monkeypatch.setattr(
        cli.ownership,
        "verify",
        lambda target, **kwargs: OwnershipProof(verified, "dns", "example.com", "TXT record"),
    )
    assert cli.main(["example.com", "--verify-ownership"]) == code


class _Scanner:
    created = 0

    def __init__(self, settings, proxy=None):
        _Scanner.created += 1

    def scan_target(self, target, progress_callback=None):
        return [
            CheckResult(
                url=target + "/", status=200, size=0, elapsed_ms=1.0, scanned_at=datetime.now(UTC)
            )
        ]


def _scan(monkeypatch, tmp_path, proof, *extra):
    _Scanner.created = 0
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    monkeypatch.setattr(cli, "Scanner", _Scanner)
    monkeypatch.setattr(cli.ownership, "verify", lambda target, **kwargs: proof)
    return cli.main(
        [
            "https://shop.example.com",
            "--yes-i-am-authorized",
            "--paths",
            "/",
            "--no-dns",
            "--lang",
            "ru",
            "--output-dir",
            str(tmp_path),
            *extra,
        ]
    )


def test_require_ownership_blocks_unverified_scan(monkeypatch, tmp_path, capsys):
    code = _scan(
        monkeypatch, tmp_path, OwnershipProof(False, detail="No TXT."), "--require-ownership"
    )
    assert code == 2
    assert _Scanner.created == 0
    assert "Refusing to scan" in capsys.readouterr().out


def test_require_ownership_from_config(monkeypatch, tmp_path):
    config = tmp_path / "web-audit.toml"
    config.write_text("[scan]\nrequire_ownership = true\n", encoding="utf-8")
    code = _scan(monkeypatch, tmp_path, OwnershipProof(False), "--config", str(config))
    assert code == 2 and _Scanner.created == 0


def test_verified_scan_mentions_ownership_in_owner_report(monkeypatch, tmp_path):
    proof = OwnershipProof(True, "dns", "example.com", "TXT record at example.com")
    assert _scan(monkeypatch, tmp_path, proof, "--require-ownership") == 0
    (page,) = [p.read_text(encoding="utf-8") for p in tmp_path.glob("owner-report-*.html")]
    assert "Владение сайтом подтверждено: DNS-запись (example.com)" in page


def test_scan_without_requirement_does_not_verify(monkeypatch, tmp_path):
    def fail(target, **kwargs):
        raise AssertionError("ownership should not be checked")

    monkeypatch.setattr(cli.ownership, "verify", fail)
    monkeypatch.setattr(cli, "resolve_target_addresses", lambda target: set())
    monkeypatch.setattr(cli, "Scanner", _Scanner)
    code = cli.main(
        ["https://example.com", "--yes-i-am-authorized", "--paths", "/", "--no-dns"]
        + ["--output-dir", str(tmp_path)]
    )
    assert code == 0
