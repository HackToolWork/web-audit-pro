import pytest

from web_audit import cli, tls_audit


@pytest.fixture(autouse=True)
def _offline_tls_check(monkeypatch):
    """Keep CLI tests offline: the TLS certificate check would contact real hosts.

    Tests that exercise the check replace ``cli.inspect_certificate`` themselves.
    """

    def unreachable(host, port=443, *, timeout=5.0):
        return tls_audit.CertificateReport(host, port, connect_error="offline test")

    monkeypatch.setattr(cli, "inspect_certificate", unreachable)


@pytest.fixture(autouse=True)
def _isolated_local_state(monkeypatch, tmp_path_factory):
    """Never touch a developer's WordPress vulnerability database, API key or ownership key."""
    path = tmp_path_factory.mktemp("wp-vulndb") / "wp-vulndb.json"
    monkeypatch.setenv("WEB_AUDIT_WP_VULN_DB", str(path))
    monkeypatch.setenv(
        "WEB_AUDIT_OWNERSHIP_KEY_FILE", str(tmp_path_factory.mktemp("ownership") / "ownership.key")
    )
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
