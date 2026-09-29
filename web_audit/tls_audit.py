from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from .models import Finding

EXPIRY_HIGH_DAYS = 14
EXPIRY_MEDIUM_DAYS = 30


@dataclass(frozen=True, slots=True)
class CertificateReport:
    host: str
    port: int
    not_after: datetime | None = None
    # Certificate validation failure reported by the TLS stack (expired,
    # hostname mismatch, untrusted issuer). Connection failures are kept
    # separate because they say nothing about the certificate itself.
    verify_error: str = ""
    connect_error: str = ""


def inspect_certificate(host: str, port: int = 443, *, timeout: float = 5.0) -> CertificateReport:
    """Perform one verified TLS handshake and read the leaf certificate expiry."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        return CertificateReport(host, port, verify_error=exc.verify_message or str(exc))
    except (OSError, ssl.SSLError) as exc:
        return CertificateReport(host, port, connect_error=f"{type(exc).__name__}: {exc}")

    not_after_text = cert.get("notAfter")
    if not isinstance(not_after_text, str):
        return CertificateReport(host, port, connect_error="Certificate has no notAfter field.")
    try:
        not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after_text), UTC)
    except ValueError:
        return CertificateReport(
            host, port, connect_error=f"Unparseable notAfter: {not_after_text}"
        )
    return CertificateReport(host, port, not_after=not_after)


def findings(report: CertificateReport, *, now: datetime | None = None) -> tuple[Finding, ...]:
    if report.connect_error:
        return ()
    endpoint = f"{report.host}:{report.port}"
    if report.verify_error:
        expired = "expired" in report.verify_error.lower()
        return (
            Finding(
                "tls.certificate_expired" if expired else "tls.certificate_invalid",
                "TLS certificate has expired" if expired else "TLS certificate failed validation",
                "high",
                "tls",
                f"{endpoint}: {report.verify_error}",
                "Renew or replace the certificate so browsers trust the site; enable automatic "
                "renewal (for example, Let's Encrypt with certbot or the hosting panel).",
            ),
        )
    if report.not_after is None:
        return ()

    now = now or datetime.now(UTC)
    days_left = (report.not_after - now).total_seconds() / 86400
    expires = report.not_after.strftime("%Y-%m-%d")
    if days_left < 0:
        return (
            Finding(
                "tls.certificate_expired",
                "TLS certificate has expired",
                "high",
                "tls",
                f"{endpoint}: certificate expired on {expires}.",
                "Renew the certificate and enable automatic renewal.",
            ),
        )
    if days_left <= EXPIRY_MEDIUM_DAYS:
        return (
            Finding(
                "tls.certificate_expiring",
                "TLS certificate expires soon",
                "high" if days_left <= EXPIRY_HIGH_DAYS else "medium",
                "tls",
                f"{endpoint}: certificate expires on {expires} ({int(days_left)} day(s) left).",
                "Renew the certificate before it expires and confirm automatic renewal works.",
            ),
        )
    return ()
