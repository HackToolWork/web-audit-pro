from __future__ import annotations

from dataclasses import dataclass

import dns.exception
import dns.resolver

from .models import Finding

_TAKEOVER_SUFFIXES = (
    "github.io",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudfront.net",
    "fastly.net",
    "unbouncepages.com",
    "readthedocs.io",
    "pantheon.io",
    "zendesk.com",
)


@dataclass(frozen=True, slots=True)
class DNSReport:
    host: str
    a: tuple[str, ...]
    aaaa: tuple[str, ...]
    mx: tuple[str, ...]
    txt: tuple[str, ...]
    spf: tuple[str, ...]
    cname: tuple[str, ...]


def _decode_dns_part(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _flatten_dns_text(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return "".join(_flatten_dns_text(part) for part in value)
    return _decode_dns_part(value)


def _render_dns_value(value: object, record_type: str) -> str:
    """Normalize dnspython RDATA into a stable text representation.

    TXT RDATA is particularly important here: dnspython exposes it as a TXT
    object whose ``strings`` attribute contains one or more byte strings.
    Test doubles and custom resolver adapters may instead return a list/tuple.
    We flatten all of those forms before any string processing such as
    ``lower()`` is attempted.
    """
    if record_type != "TXT":
        return str(value).rstrip(".")

    strings = getattr(value, "strings", None)
    if strings is not None:
        return _flatten_dns_text(strings)

    return _flatten_dns_text(value)


def _is_spf_record(value: str) -> bool:
    """Return whether a normalized TXT value starts with an SPF policy."""
    normalized = value.strip().strip('"').strip()
    return normalized.lower().startswith("v=spf1")


def _resolve(resolver: dns.resolver.Resolver, name: str, record_type: str) -> tuple[str, ...]:
    try:
        answers = resolver.resolve(name, record_type, lifetime=3.0)
        values = (_render_dns_value(value, record_type).strip() for value in answers)
        return tuple(sorted(dict.fromkeys(values)))
    except (dns.exception.DNSException, OSError):
        return ()


def inspect_domain(host: str) -> DNSReport:
    resolver = dns.resolver.Resolver()
    a = _resolve(resolver, host, "A")
    aaaa = _resolve(resolver, host, "AAAA")
    mx = _resolve(resolver, host, "MX")
    txt = _resolve(resolver, host, "TXT")
    spf = tuple(value for value in txt if _is_spf_record(value))
    cname = _resolve(resolver, host, "CNAME")
    return DNSReport(host, a, aaaa, mx, txt, spf, cname)


def findings(report: DNSReport) -> tuple[Finding, ...]:
    out: list[Finding] = []
    if len(report.spf) > 1:
        out.append(
            Finding(
                "dns.spf.multiple",
                "Multiple SPF records are published",
                "medium",
                "dns",
                f"Found {len(report.spf)} SPF TXT records.",
                (
                    "Publish one valid SPF policy; multiple SPF records can cause "
                    "SPF evaluation errors."
                ),
            )
        )
    for spf in report.spf:
        if "+all" in spf.lower():
            out.append(
                Finding(
                    "dns.spf.permissive_all",
                    "SPF policy permits all senders",
                    "medium",
                    "email_security",
                    f"SPF: {spf}",
                    "Replace a permissive all-mechanism with an explicit authorized-sender policy.",
                )
            )
        elif "?all" in spf.lower():
            out.append(
                Finding(
                    "dns.spf.neutral_all",
                    "SPF ends with a neutral all-mechanism",
                    "low",
                    "email_security",
                    f"SPF: {spf}",
                    "Review whether the SPF policy should explicitly fail unauthorized senders.",
                )
            )
    if not report.spf:
        out.append(
            Finding(
                "dns.spf.missing",
                "SPF record was not found",
                "low",
                "email_security",
                "No TXT record beginning with v=spf1 was resolved for the host.",
                "Publish SPF if the domain sends email and maintain it with the organization’s "
                "mail providers.",
                confidence="medium",
            )
        )
    if report.cname and not report.a and not report.aaaa:
        for target in report.cname:
            target_lower = target.lower()
            if any(target_lower.endswith(suffix) for suffix in _TAKEOVER_SUFFIXES):
                out.append(
                    Finding(
                        "dns.cname.potential_takeover",
                        "Potential dangling third-party CNAME",
                        "medium",
                        "dns_takeover",
                        f"CNAME {report.host} -> {target} without A/AAAA resolution.",
                        "Confirm the service is still claimed by the organization before "
                        "changing DNS; do not rely on this observation alone as proof of takeover.",
                        confidence="low",
                    )
                )
                break
    return tuple(out)
