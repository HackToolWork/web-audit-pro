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
    dmarc: tuple[str, ...] = ()
    dmarc_domain: str = ""
    # Domains where ``spf`` and ``mx`` were found. They differ from ``host`` when
    # the host (for example ``www.example.com``) inherits its parent's mail setup.
    spf_domain: str = ""
    mx_domain: str = ""


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


def _is_dmarc_record(value: str) -> bool:
    normalized = value.strip().strip('"').strip()
    return normalized.lower().replace(" ", "").startswith("v=dmarc1")


def _dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.strip().strip('"').split(";"):
        name, sep, value = part.partition("=")
        if sep:
            tags.setdefault(name.strip().lower(), value.strip())
    return tags


def _parent_candidates(host: str) -> tuple[str, ...]:
    """Return the host and its parent domains, most specific first.

    Web hosts such as ``www.example.com`` usually rely on the organizational
    domain's mail setup, and DMARC receivers apply its policy when a subdomain
    has none. Without a public-suffix list we stop at two labels.
    """
    labels = host.rstrip(".").lower().split(".")
    return tuple(".".join(labels[index:]) for index in range(max(len(labels) - 1, 1)))


def _resolve(resolver: dns.resolver.Resolver, name: str, record_type: str) -> tuple[str, ...]:
    try:
        answers = resolver.resolve(name, record_type, lifetime=3.0)
        values = (_render_dns_value(value, record_type).strip() for value in answers)
        return tuple(sorted(dict.fromkeys(values)))
    except (dns.exception.DNSException, OSError):
        return ()


def _first_match(resolve, candidates: tuple[str, ...]) -> tuple[tuple[str, ...], str]:
    for candidate in candidates:
        records = resolve(candidate)
        if records:
            return records, candidate
    return (), ""


def inspect_domain(host: str) -> DNSReport:
    resolver = dns.resolver.Resolver()
    candidates = _parent_candidates(host)
    a = _resolve(resolver, host, "A")
    aaaa = _resolve(resolver, host, "AAAA")
    txt = _resolve(resolver, host, "TXT")
    cname = _resolve(resolver, host, "CNAME")

    def txt_at(name: str) -> tuple[str, ...]:
        return txt if name == candidates[0] else _resolve(resolver, name, "TXT")

    mx, mx_domain = _first_match(lambda name: _resolve(resolver, name, "MX"), candidates)
    spf, spf_domain = _first_match(
        lambda name: tuple(value for value in txt_at(name) if _is_spf_record(value)), candidates
    )
    dmarc, dmarc_domain = _first_match(
        lambda name: tuple(
            value
            for value in _resolve(resolver, f"_dmarc.{name}", "TXT")
            if _is_dmarc_record(value)
        ),
        candidates,
    )
    return DNSReport(host, a, aaaa, mx, txt, spf, cname, dmarc, dmarc_domain, spf_domain, mx_domain)


def _dmarc_findings(report: DNSReport) -> list[Finding]:
    if not report.dmarc:
        return [
            Finding(
                "dns.dmarc.missing",
                "DMARC policy was not found",
                "medium" if report.mx else "low",
                "email_security",
                f"No v=DMARC1 TXT record was resolved at _dmarc.{report.host} "
                "or its parent domain.",
                "Publish a DMARC record (start with p=none and a rua= reporting address, then "
                "move to p=quarantine or p=reject) so others cannot easily send email that "
                "impersonates the domain.",
                confidence="medium",
            )
        ]
    evidence_prefix = f"_dmarc.{report.dmarc_domain}"
    if len(report.dmarc) > 1:
        return [
            Finding(
                "dns.dmarc.multiple",
                "Multiple DMARC records are published",
                "medium",
                "email_security",
                f"Found {len(report.dmarc)} DMARC records at {evidence_prefix}.",
                "Publish exactly one DMARC record; receivers ignore DMARC when several exist.",
            )
        ]
    record = report.dmarc[0]
    policy = _dmarc_tags(record).get("p", "").lower()
    if policy not in {"none", "quarantine", "reject"}:
        return [
            Finding(
                "dns.dmarc.invalid_policy",
                "DMARC record has no valid policy",
                "medium",
                "email_security",
                f"{evidence_prefix}: {record}",
                "Set the p= tag to none, quarantine, or reject.",
            )
        ]
    if policy == "none":
        return [
            Finding(
                "dns.dmarc.monitor_only",
                "DMARC policy only monitors spoofed email",
                "low",
                "email_security",
                f"{evidence_prefix}: {record}",
                "After reviewing DMARC reports, move to p=quarantine or p=reject so "
                "receivers stop delivering email that fails authentication.",
            )
        ]
    return []


def findings(report: DNSReport) -> tuple[Finding, ...]:
    out: list[Finding] = []
    if len(report.spf) > 1:
        out.append(
            Finding(
                "dns.spf.multiple",
                "Multiple SPF records are published",
                "medium",
                "dns",
                f"Found {len(report.spf)} SPF TXT records at {report.spf_domain or report.host}.",
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
                "No TXT record beginning with v=spf1 was resolved for the host or its parent "
                "domain.",
                "Publish SPF if the domain sends email and maintain it with the organization’s "
                "mail providers.",
                confidence="medium",
            )
        )
    out.extend(_dmarc_findings(report))
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
