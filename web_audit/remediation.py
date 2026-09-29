from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from .identity import FindingIdentity
from .lifecycle import FindingObservation

VerificationState = Literal["fixed"]


@dataclass(frozen=True, slots=True)
class RemediationProof:
    """Immutable proof that a previously observed finding was fixed."""

    identity: FindingIdentity
    target: str
    location: str
    previous_scan_id: int
    verification_scan_id: int
    previous_severity: str
    verification_state: VerificationState
    evidence_digest: str

    @property
    def key(self) -> str:
        """Return a deterministic identifier for this proof."""
        return json.dumps(
            {
                "identity": self.identity.key,
                "previous_scan_id": self.previous_scan_id,
                "verification_scan_id": self.verification_scan_id,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def _evidence_payload(observation: FindingObservation) -> dict[str, object]:
    finding = observation.finding

    return {
        "identity": observation.identity.key,
        "finding": {
            "category": finding.category,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "title": finding.title,
        },
    }


def observation_evidence_digest(observation: FindingObservation) -> str:
    """Return a deterministic digest of one finding observation."""
    payload = json.dumps(
        _evidence_payload(observation),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def build_remediation_proof(
    previous: FindingObservation | None,
    current: FindingObservation | None,
    *,
    previous_scan_id: int,
    verification_scan_id: int,
) -> RemediationProof:
    """Build proof that a previously observed finding is now absent."""
    if previous is None:
        raise ValueError("remediation proof requires a previous observation")

    if current is not None:
        raise ValueError("remediation proof requires the finding to be absent during verification")

    if previous_scan_id < 1:
        raise ValueError("previous_scan_id must be >= 1")

    if verification_scan_id < 1:
        raise ValueError("verification_scan_id must be >= 1")

    if verification_scan_id <= previous_scan_id:
        raise ValueError("verification_scan_id must be greater than previous_scan_id")

    return RemediationProof(
        identity=previous.identity,
        target=previous.identity.target,
        location=previous.identity.location,
        previous_scan_id=previous_scan_id,
        verification_scan_id=verification_scan_id,
        previous_severity=previous.finding.severity,
        verification_state="fixed",
        evidence_digest=observation_evidence_digest(previous),
    )
