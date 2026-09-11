import pytest

from web_audit.identity import build_finding_identity
from web_audit.lifecycle import FindingObservation
from web_audit.models import Finding
from web_audit.remediation import (
    build_remediation_proof,
    observation_evidence_digest,
)


def make_observation(
    *,
    rule_id: str = "headers.csp",
    severity: str = "low",
    evidence: str = "missing",
) -> FindingObservation:
    finding = Finding(
        rule_id=rule_id,
        title="CSP",
        severity=severity,
        category="headers",
        evidence=evidence,
        recommendation="Add CSP",
        confidence="high",
    )

    identity = build_finding_identity(
        finding,
        target="https://example.com",
        location="https://example.com/",
    )

    return FindingObservation(
        identity=identity,
        finding=finding,
    )


def test_build_remediation_proof_for_fixed_finding():
    previous = make_observation()

    proof = build_remediation_proof(
        previous,
        None,
        previous_scan_id=10,
        verification_scan_id=11,
    )

    assert proof.identity == previous.identity
    assert proof.target == "https://example.com/"
    assert proof.location == "https://example.com/"
    assert proof.previous_scan_id == 10
    assert proof.verification_scan_id == 11
    assert proof.previous_severity == "low"
    assert proof.verification_state == "fixed"
    assert len(proof.evidence_digest) == 64


def test_same_observation_produces_same_digest():
    first = make_observation()
    second = make_observation()

    assert observation_evidence_digest(first) == observation_evidence_digest(second)


def test_evidence_change_changes_digest():
    previous = make_observation(evidence="missing")
    changed = make_observation(evidence="different evidence")

    assert observation_evidence_digest(previous) != observation_evidence_digest(changed)


def test_severity_change_changes_digest():
    low = make_observation(severity="low")
    medium = make_observation(severity="medium")

    assert observation_evidence_digest(low) != observation_evidence_digest(medium)


def test_present_finding_cannot_create_remediation_proof():
    previous = make_observation()
    current = make_observation()

    with pytest.raises(
        ValueError,
        match="finding to be absent",
    ):
        build_remediation_proof(
            previous,
            current,
            previous_scan_id=10,
            verification_scan_id=11,
        )


def test_missing_previous_observation_cannot_create_proof():
    with pytest.raises(
        ValueError,
        match="previous observation",
    ):
        build_remediation_proof(
            None,
            None,
            previous_scan_id=10,
            verification_scan_id=11,
        )


def test_verification_scan_must_be_newer():
    previous = make_observation()

    with pytest.raises(
        ValueError,
        match="greater than previous_scan_id",
    ):
        build_remediation_proof(
            previous,
            None,
            previous_scan_id=11,
            verification_scan_id=11,
        )


def test_scan_ids_must_be_positive():
    previous = make_observation()

    with pytest.raises(
        ValueError,
        match="previous_scan_id",
    ):
        build_remediation_proof(
            previous,
            None,
            previous_scan_id=0,
            verification_scan_id=1,
        )

    with pytest.raises(
        ValueError,
        match="verification_scan_id",
    ):
        build_remediation_proof(
            previous,
            None,
            previous_scan_id=1,
            verification_scan_id=0,
        )


def test_proof_key_is_deterministic():
    previous = make_observation()

    first = build_remediation_proof(
        previous,
        None,
        previous_scan_id=10,
        verification_scan_id=11,
    )
    second = build_remediation_proof(
        previous,
        None,
        previous_scan_id=10,
        verification_scan_id=11,
    )

    assert first.key == second.key
