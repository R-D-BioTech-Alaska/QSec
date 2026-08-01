from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Tuple

from .attestation import ArtifactBinding, AttestationManifest, AttestationPolicy, AttestationVerifier, HMACAttestor
from .governance import ActionGovernor, ActionRequest, ActionRisk, ApprovalSigner, GovernancePolicy
from .pulse import PulsePolicy, PulseSchedule, PulseSegment, inspect_pulse_schedule
from .qec import QECPolicy, StabilizerCode, SyndromeEvidence, syndrome_for_error, verify_syndrome_evidence
from .thermal import ThermalPolicy, ThermalSample, inspect_thermal_telemetry


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    domain: str
    malicious: bool
    detected: bool
    highest_severity: str
    finding_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "domain": self.domain, "malicious": self.malicious,
            "detected": self.detected, "highest_severity": self.highest_severity,
            "finding_count": self.finding_count,
        }


def _classification(name: str, domain: str, malicious: bool, report: Any) -> ScenarioResult:
    findings = tuple(report.findings)
    detected = any(int(item.severity) >= 40 for item in findings)
    highest = max(findings, key=lambda item: int(item.severity)).severity.name.lower() if findings else "informational"
    return ScenarioResult(name, domain, malicious, detected, highest, len(findings))


def _attestation_fixture(now: datetime):
    key = b"attestation-key-material-32-bytes"
    policy = AttestationPolicy(allowed_issuers=("qsec-root",), allowed_subject_kinds=("backend",), require_policy_digest=True)
    verifier = AttestationVerifier({"root": key}, policy)
    artifact = ArtifactBinding.from_bytes("compiler.bin", "compiler", b"trusted-compiler")
    manifest = AttestationManifest.issue(
        "backend-a", "backend", "qsec-root", "challenge-1", 7, (artifact,),
        policy_digest="policy-v1", lifetime_seconds=300, now=now,
    )
    signed = HMACAttestor("root", key).sign(manifest)
    return verifier, signed, artifact


def _pulse_fixture():
    schedule = PulseSchedule("backend-a", 1e-9, (
        PulseSegment("d0", 0.0, 0.10, 0.20, phase=0.1, frequency=5.0, shape="sampled", samples=(0.0, 0.1, 0.2, 0.1, 0.0)),
        PulseSegment("d0", 0.12, 0.10, -0.15, phase=-0.2, frequency=5.0, shape="gaussian"),
    ))
    policy = PulsePolicy(
        allowed_channels=("d0",), maximum_absolute_amplitude=0.5, maximum_duration=0.2,
        maximum_schedule_duration=1.0, maximum_duty_cycle=0.95, maximum_slew_rate=20.0,
        maximum_control_energy=1.0, amplitude_tolerance=1e-5, phase_tolerance=1e-5,
    )
    return schedule, policy


def _qec_fixture():
    code = StabilizerCode("bit-flip-3", ("ZZI", "IZZ"))
    error = "XII"
    correction = "XII"
    syndrome = syndrome_for_error(code.stabilizers, error)
    evidence = SyndromeEvidence(
        code_digest=code.digest, round_index=3, nonce="qec-challenge", measured_syndrome=syndrome,
        error_witness=error, correction_witness=correction, ancilla_syndrome=syndrome,
        decoder_votes=(("decoder-a", correction), ("decoder-b", correction)), previous_round_digest="previous",
    )
    policy = QECPolicy(minimum_decoder_votes=2)
    return code, evidence, policy


def _governance_fixture(now: datetime):
    policy = GovernancePolicy(
        allowed_actors=("brain-runtime",), allowed_actions=("checkpoint.promote",),
        allowed_resource_prefixes=("model://candidate/",), allowed_scopes=("read", "promote"),
        quorum_high=2, lease_lifetime_seconds=30, lease_uses=1,
    )
    request = ActionRequest.issue(
        "request-1", "brain-runtime", "checkpoint.promote", "model://candidate/42",
        ("read", "promote"), ActionRisk.HIGH, "action-challenge", policy_digest=policy.digest,
        attestation_digest="attested", now=now,
    )
    keys = {"safety-key": b"safety-approval-key-material-32", "operator-key": b"operator-approval-key-mat-32"}
    approvals = (
        ApprovalSigner("safety-key", keys["safety-key"]).sign(request, "safety-1", "safety", now=now),
        ApprovalSigner("operator-key", keys["operator-key"]).sign(request, "operator-1", "operator", now=now),
    )
    governor = ActionGovernor(keys, policy)
    return governor, request, approvals, policy


def _thermal_fixture(now: datetime):
    policy = ThermalPolicy(
        minimum_temperature=3.0, maximum_temperature=6.0, maximum_temperature_rate=0.5,
        maximum_sensor_step=0.5, heat_capacity=10.0, ambient_temperature=4.0,
        passive_conductance=0.0, maximum_first_law_residual=0.25,
        maximum_input_power=10.0, maximum_cooling_power=10.0,
    )
    samples = (
        ThermalSample(now.isoformat(), 4.0, 2.0, 1.0),
        ThermalSample((now + timedelta(seconds=1)).isoformat(), 4.1, 2.0, 1.0),
    )
    return samples, policy


def run_controlled_scenarios(now: datetime | None = None) -> Dict[str, Any]:
    current = (now or datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)).astimezone(timezone.utc)
    results = []

    verifier, signed, artifact = _attestation_fixture(current)
    clean = verifier.verify(signed, now=current, expected_nonce="challenge-1", expected_subject_id="backend-a", expected_policy_digest="policy-v1", artifact_bytes={artifact.name: b"trusted-compiler"})
    results.append(_classification("attestation-clean", "attestation", False, clean))
    forged = replace(signed, signature="0" * 64)
    results.append(_classification("attestation-forged-signature", "attestation", True, verifier.verify(forged, now=current, expected_nonce="challenge-1", expected_policy_digest="policy-v1", artifact_bytes={artifact.name: b"trusted-compiler"})))
    results.append(_classification("attestation-artifact-substitution", "attestation", True, verifier.verify(signed, now=current, expected_nonce="challenge-1", expected_policy_digest="policy-v1", artifact_bytes={artifact.name: b"modified-compiler"})))
    results.append(_classification("attestation-context-replay", "attestation", True, verifier.verify(signed, now=current, expected_nonce="new-challenge", expected_policy_digest="policy-v1", artifact_bytes={artifact.name: b"trusted-compiler"})))

    pulse, pulse_policy = _pulse_fixture()
    results.append(_classification("pulse-clean", "pulse", False, inspect_pulse_schedule(pulse, pulse, pulse_policy)))
    segments = list(pulse.segments)
    segments[0] = replace(segments[0], amplitude=0.35)
    results.append(_classification("pulse-amplitude-steering", "pulse", True, inspect_pulse_schedule(PulseSchedule(pulse.backend_id, pulse.clock_period, tuple(segments)), pulse, pulse_policy)))
    segments = list(pulse.segments)
    segments[0] = replace(segments[0], phase=0.4)
    results.append(_classification("pulse-phase-injection", "pulse", True, inspect_pulse_schedule(PulseSchedule(pulse.backend_id, pulse.clock_period, tuple(segments)), pulse, pulse_policy)))
    segments = pulse.segments + (PulseSegment("d0", 0.24, 0.05, 0.1),)
    results.append(_classification("pulse-waveform-grafting", "pulse", True, inspect_pulse_schedule(PulseSchedule(pulse.backend_id, pulse.clock_period, segments), pulse, pulse_policy)))

    code, evidence, qec_policy = _qec_fixture()
    clean_qec = verify_syndrome_evidence(code, evidence, expected_nonce="qec-challenge", minimum_round=3, expected_previous_digest="previous", policy=qec_policy)
    results.append(_classification("qec-clean", "qec", False, clean_qec))
    results.append(_classification("qec-syndrome-injection", "qec", True, verify_syndrome_evidence(code, replace(evidence, measured_syndrome=(0, 0)), expected_nonce="qec-challenge", minimum_round=3, expected_previous_digest="previous", policy=qec_policy)))
    results.append(_classification("qec-ancilla-tampering", "qec", True, verify_syndrome_evidence(code, replace(evidence, ancilla_syndrome=(0, 0)), expected_nonce="qec-challenge", minimum_round=3, expected_previous_digest="previous", policy=qec_policy)))
    results.append(_classification("qec-decoder-disagreement", "qec", True, verify_syndrome_evidence(code, replace(evidence, decoder_votes=(("decoder-a", "XII"), ("decoder-b", "IIX"))), expected_nonce="qec-challenge", minimum_round=3, expected_previous_digest="previous", policy=qec_policy)))

    governor, request, approvals, governance_policy = _governance_fixture(current)
    clean_governance = governor.authorize(request, approvals, now=current, expected_nonce="action-challenge", attestation_valid=True)
    results.append(_classification("governance-clean", "governance", False, clean_governance))
    bad_approval = replace(approvals[0], signature="f" * 64)
    results.append(_classification("governance-approval-forgery", "governance", True, governor.authorize(request, (bad_approval, approvals[1]), now=current, expected_nonce="action-challenge", attestation_valid=True)))
    escalated = ActionRequest.issue(
        "request-2", "brain-runtime", "checkpoint.promote", "model://candidate/42",
        ("read", "promote", "admin"), ActionRisk.HIGH, "action-challenge", policy_digest=governance_policy.digest,
        attestation_digest="attested", now=current,
    )
    escalated_approvals = (
        ApprovalSigner("safety-key", governor.keys["safety-key"]).sign(escalated, "safety-1", "safety", now=current),
        ApprovalSigner("operator-key", governor.keys["operator-key"]).sign(escalated, "operator-1", "operator", now=current),
    )
    results.append(_classification("governance-scope-escalation", "governance", True, governor.authorize(escalated, escalated_approvals, now=current, expected_nonce="action-challenge", attestation_valid=True)))

    samples, thermal_policy = _thermal_fixture(current)
    results.append(_classification("thermal-clean", "thermal", False, inspect_thermal_telemetry(samples, thermal_policy)))
    tampered = (samples[0], replace(samples[1], temperature=5.5))
    results.append(_classification("thermal-energy-inconsistency", "thermal", True, inspect_thermal_telemetry(tampered, thermal_policy)))

    true_positive = sum(item.malicious and item.detected for item in results)
    true_negative = sum((not item.malicious) and (not item.detected) for item in results)
    false_negative = sum(item.malicious and not item.detected for item in results)
    false_positive = sum((not item.malicious) and item.detected for item in results)
    malicious_count = true_positive + false_negative
    benign_count = true_negative + false_positive
    return {
        "scenario_count": len(results), "malicious_scenarios": malicious_count, "benign_controls": benign_count,
        "true_positive": true_positive, "true_negative": true_negative, "false_positive": false_positive,
        "false_negative": false_negative,
        "recall": true_positive / malicious_count if malicious_count else 0.0,
        "specificity": true_negative / benign_count if benign_count else 0.0,
        "precision": true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0,
        "results": [item.to_dict() for item in results],
    }
