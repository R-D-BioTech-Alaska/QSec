from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qsec.attestation import ArtifactBinding, AttestationManifest, AttestationPolicy, AttestationVerifier, HMACAttestor
from qsec.governance import ActionGovernor, ActionRequest, ActionRisk, ApprovalSigner, GovernancePolicy
from qsec.pulse import PulsePolicy, PulseSchedule, PulseSegment, inspect_pulse_schedule
from qsec.qec import QECPolicy, StabilizerCode, SyndromeEvidence, syndrome_for_error, verify_syndrome_evidence
from qsec.scenarios import run_controlled_scenarios
from qsec.thermal import ThermalPolicy, ThermalSample, inspect_thermal_telemetry


def rate(iterations, function):
    start = perf_counter()
    for _ in range(iterations):
        function()
    elapsed = perf_counter() - start
    return {"iterations": iterations, "seconds": elapsed, "operations_per_second": iterations / elapsed}


def main():
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    key = b"attestation-key-material-32-bytes"
    artifact = ArtifactBinding.from_bytes("runtime.bin", "runtime", b"runtime")
    manifest = AttestationManifest.issue("backend", "backend", "root", "nonce", 1, (artifact,), policy_digest="policy", now=now)
    signed = HMACAttestor("root", key).sign(manifest)
    verifier = AttestationVerifier({"root": key}, AttestationPolicy(allowed_issuers=("root",), allowed_subject_kinds=("backend",), require_policy_digest=True))
    verify_attestation = lambda: verifier.verify(signed, now=now, expected_nonce="nonce", expected_policy_digest="policy", artifact_bytes={"runtime.bin": b"runtime"})

    pulse = PulseSchedule("backend", 1e-9, (PulseSegment("d0", 0.0, 0.1, 0.2, shape="sampled", samples=(0.0, 0.1, 0.0)),))
    pulse_policy = PulsePolicy(allowed_channels=("d0",), maximum_duration=1.0, maximum_schedule_duration=1.0, maximum_duty_cycle=1.0, maximum_control_energy=1.0)
    verify_pulse = lambda: inspect_pulse_schedule(pulse, pulse, pulse_policy)

    code = StabilizerCode("bit-flip", ("ZZI", "IZZ"))
    syndrome = syndrome_for_error(code.stabilizers, "XII")
    evidence = SyndromeEvidence(code.digest, 1, "nonce", syndrome, "XII", "XII", syndrome, (("a", "XII"), ("b", "XII")), "previous")
    verify_qec = lambda: verify_syndrome_evidence(code, evidence, expected_nonce="nonce", minimum_round=1, expected_previous_digest="previous", policy=QECPolicy(minimum_decoder_votes=2))

    governance_policy = GovernancePolicy(allowed_actors=("runtime",), allowed_actions=("promote",), allowed_resource_prefixes=("model://",), allowed_scopes=("promote",), quorum_high=2)
    request = ActionRequest.issue("r", "runtime", "promote", "model://candidate", ("promote",), ActionRisk.HIGH, "nonce", policy_digest=governance_policy.digest, attestation_digest="attested", now=now)
    keys = {"a": b"approval-key-a-material-32-bytes", "b": b"approval-key-b-material-32-bytes"}
    approvals = (ApprovalSigner("a", keys["a"]).sign(request, "a", "safety", now=now), ApprovalSigner("b", keys["b"]).sign(request, "b", "operator", now=now))
    governor = ActionGovernor(keys, governance_policy)
    authorize = lambda: governor.authorize(request, approvals, now=now, expected_nonce="nonce", attestation_valid=True)

    thermal_policy = ThermalPolicy(3.0, 6.0, 0.5, 0.5, 10.0, 4.0, maximum_first_law_residual=0.25)
    samples = (ThermalSample(now.isoformat(), 4.0, 2.0, 1.0), ThermalSample((now + timedelta(seconds=1)).isoformat(), 4.1, 2.0, 1.0))
    verify_thermal = lambda: inspect_thermal_telemetry(samples, thermal_policy)

    results = {
        "schema_version": "qsec.trust-mesh-benchmark.v1",
        "attestation_verification": rate(5000, verify_attestation),
        "pulse_verification": rate(5000, verify_pulse),
        "qec_verification": rate(5000, verify_qec),
        "action_authorization": rate(3000, authorize),
        "thermal_verification": rate(5000, verify_thermal),
        "controlled_scenarios": run_controlled_scenarios(now),
    }
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
