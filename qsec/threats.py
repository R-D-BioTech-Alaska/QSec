from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class ThreatDefinition:
    code: str
    name: str
    layer: str
    description: str
    techniques: Tuple[str, ...]
    evidence: Tuple[str, ...]


THREATS: Dict[str, ThreatDefinition] = {
    "phaseworm": ThreatDefinition(
        "QSEC-PHASE-001",
        "Phaseworm",
        "state and circuit",
        "Self-propagating malicious logic that exploits or changes relative phase.",
        ("Phase Injection", "Amplitude Steering", "Circuit Splicing"),
        ("unexpected phase deltas", "repeated propagation path", "circuit or pulse residue"),
    ),
    "shadow_circuit": ThreatDefinition(
        "QSEC-CIRCUIT-001",
        "Shadow Circuit",
        "circuit",
        "Unauthorized gates or branches concealed inside an approved circuit.",
        ("Gate Grafting", "Circuit Splicing", "Transpiler Grafting"),
        ("manifest mismatch", "unapproved gate", "depth or topology change"),
    ),
    "state_leech": ThreatDefinition(
        "QSEC-STATE-002",
        "State Leech",
        "state and side channel",
        "Repeatedly extracts information from preparation, leakage, or physical side channels.",
        ("State Probing", "Preparation Replay", "Leakage Correlation"),
        ("repeated preparation access", "correlated leakage", "unauthorized sampling"),
    ),
    "collapseware": ThreatDefinition(
        "QSEC-MEASURE-001",
        "Collapseware",
        "measurement",
        "Forces premature measurement or destructive state loss.",
        ("Measurement Injection", "Basis Substitution", "Coherence Starvation"),
        ("unexpected measurement", "state lifetime collapse", "basis control change"),
    ),
    "driftroot": ThreatDefinition(
        "QSEC-CAL-001",
        "Driftroot",
        "calibration",
        "Persistent manipulation of calibration that slowly moves trusted operations.",
        ("Calibration Poisoning", "Amplitude Steering", "Phase Injection"),
        ("persistent T1/T2 drift", "detuning shift", "gate error drift"),
    ),
    "noisecloak": ThreatDefinition(
        "QSEC-NOISE-001",
        "Noisecloak",
        "noise",
        "Targeted manipulation hidden inside apparently ordinary hardware noise.",
        ("Noise Camouflage", "Pulse Tampering", "Readout Forgery"),
        ("structured residuals", "nonstationary noise", "cross-layer correlation"),
    ),
    "pulse_parasite": ThreatDefinition(
        "QSEC-PULSE-001",
        "Pulse Parasite",
        "control pulse",
        "Unauthorized modification of the physical control pulses sent to hardware.",
        ("Pulse Tampering", "Pulse Substitution", "Waveform Grafting"),
        ("waveform digest mismatch", "timing shift", "unapproved pulse segment"),
    ),
    "syndrome_forger": ThreatDefinition(
        "QSEC-QEC-001",
        "Syndrome Forger",
        "error correction",
        "Falsifies or suppresses quantum error-correction syndrome results.",
        ("Syndrome Suppression", "Syndrome Injection", "Ancilla Tampering"),
        ("syndrome inconsistency", "decoder disagreement", "ancilla correlation anomaly"),
    ),
    "entanglement_siphon": ThreatDefinition(
        "QSEC-ENT-001",
        "Entanglement Siphon",
        "entanglement and channel",
        "Uses unauthorized shared correlations to leak information or redirect trust.",
        ("Entanglement Hijacking", "Channel Splicing", "Correlation Spoofing"),
        ("monogamy violation indicator", "unexpected correlation endpoint", "Bell-test drift"),
    ),
    "oracle_mimic": ThreatDefinition(
        "QSEC-BACKEND-001",
        "Oracle Mimic",
        "backend and service",
        "Impersonates a trusted oracle, backend, simulator, compiler, or quantum service.",
        ("Backend Impersonation", "Compiler Poisoning", "Response Replay"),
        ("identity mismatch", "attestation failure", "response signature mismatch"),
    ),
    "coherence_eater": ThreatDefinition(
        "QSEC-COHERENCE-001",
        "Coherence Eater",
        "coherence",
        "Deliberately accelerates decoherence to disable or bias computation.",
        ("Coherence Starvation", "Noise Injection", "Thermal Loading"),
        ("T2 collapse", "temperature shift", "coherence loss outside baseline"),
    ),
    "state_doppelganger": ThreatDefinition(
        "QSEC-STATE-001",
        "State Doppelgänger",
        "state",
        "Substitutes an attacker-controlled state that resembles the expected state.",
        ("State Replacement", "Preparation Substitution", "State Replay"),
        ("fidelity failure", "physical invariant failure", "preparation digest mismatch"),
    ),
    "basis_trap": ThreatDefinition(
        "QSEC-BASIS-001",
        "Basis Trap",
        "measurement",
        "Manipulates basis selection to reveal information or corrupt a result.",
        ("Basis Substitution", "Basis Biasing", "Measurement Steering"),
        ("basis schedule mismatch", "basis distribution bias", "control-path residue"),
    ),
    "readout_phantom": ThreatDefinition(
        "QSEC-READOUT-001",
        "Readout Phantom",
        "readout",
        "Forges measurement output without necessarily changing the computation.",
        ("Readout Forgery", "Measurement Injection", "Result Replay"),
        ("readout matrix drift", "distribution mismatch", "signed-result failure"),
    ),
    "reset_ghost": ThreatDefinition(
        "QSEC-RESET-001",
        "Reset Ghost",
        "reset",
        "Survives or influences a reset that is expected to return a clean state.",
        ("Reset Contamination", "Thermal Persistence", "State Carryover"),
        ("post-reset excitation", "cross-job correlation", "reset verification failure"),
    ),
    "ancilla_parasite": ThreatDefinition(
        "QSEC-ANCILLA-001",
        "Ancilla Parasite",
        "ancilla",
        "Compromises helper qubits used for measurement, verification, or correction.",
        ("Ancilla Tampering", "Syndrome Injection", "Correlation Redirection"),
        ("ancilla preparation failure", "unexpected entanglement", "syndrome inconsistency"),
    ),
    "channel_splice": ThreatDefinition(
        "QSEC-CHANNEL-001",
        "Channel Splice",
        "communication channel",
        "Inserts an unauthorized endpoint into a trusted classical or quantum channel.",
        ("Channel Splicing", "Endpoint Substitution", "Entanglement Hijacking"),
        ("endpoint identity mismatch", "channel attestation failure", "unexpected correlation"),
    ),
    "correlation_forge": ThreatDefinition(
        "QSEC-CORR-001",
        "Correlation Forge",
        "correlation",
        "Manufactures false correlations that appear physically or statistically legitimate.",
        ("Correlation Spoofing", "Sample Replay", "Readout Coordination"),
        ("cross-run reuse", "impossible covariance", "independent verifier disagreement"),
    ),
    "entropy_leech": ThreatDefinition(
        "QSEC-ENTROPY-001",
        "Entropy Leech",
        "randomness",
        "Reduces, predicts, reuses, or biases a source that is expected to be random.",
        ("Entropy Biasing", "Seed Replay", "Randomness Suppression"),
        ("min-entropy loss", "bit bias", "repetition", "serial correlation"),
    ),
    "harvest_vault": ThreatDefinition(
        "QSEC-CRYPTO-001",
        "Harvest Vault",
        "cryptography and storage",
        "Collects protected data now for later decryption with stronger quantum capability.",
        ("Harvest Now Decrypt Later", "Long-Lived Ciphertext Collection"),
        ("quantum-vulnerable key exchange", "long confidentiality lifetime", "captured ciphertext"),
    ),
}


def get_threat(name: str) -> ThreatDefinition:
    key = name.strip().lower().replace(" ", "_").replace("-", "_")
    if key not in THREATS:
        raise KeyError(f"Unknown QSec threat class: {name}")
    return THREATS[key]
