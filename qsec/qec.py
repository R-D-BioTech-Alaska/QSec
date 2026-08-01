from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

import numpy as np

from .model import Finding, FindingStatus, Severity
from .trust import canonical_json, make_finding, sha256_bytes


_PAULI_BITS = {"I": (0, 0), "X": (1, 0), "Y": (1, 1), "Z": (0, 1)}


def pauli_to_symplectic(pauli: str) -> np.ndarray:
    text = pauli.strip().upper().replace(" ", "")
    if not text or any(ch not in _PAULI_BITS for ch in text):
        raise ValueError("Pauli strings must contain only I, X, Y, and Z")
    x = [_PAULI_BITS[ch][0] for ch in text]
    z = [_PAULI_BITS[ch][1] for ch in text]
    return np.asarray(x + z, dtype=np.uint8)


def symplectic_product(left: np.ndarray, right: np.ndarray) -> int:
    if left.shape != right.shape or left.ndim != 1 or left.size % 2:
        raise ValueError("symplectic vectors must have equal even length")
    n = left.size // 2
    return int((np.dot(left[:n], right[n:]) + np.dot(left[n:], right[:n])) % 2)


def syndrome_for_error(stabilizers: Sequence[str], error: str) -> Tuple[int, ...]:
    error_vector = pauli_to_symplectic(error)
    result = []
    for stabilizer in stabilizers:
        vector = pauli_to_symplectic(stabilizer)
        if vector.size != error_vector.size:
            raise ValueError("stabilizers and error must act on the same number of qubits")
        result.append(symplectic_product(vector, error_vector))
    return tuple(result)


def combine_paulis(left: str, right: str) -> str:
    if len(left) != len(right):
        raise ValueError("Pauli strings must have equal length")
    table = {
        ("I", "I"): "I", ("I", "X"): "X", ("I", "Y"): "Y", ("I", "Z"): "Z",
        ("X", "I"): "X", ("X", "X"): "I", ("X", "Y"): "Z", ("X", "Z"): "Y",
        ("Y", "I"): "Y", ("Y", "X"): "Z", ("Y", "Y"): "I", ("Y", "Z"): "X",
        ("Z", "I"): "Z", ("Z", "X"): "Y", ("Z", "Y"): "X", ("Z", "Z"): "I",
    }
    return "".join(table[(a.upper(), b.upper())] for a, b in zip(left, right))


@dataclass(frozen=True)
class StabilizerCode:
    name: str
    stabilizers: Tuple[str, ...]

    def __post_init__(self):
        if not self.name or not self.stabilizers:
            raise ValueError("code name and stabilizers are required")
        width = len(self.stabilizers[0])
        vectors = [pauli_to_symplectic(item) for item in self.stabilizers]
        if any(len(item) != width for item in self.stabilizers):
            raise ValueError("all stabilizers must have the same width")
        for i, left in enumerate(vectors):
            for right in vectors[i + 1:]:
                if symplectic_product(left, right):
                    raise ValueError("stabilizer generators must commute")

    @property
    def qubits(self) -> int:
        return len(self.stabilizers[0])

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json({"name": self.name, "stabilizers": list(self.stabilizers)}))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StabilizerCode":
        return cls(str(data["name"]), tuple(str(item).upper() for item in data["stabilizers"]))


@dataclass(frozen=True)
class SyndromeEvidence:
    code_digest: str
    round_index: int
    nonce: str
    measured_syndrome: Tuple[int, ...]
    error_witness: Optional[str] = None
    correction_witness: Optional[str] = None
    ancilla_syndrome: Tuple[int, ...] = ()
    decoder_votes: Tuple[Tuple[str, str], ...] = ()
    previous_round_digest: Optional[str] = None

    def __post_init__(self):
        if self.round_index < 0 or not self.nonce:
            raise ValueError("round_index must be nonnegative and nonce is required")
        if any(bit not in (0, 1) for bit in self.measured_syndrome + self.ancilla_syndrome):
            raise ValueError("syndrome values must be binary")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SyndromeEvidence":
        votes = data.get("decoder_votes", {})
        if isinstance(votes, Mapping):
            votes_tuple = tuple(sorted((str(k), str(v).upper()) for k, v in votes.items()))
        else:
            votes_tuple = tuple((str(item[0]), str(item[1]).upper()) for item in votes)
        return cls(
            code_digest=str(data["code_digest"]), round_index=int(data["round_index"]), nonce=str(data["nonce"]),
            measured_syndrome=tuple(int(v) for v in data["measured_syndrome"]),
            error_witness=str(data["error_witness"]).upper() if data.get("error_witness") is not None else None,
            correction_witness=str(data["correction_witness"]).upper() if data.get("correction_witness") is not None else None,
            ancilla_syndrome=tuple(int(v) for v in data.get("ancilla_syndrome", [])),
            decoder_votes=votes_tuple, previous_round_digest=data.get("previous_round_digest"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code_digest": self.code_digest, "round_index": self.round_index, "nonce": self.nonce,
            "measured_syndrome": list(self.measured_syndrome), "error_witness": self.error_witness,
            "correction_witness": self.correction_witness, "ancilla_syndrome": list(self.ancilla_syndrome),
            "decoder_votes": dict(self.decoder_votes), "previous_round_digest": self.previous_round_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()))


@dataclass(frozen=True)
class QECPolicy:
    minimum_decoder_votes: int = 1
    require_unanimous_decoders: bool = True
    require_ancilla_agreement: bool = True
    require_error_witness: bool = True
    require_correction_witness: bool = True


@dataclass(frozen=True)
class QECReport:
    valid: bool
    evidence_digest: str
    checks: Dict[str, Any]
    findings: Tuple[Finding, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {"valid": self.valid, "evidence_digest": self.evidence_digest, "checks": self.checks, "findings": [item.to_dict() for item in self.findings]}


def verify_syndrome_evidence(
    code: StabilizerCode,
    evidence: SyndromeEvidence,
    *,
    expected_nonce: Optional[str] = None,
    minimum_round: Optional[int] = None,
    expected_previous_digest: Optional[str] = None,
    policy: QECPolicy = QECPolicy(),
) -> QECReport:
    findings = []
    checks: Dict[str, Any] = {"code_digest_match": evidence.code_digest == code.digest}
    if evidence.code_digest != code.digest:
        findings.append(make_finding("syndrome_forger", "Syndrome Injection", Severity.CRITICAL, 0.99, "The syndrome evidence is bound to a different error-correction code.", {"expected": code.digest, "actual": evidence.code_digest}, FindingStatus.BREACH))
    if expected_nonce is not None and evidence.nonce != expected_nonce:
        findings.append(make_finding("intent_forger", "Context Replay", Severity.CRITICAL, 0.98, "The syndrome nonce does not match the active challenge.", {"expected": expected_nonce, "actual": evidence.nonce}, FindingStatus.BREACH))
    if minimum_round is not None and evidence.round_index < minimum_round:
        findings.append(make_finding("syndrome_forger", "Syndrome Suppression", Severity.HIGH, 0.96, "The syndrome round moved backward.", {"minimum": minimum_round, "actual": evidence.round_index}))
    if expected_previous_digest is not None and evidence.previous_round_digest != expected_previous_digest:
        findings.append(make_finding("syndrome_forger", "Syndrome Injection", Severity.CRITICAL, 0.98, "The syndrome round is not linked to the accepted previous round.", {"expected": expected_previous_digest, "actual": evidence.previous_round_digest}, FindingStatus.BREACH))

    if len(evidence.measured_syndrome) != len(code.stabilizers):
        findings.append(make_finding("syndrome_forger", "Syndrome Injection", Severity.CRITICAL, 0.99, "The syndrome length does not match the stabilizer code.", {"expected": len(code.stabilizers), "actual": len(evidence.measured_syndrome)}, FindingStatus.BREACH))

    predicted = None
    if evidence.error_witness is not None:
        if len(evidence.error_witness) != code.qubits:
            findings.append(make_finding("syndrome_forger", "Syndrome Injection", Severity.CRITICAL, 0.98, "The error witness has the wrong width.", {"expected": code.qubits, "actual": len(evidence.error_witness)}, FindingStatus.BREACH))
        else:
            predicted = syndrome_for_error(code.stabilizers, evidence.error_witness)
            checks["predicted_syndrome"] = list(predicted)
            if predicted != evidence.measured_syndrome:
                findings.append(make_finding("syndrome_forger", "Syndrome Injection", Severity.CRITICAL, 0.99, "The measured syndrome is inconsistent with the supplied error witness.", {"predicted": list(predicted), "measured": list(evidence.measured_syndrome)}, FindingStatus.BREACH))
    elif policy.require_error_witness:
        findings.append(make_finding("syndrome_forger", "Syndrome Suppression", Severity.HIGH, 0.90, "No error witness was supplied for independent syndrome verification.", {}))

    if evidence.correction_witness is not None:
        if len(evidence.correction_witness) != code.qubits:
            findings.append(make_finding("syndrome_forger", "Syndrome Injection", Severity.CRITICAL, 0.98, "The correction witness has the wrong width.", {"expected": code.qubits, "actual": len(evidence.correction_witness)}, FindingStatus.BREACH))
        elif evidence.error_witness is not None and len(evidence.error_witness) == code.qubits:
            combined = combine_paulis(evidence.error_witness, evidence.correction_witness)
            residual = syndrome_for_error(code.stabilizers, combined)
            checks["post_correction_syndrome"] = list(residual)
            if any(residual):
                findings.append(make_finding("syndrome_forger", "Syndrome Suppression", Severity.HIGH, 0.96, "The proposed correction does not clear the verified syndrome.", {"residual_syndrome": list(residual), "combined_error": combined}))
    elif policy.require_correction_witness:
        findings.append(make_finding("syndrome_forger", "Syndrome Suppression", Severity.HIGH, 0.90, "No correction witness was supplied.", {}))

    if evidence.ancilla_syndrome:
        agreement = evidence.ancilla_syndrome == evidence.measured_syndrome
        checks["ancilla_agreement"] = agreement
        if not agreement:
            findings.append(make_finding("ancilla_parasite", "Ancilla Tampering", Severity.CRITICAL, 0.98, "Ancilla evidence disagrees with the reported syndrome.", {"ancilla": list(evidence.ancilla_syndrome), "measured": list(evidence.measured_syndrome)}, FindingStatus.BREACH))
    elif policy.require_ancilla_agreement:
        findings.append(make_finding("ancilla_parasite", "Ancilla Tampering", Severity.HIGH, 0.88, "No independent ancilla syndrome was supplied.", {}))

    votes = dict(evidence.decoder_votes)
    checks["decoder_vote_count"] = len(votes)
    if len(votes) < policy.minimum_decoder_votes:
        findings.append(make_finding("consensus_forge", "Quorum Replay", Severity.HIGH, 0.90, "Too few independent decoder votes were supplied.", {"minimum": policy.minimum_decoder_votes, "actual": len(votes)}))
    if votes:
        unique = set(votes.values())
        checks["decoder_unanimous"] = len(unique) == 1
        if policy.require_unanimous_decoders and len(unique) != 1:
            findings.append(make_finding("consensus_forge", "Verifier Collusion", Severity.HIGH, 0.94, "Independent decoders disagree on the proposed correction.", {"votes": votes}))
        if evidence.correction_witness is not None and any(vote != evidence.correction_witness for vote in votes.values()):
            findings.append(make_finding("consensus_forge", "Approval Forgery", Severity.HIGH, 0.95, "A decoder vote does not match the recorded correction witness.", {"votes": votes, "correction": evidence.correction_witness}))

    ordered = tuple(sorted(findings, key=lambda item: int(item.severity), reverse=True))
    return QECReport(not any(item.severity >= Severity.HIGH for item in ordered), evidence.digest, checks, ordered)
