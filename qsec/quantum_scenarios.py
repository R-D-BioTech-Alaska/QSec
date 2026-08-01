from __future__ import annotations

import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

from .quantum_core import (
    QuantumGate,
    QuantumProtocolError,
    QuantumRequest,
    QuantumWitness,
    consensus_digest_for,
    execute_request,
)
from .quantum_hopper import HopperMesh, QuantumReplayGuard, native_worker, python_worker


@dataclass(frozen=True)
class QuantumScenarioResult:
    name: str
    malicious: bool
    detected: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "malicious": self.malicious,
            "detected": self.detected,
            "detail": self.detail,
        }


def _request(identifier: str, nonce: str, gates: Iterable[QuantumGate], *, initial_basis: int = 0, qubits: int = 3) -> QuantumRequest:
    return QuantumRequest(
        request_id=identifier * 64,
        nonce=nonce * 64,
        policy_digest="c" * 64,
        parent_digest="d" * 64,
        qubits=qubits,
        initial_basis=initial_basis,
        gates=tuple(gates),
    )


def run_quantum_scenarios(native_path: str | Path) -> tuple[QuantumScenarioResult, ...]:
    workers = [python_worker(), native_worker(native_path)]
    clean_bell = _request("1", "2", [QuantumGate("H", 0), QuantumGate("CNOT", 0, 1)])
    clean_ghz = _request(
        "2",
        "3",
        [QuantumGate("H", 0), QuantumGate("CNOT", 0, 1), QuantumGate("CNOT", 0, 2)],
    )
    clean_rotation = _request(
        "3",
        "4",
        [QuantumGate("RX", 0, angle_nanoradians=250000000), QuantumGate("RY", 1, angle_nanoradians=-125000000)],
    )

    results: list[QuantumScenarioResult] = []
    for name, value in (
        ("clean_bell", clean_bell),
        ("clean_ghz", clean_ghz),
        ("clean_rotation", clean_rotation),
    ):
        receipt = HopperMesh(workers).verify(value)
        results.append(QuantumScenarioResult(name, False, receipt.accepted, "independent workers agree"))

    baseline = execute_request(clean_bell)
    mutations = (
        (
            "gate_insertion",
            _request("4", "5", [QuantumGate("H", 0), QuantumGate("X", 2), QuantumGate("CNOT", 0, 1)]),
        ),
        (
            "relative_phase_injection",
            _request("5", "6", [QuantumGate("H", 0), QuantumGate("CNOT", 0, 1), QuantumGate("Z", 0)]),
        ),
        (
            "target_substitution",
            _request("6", "7", [QuantumGate("H", 0), QuantumGate("CNOT", 0, 2)]),
        ),
        (
            "initial_state_substitution",
            _request("7", "8", [QuantumGate("H", 0), QuantumGate("CNOT", 0, 1)], initial_basis=1),
        ),
    )
    for name, value in mutations:
        witness = execute_request(value)
        results.append(
            QuantumScenarioResult(
                name,
                True,
                witness.consensus_digest != baseline.consensus_digest,
                "quantum witness changed",
            )
        )

    class DivergentWorker:
        name = "divergent"

        def verify(self, value: QuantumRequest) -> QuantumWitness:
            witness = execute_request(value, backend_id=self.name)
            state_digest = "e" * 64
            return replace(
                witness,
                state_digest=state_digest,
                consensus_digest=consensus_digest_for(
                    witness.request_digest,
                    state_digest,
                    witness.probability_digest,
                    witness.norm_scaled,
                    value.qubits,
                ),
            )

    divergent = HopperMesh(
        [python_worker(), native_worker(native_path), DivergentWorker()],
        minimum_agreement=2,
        require_unanimous=True,
    ).verify(_request("8", "9", [QuantumGate("H", 0)]))
    results.append(QuantumScenarioResult("worker_divergence", True, not divergent.accepted, "unanimity failed closed"))

    with tempfile.TemporaryDirectory() as directory:
        guard = QuantumReplayGuard(Path(directory) / "replay.sqlite3")
        replay_value = _request("9", "a", [QuantumGate("X", 0)])
        guard.consume(replay_value)
        replay_detected = False
        try:
            guard.consume(replay_value)
        except QuantumProtocolError:
            replay_detected = True
        results.append(QuantumScenarioResult("nonce_replay", True, replay_detected, "durable nonce uniqueness"))

    malformed_detected = False
    try:
        QuantumRequest.decode(clean_bell.encode().replace(b"gate_count=2", b"gate_count=02"))
    except QuantumProtocolError:
        malformed_detected = True
    results.append(QuantumScenarioResult("noncanonical_protocol", True, malformed_detected, "strict parser rejected input"))
    return tuple(results)


def summarize_quantum_scenarios(results: Iterable[QuantumScenarioResult]) -> dict[str, object]:
    values = tuple(results)
    true_positive = sum(1 for item in values if item.malicious and item.detected)
    false_negative = sum(1 for item in values if item.malicious and not item.detected)
    true_negative = sum(1 for item in values if not item.malicious and item.detected)
    false_positive = sum(1 for item in values if not item.malicious and not item.detected)
    return {
        "total": len(values),
        "malicious": sum(1 for item in values if item.malicious),
        "clean": sum(1 for item in values if not item.malicious),
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "passed": false_negative == 0 and false_positive == 0,
        "results": [item.to_dict() for item in values],
    }
