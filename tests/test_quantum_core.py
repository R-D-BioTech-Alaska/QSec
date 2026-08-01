from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from qsec.quantum_core import (
    QuantumGate,
    QuantumProtocolError,
    QuantumRequest,
    QuantumWitness,
    consensus_digest_for,
    execute_request,
)
from qsec.quantum_hopper import HopperMesh, QuantumReplayGuard, native_worker, python_worker


ROOT = Path(__file__).resolve().parents[1]


def request(*gates: QuantumGate, nonce: str = "2" * 64) -> QuantumRequest:
    return QuantumRequest(
        request_id="1" * 64,
        nonce=nonce,
        policy_digest="3" * 64,
        parent_digest="4" * 64,
        qubits=2,
        initial_basis=0,
        gates=tuple(gates),
    )


class QuantumCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configured = os.environ.get("QSEC_NATIVE_CORE")
        if configured and Path(configured).is_file():
            cls.native = Path(configured)
            return
        compiler = next((item for item in ("c++", "g++", "clang++") if shutil.which(item)), None)
        if compiler is None:
            cls.native = None
            return
        cls.build = tempfile.TemporaryDirectory()
        cls.native = Path(cls.build.name) / "qsec-law-core"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "build_native_core.py"),
                "--compiler",
                compiler,
                "--output",
                str(cls.native),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        build = getattr(cls, "build", None)
        if build is not None:
            build.cleanup()

    def test_protocol_round_trip_is_byte_exact(self) -> None:
        value = request(QuantumGate("H", 0), QuantumGate("CNOT", 0, 1))
        self.assertEqual(QuantumRequest.decode(value.encode()), value)
        self.assertEqual(QuantumRequest.decode(value.encode()).encode(), value.encode())

    def test_protocol_rejects_noncanonical_or_executable_fields(self) -> None:
        value = request(QuantumGate("H", 0)).encode().replace(b"gate_count=1", b"gate_count=01")
        with self.assertRaises(QuantumProtocolError):
            QuantumRequest.decode(value)
        with self.assertRaises(QuantumProtocolError):
            QuantumGate("IMPORT", 0)

    def test_relative_phase_changes_state_witness_without_changing_probabilities(self) -> None:
        clean = request(QuantumGate("H", 0), QuantumGate("CNOT", 0, 1))
        phase = request(QuantumGate("H", 0), QuantumGate("CNOT", 0, 1), QuantumGate("Z", 0))
        clean_witness = execute_request(clean)
        phase_witness = execute_request(phase)
        self.assertEqual(clean_witness.probability_digest, phase_witness.probability_digest)
        self.assertNotEqual(clean_witness.state_digest, phase_witness.state_digest)
        self.assertNotEqual(clean_witness.consensus_digest, phase_witness.consensus_digest)


    def test_global_phase_is_not_a_state_difference(self) -> None:
        plain = QuantumRequest(
            request_id="5" * 64,
            nonce="6" * 64,
            policy_digest="-",
            parent_digest="-",
            qubits=1,
            initial_basis=1,
            gates=(),
        )
        phased = QuantumRequest(
            request_id="7" * 64,
            nonce="8" * 64,
            policy_digest="-",
            parent_digest="-",
            qubits=1,
            initial_basis=1,
            gates=(QuantumGate("Z", 0),),
        )
        self.assertEqual(execute_request(plain).state_digest, execute_request(phased).state_digest)

    def test_rotation_angle_is_bounded(self) -> None:
        with self.assertRaises(QuantumProtocolError):
            QuantumGate("RX", 0, angle_nanoradians=25_132_741_230)

    def test_json_contract_rejects_non_object_gate(self) -> None:
        payload = request(QuantumGate("H", 0)).to_dict()
        payload["gates"] = ["H:0"]
        with self.assertRaises(QuantumProtocolError):
            QuantumRequest.from_dict(payload)

    def test_witness_does_not_expose_internal_amplitudes(self) -> None:
        witness = execute_request(request(QuantumGate("H", 0)))
        encoded = witness.encode().decode("ascii").lower()
        self.assertNotIn("amplitude", encoded)
        self.assertNotIn("statevector", encoded)

    def test_python_and_native_workers_agree(self) -> None:
        if self.native is None:
            self.skipTest("no C++ compiler is available")
        value = request(
            QuantumGate("H", 0),
            QuantumGate("CNOT", 0, 1),
            QuantumGate("RZ", 1, angle_nanoradians=314159265),
            QuantumGate("SWAP", 0, 1),
        )
        python_result = python_worker().verify(value)
        native_result = native_worker(self.native).verify(value)
        self.assertEqual(python_result.consensus_digest, native_result.consensus_digest)
        self.assertEqual(python_result.state_digest, native_result.state_digest)
        self.assertEqual(python_result.probability_digest, native_result.probability_digest)

    def test_hopper_mesh_accepts_only_independent_agreement(self) -> None:
        if self.native is None:
            self.skipTest("no C++ compiler is available")
        value = request(QuantumGate("H", 0), QuantumGate("CNOT", 0, 1))
        receipt = HopperMesh([python_worker(), native_worker(self.native)]).verify(value)
        self.assertTrue(receipt.accepted)
        self.assertEqual(set(receipt.route), {"python-isolated", "native-cpp"})
        self.assertFalse(receipt.disagreements)
        self.assertFalse(receipt.failures)

    def test_hopper_mesh_fails_closed_on_valid_but_disagreeing_worker(self) -> None:
        if self.native is None:
            self.skipTest("no C++ compiler is available")

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

        value = request(QuantumGate("H", 0))
        receipt = HopperMesh(
            [python_worker(), native_worker(self.native), DivergentWorker()],
            minimum_agreement=2,
            require_unanimous=True,
        ).verify(value)
        self.assertFalse(receipt.accepted)
        self.assertTrue(receipt.disagreements)

    def test_replay_guard_consumes_nonce_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = QuantumReplayGuard(Path(directory) / "replay.sqlite3")
            value = request(QuantumGate("X", 0))
            guard.consume(value)
            with self.assertRaises(QuantumProtocolError):
                guard.consume(value)

    def test_json_contract_round_trip(self) -> None:
        value = request(QuantumGate("RX", 0, angle_nanoradians=125000000))
        encoded = json.loads(json.dumps(value.to_dict()))
        self.assertEqual(QuantumRequest.from_dict(encoded), value)
