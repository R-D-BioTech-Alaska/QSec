from __future__ import annotations

import math
import sys
import types
import unittest
from unittest.mock import patch

from qsec.qsa_evidence import (
    QSAEvidencePolicy,
    QSAEvidenceReceipt,
    QSAEvidenceRequest,
    collect_qsa_evidence,
)
from qsec.quantum_core import QuantumGate


class FakePlan:
    def __init__(self, operations: object) -> None:
        self.operations = tuple(operations)

    def compiled_step_count(self, state: object) -> int:
        return max(1, len(self.operations) - 1)

    def close(self) -> None:
        pass


class FakeState:
    native_version = "0.2.0"
    abi_version = (1, 5, 0)

    def __init__(self, qubits: int) -> None:
        self.qubits = qubits
        self.component_count = 1
        self.estimated_bytes = 4096

    def apply_plan(self, plan: FakePlan) -> "FakeState":
        return self

    def validate(self) -> bool:
        return True

    def component_kind(self, qubit: int) -> str:
        return "sparse"

    def component_size(self, qubit: int) -> int:
        return self.qubits

    def component_nonzero_count(self, qubit: int) -> int:
        return 2

    def amplitude(self, basis_index: int) -> complex:
        if basis_index in {0, (1 << self.qubits) - 1}:
            return complex(1.0 / math.sqrt(2.0), 0.0)
        return 0j

    def probability_one(self, qubit: int) -> float:
        return 0.5

    def encode_qsc(self) -> bytes:
        return f"fake-qsc:{self.qubits}".encode("ascii")

    @classmethod
    def decode_qsc(cls, payload: bytes) -> "FakeState":
        return cls(int(payload.decode("ascii").split(":", 1)[1]))

    def close(self) -> None:
        pass


class UnstableState(FakeState):
    def __init__(self, qubits: int, restored: bool = False) -> None:
        super().__init__(qubits)
        self.restored = restored

    def encode_qsc(self) -> bytes:
        suffix = ":restored" if self.restored else ""
        return f"fake-qsc:{self.qubits}{suffix}".encode("ascii")

    @classmethod
    def decode_qsc(cls, payload: bytes) -> "UnstableState":
        qubits = int(payload.decode("ascii").split(":", 2)[1])
        return cls(qubits, restored=True)


class QSAEvidenceTests(unittest.TestCase):
    def request(self, qubits: int) -> QSAEvidenceRequest:
        gates = [QuantumGate("H", 0)]
        if qubits > 1:
            gates.append(QuantumGate("CNOT", 0, qubits - 1))
        return QSAEvidenceRequest(
            request_id="a" * 64,
            nonce="b" * 64,
            policy_digest="c" * 64,
            parent_digest="d" * 64,
            qubits=qubits,
            initial_basis=0,
            gates=tuple(gates),
        )

    def qsa_module(self, version: str = "0.2.0") -> types.ModuleType:
        module = types.ModuleType("qsa")
        module.__version__ = version
        module.OperationPlan = FakePlan
        module.QubitRegister = FakeState
        return module

    def test_wide_structured_receipt(self) -> None:
        with patch.dict(sys.modules, {"qsa": self.qsa_module()}):
            receipt = collect_qsa_evidence(self.request(50))
        self.assertTrue(receipt.accepted)
        self.assertTrue(receipt.validated)
        self.assertTrue(receipt.roundtrip_equivalent)
        self.assertTrue(receipt.qsc_byte_stable)
        self.assertEqual(receipt.component_kinds, {"sparse": 50})
        self.assertEqual(receipt.dense_statevector_bytes, 16 * (1 << 50))
        self.assertGreater(receipt.dense_reduction, 1_000_000_000)
        self.assertIsNone(receipt.state_digest)
        self.assertEqual(QSAEvidenceReceipt.from_dict(receipt.to_dict()), receipt)

    def test_bounded_receipt_keeps_cross_code_commitments(self) -> None:
        with patch.dict(sys.modules, {"qsa": self.qsa_module()}):
            receipt = collect_qsa_evidence(self.request(3))
        self.assertTrue(receipt.accepted)
        self.assertIsNotNone(receipt.state_digest)
        self.assertIsNotNone(receipt.probability_digest)

    def test_qsc_byte_change_fails_closed(self) -> None:
        module = self.qsa_module()
        module.QubitRegister = UnstableState
        with patch.dict(sys.modules, {"qsa": module}):
            receipt = collect_qsa_evidence(self.request(20))
        self.assertFalse(receipt.accepted)
        self.assertFalse(receipt.qsc_byte_stable)
        self.assertIn("QSC_ROUNDTRIP", receipt.failures)

    def test_version_and_resource_policy_fail_closed(self) -> None:
        policy = QSAEvidencePolicy(max_estimated_bytes=1024)
        with patch.dict(sys.modules, {"qsa": self.qsa_module("0.1.9")}):
            receipt = collect_qsa_evidence(self.request(20), policy)
        self.assertFalse(receipt.accepted)
        self.assertIn("QSA_PACKAGE_VERSION", receipt.failures)
        self.assertIn("STATE_MEMORY_LIMIT", receipt.failures)

    def test_request_allows_structured_width_but_stays_bounded(self) -> None:
        self.assertEqual(self.request(64).qubits, 64)
        with self.assertRaises(ValueError):
            self.request(65)


if __name__ == "__main__":
    unittest.main()
