from __future__ import annotations

import cmath
import math
import sys
import types
import unittest
from unittest.mock import patch

from qsec.qsa_symmetry import (
    QSASymmetryPolicy,
    QSASymmetryReceipt,
    QSASymmetryRequest,
    _phases,
    collect_qsa_symmetry,
)


class FakeIdentity:
    native_version = "0.2.0"
    abi_version = (1, 5, 0)

    def __init__(self, qubits: int) -> None:
        self.qubits = qubits

    def close(self) -> None:
        pass


class FakeSymmetry:
    estimated_bytes = 4096
    membership = "hamming_weight"

    def __init__(self, qubits: int) -> None:
        self.qubit_count = int(qubits)
        self.space_size = 1 << self.qubit_count
        self.class_count = self.qubit_count + 1
        self._angles = [0.0] * self.class_count

    @classmethod
    def hamming_weight(cls, qubits: int) -> "FakeSymmetry":
        return cls(qubits)

    def phases(self, angles: object) -> "FakeSymmetry":
        self._angles = [float(value) for value in angles]
        return self

    def validate(self) -> bool:
        return True

    def class_size(self, weight: int) -> int:
        return math.comb(self.qubit_count, int(weight))

    def class_amplitude(self, weight: int) -> complex:
        return cmath.rect(1.0 / math.sqrt(self.space_size), self._angles[int(weight)])

    def class_probability(self, weight: int) -> float:
        return self.class_size(weight) / self.space_size

    def amplitude(self, basis: int) -> complex:
        return self.class_amplitude(int(basis).bit_count())

    def close(self) -> None:
        pass


class BadSymmetry(FakeSymmetry):
    def class_amplitude(self, weight: int) -> complex:
        if int(weight) == self.qubit_count // 2:
            return 0j
        return super().class_amplitude(weight)


class QSASymmetryTests(unittest.TestCase):
    def request(self, nonce: str = "b" * 64) -> QSASymmetryRequest:
        return QSASymmetryRequest(
            request_id="a" * 64,
            nonce=nonce,
            policy_digest=QSASymmetryPolicy().digest,
            parent_digest="d" * 64,
            qubits=60,
        )

    def qsa_module(self, symmetry: type[FakeSymmetry] = FakeSymmetry, version: str = "0.2.0") -> types.ModuleType:
        module = types.ModuleType("qsa")
        module.__version__ = version
        module.QubitRegister = FakeIdentity
        module.SymmetryState = symmetry
        return module

    def test_60_qubit_hamming_weight_challenge(self) -> None:
        request = self.request()
        with patch.dict(sys.modules, {"qsa": self.qsa_module()}):
            receipt = collect_qsa_symmetry(request)
        self.assertTrue(receipt.accepted)
        self.assertEqual(receipt.logical_states, 1 << 60)
        self.assertEqual(receipt.class_count, 61)
        self.assertEqual(receipt.membership, "hamming_weight")
        self.assertEqual(receipt.classes[30]["size"], math.comb(60, 30))
        self.assertEqual(QSASymmetryReceipt.from_dict(receipt.to_dict()), receipt)

    def test_nonce_changes_phase_challenge(self) -> None:
        self.assertNotEqual(_phases(self.request("b" * 64)), _phases(self.request("e" * 64)))

    def test_class_mismatch_fails_closed(self) -> None:
        with patch.dict(sys.modules, {"qsa": self.qsa_module(BadSymmetry)}):
            receipt = collect_qsa_symmetry(self.request())
        self.assertFalse(receipt.accepted)
        self.assertIn("CLASS_MISMATCH", receipt.failures)

    def test_policy_and_memory_fail_closed(self) -> None:
        class LargeSymmetry(FakeSymmetry):
            estimated_bytes = 8192

        request = QSASymmetryRequest(
            request_id="a" * 64,
            nonce="b" * 64,
            policy_digest="c" * 64,
            parent_digest="d" * 64,
            qubits=60,
        )
        policy = QSASymmetryPolicy(max_estimated_bytes=1024)
        with patch.dict(sys.modules, {"qsa": self.qsa_module(LargeSymmetry, "0.1.9")}):
            receipt = collect_qsa_symmetry(request, policy)
        self.assertFalse(receipt.accepted)
        self.assertIn("POLICY_DIGEST", receipt.failures)
        self.assertIn("QSA_PACKAGE_VERSION", receipt.failures)
        self.assertIn("STATE_MEMORY_LIMIT", receipt.failures)

    def test_request_is_bounded_to_qsa_symmetry_domain(self) -> None:
        with self.assertRaises(ValueError):
            QSASymmetryRequest("a" * 64, "b" * 64, "-", "-", 63)


if __name__ == "__main__":
    unittest.main()
