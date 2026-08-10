from __future__ import annotations

import math
import sys
import types
import unittest
from unittest.mock import patch

from qsec.qsa_grover import (
    QSAGroverPolicy,
    QSAGroverReceipt,
    QSAGroverRequest,
    _challenge_indices,
    collect_qsa_grover,
)


class FakeIdentity:
    native_version = "0.2.0"
    abi_version = (1, 5, 0)

    def __init__(self, qubits: int) -> None:
        self.qubits = qubits

    def close(self) -> None:
        pass


class FakeGrover:
    estimated_bytes = 96

    def __init__(self, qubits: int, marked_indices: object) -> None:
        self._qubits = int(qubits)
        self._marked = tuple(sorted(int(value) for value in marked_indices))
        self._iterations = 0

    @property
    def qubit_count(self) -> int:
        return self._qubits

    @property
    def space_size(self) -> int:
        return 1 << self._qubits

    @property
    def marked_count(self) -> int:
        return len(self._marked)

    @property
    def iteration_count(self) -> int:
        return self._iterations

    @property
    def optimal_iterations(self) -> int:
        theta = math.asin(math.sqrt(self.marked_count / self.space_size))
        ideal = math.pi / (4.0 * theta) - 0.5
        if ideal <= 0:
            return 0
        lower = int(math.floor(ideal))
        upper = lower + 1
        probability = lambda count: math.sin((2 * count + 1) * theta) ** 2
        return upper if probability(upper) > probability(lower) else lower

    @property
    def has_explicit_marked_indices(self) -> bool:
        return True

    def iterate(self, count: int) -> "FakeGrover":
        self._iterations += int(count)
        return self

    def run_optimal(self) -> "FakeGrover":
        return self.iterate(self.optimal_iterations)

    def _values(self) -> tuple[float, complex, complex]:
        theta = math.asin(math.sqrt(self.marked_count / self.space_size))
        angle = (2 * self._iterations + 1) * theta
        marked = complex(math.sin(angle) / math.sqrt(self.marked_count), 0.0)
        unmarked = complex(math.cos(angle) / math.sqrt(self.space_size - self.marked_count), 0.0)
        return math.sin(angle) ** 2, marked, unmarked

    @property
    def success_probability(self) -> float:
        return self._values()[0]

    @property
    def marked_amplitude(self) -> complex:
        return self._values()[1]

    @property
    def unmarked_amplitude(self) -> complex:
        return self._values()[2]

    def amplitude(self, basis_index: int) -> complex:
        return self.marked_amplitude if int(basis_index) in self._marked else self.unmarked_amplitude

    def validate(self) -> bool:
        return True

    def close(self) -> None:
        pass


class BadProbabilityGrover(FakeGrover):
    @property
    def success_probability(self) -> float:
        return 0.5


class QSAGroverTests(unittest.TestCase):
    def request(self, nonce: str = "b" * 64) -> QSAGroverRequest:
        return QSAGroverRequest(
            request_id="a" * 64,
            nonce=nonce,
            policy_digest=QSAGroverPolicy().digest,
            parent_digest="d" * 64,
            qubits=60,
            marked_count=1,
            iterations=None,
        )

    def qsa_module(self, grover: type[FakeGrover] = FakeGrover, version: str = "0.2.0") -> types.ModuleType:
        module = types.ModuleType("qsa")
        module.__version__ = version
        module.GroverSearch = grover
        module.QubitRegister = FakeIdentity
        return module

    def test_60_qubit_nonce_bound_challenge(self) -> None:
        request = self.request()
        with patch.dict(sys.modules, {"qsa": self.qsa_module()}):
            receipt = collect_qsa_grover(request)
        self.assertTrue(receipt.accepted)
        self.assertEqual(receipt.logical_states, 1 << 60)
        self.assertEqual(receipt.dense_statevector_bytes, 16 * (1 << 60))
        self.assertGreater(receipt.dense_reduction, 100_000_000_000_000_000)
        self.assertLessEqual(receipt.probability_error_scaled, 1)
        self.assertEqual(QSAGroverReceipt.from_dict(receipt.to_dict()), receipt)

    def test_nonce_changes_the_marked_challenge(self) -> None:
        first = _challenge_indices(self.request("b" * 64))
        second = _challenge_indices(self.request("e" * 64))
        self.assertNotEqual(first, second)

    def test_probability_mismatch_fails_closed(self) -> None:
        with patch.dict(sys.modules, {"qsa": self.qsa_module(BadProbabilityGrover)}):
            receipt = collect_qsa_grover(self.request())
        self.assertFalse(receipt.accepted)
        self.assertIn("PROBABILITY_MISMATCH", receipt.failures)

    def test_policy_digest_mismatch_fails_closed(self) -> None:
        request = QSAGroverRequest(
            request_id="a" * 64,
            nonce="b" * 64,
            policy_digest="c" * 64,
            parent_digest="d" * 64,
            qubits=60,
            marked_count=1,
        )
        with patch.dict(sys.modules, {"qsa": self.qsa_module()}):
            receipt = collect_qsa_grover(request)
        self.assertFalse(receipt.accepted)
        self.assertIn("POLICY_DIGEST", receipt.failures)

    def test_version_and_memory_policy_fail_closed(self) -> None:
        class LargeGrover(FakeGrover):
            estimated_bytes = 4096

        policy = QSAGroverPolicy(max_estimated_bytes=1024)
        with patch.dict(sys.modules, {"qsa": self.qsa_module(LargeGrover, "0.1.9")}):
            receipt = collect_qsa_grover(self.request(), policy)
        self.assertFalse(receipt.accepted)
        self.assertIn("QSA_PACKAGE_VERSION", receipt.failures)
        self.assertIn("STATE_MEMORY_LIMIT", receipt.failures)

    def test_request_is_bounded_to_qsa_grover_domain(self) -> None:
        with self.assertRaises(ValueError):
            QSAGroverRequest(
                request_id="a" * 64,
                nonce="b" * 64,
                policy_digest="-",
                parent_digest="-",
                qubits=63,
                marked_count=1,
            )


if __name__ == "__main__":
    unittest.main()
