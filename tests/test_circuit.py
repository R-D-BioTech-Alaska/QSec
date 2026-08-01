import unittest

from qsec.circuit import CircuitManifest, CircuitPolicy, compare_circuits


def manifest(extra=None):
    operations = [
        {"name": "H", "qubits": [0]},
        {"name": "CNOT", "qubits": [0, 1]},
        {"name": "RZ", "qubits": [1], "parameters": [0.25]},
    ]
    if extra:
        operations.extend(extra)
    return CircuitManifest.from_dict({"name": "bell", "backend_family": "test", "num_qubits": 2, "operations": operations})


class CircuitTests(unittest.TestCase):
    def test_exact_match(self):
        baseline = manifest()
        current = manifest()
        delta = compare_circuits(baseline, current)
        self.assertTrue(delta.matched)
        self.assertEqual(delta.baseline_digest, delta.current_digest)

    def test_detects_added_gate(self):
        delta = compare_circuits(manifest(), manifest([{"name": "X", "qubits": [0]}]))
        self.assertFalse(delta.matched)
        self.assertEqual(len(delta.added_operations), 1)

    def test_detects_parameter_change(self):
        baseline = manifest()
        current = CircuitManifest.from_dict({
            "name": "bell",
            "backend_family": "test",
            "num_qubits": 2,
            "operations": [
                {"name": "H", "qubits": [0]},
                {"name": "CNOT", "qubits": [0, 1]},
                {"name": "RZ", "qubits": [1], "parameters": [0.30]},
            ],
        })
        delta = compare_circuits(baseline, current)
        self.assertFalse(delta.matched)
        self.assertEqual(len(delta.changed_operations), 1)

    def test_policy_rejects_unapproved_gate(self):
        policy = CircuitPolicy(allowed_gates=("H", "CNOT", "RZ"), require_exact_manifest=False)
        delta = compare_circuits(manifest(), manifest([{"name": "X", "qubits": [0]}]), policy)
        self.assertFalse(delta.matched)
        self.assertTrue(any("unapproved gates" in item for item in delta.policy_violations))

    def test_manifest_name_is_part_of_identity(self):
        baseline = manifest()
        current_data = baseline.to_dict()
        current_data["name"] = "other"
        delta = compare_circuits(baseline, CircuitManifest.from_dict(current_data))
        self.assertFalse(delta.matched)
        self.assertIn("circuit name changed", delta.policy_violations)

    def test_rejects_nonfinite_parameter(self):
        with self.assertRaises(ValueError):
            CircuitManifest.from_dict({
                "num_qubits": 1,
                "operations": [{"name": "RZ", "qubits": [0], "parameters": [float("nan")]}],
            })

    def test_depth(self):
        self.assertEqual(manifest().depth(), 3)


if __name__ == "__main__":
    unittest.main()
