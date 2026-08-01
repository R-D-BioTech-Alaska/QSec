import unittest

from qsec.engine import QuantumSecurityEngine
from qsec.model import SecuritySnapshot


def snapshot(**changes):
    data = {
        "backend_id": "backend-a",
        "backend_fingerprint": "sha256:trusted",
        "circuit": {
            "name": "bell",
            "backend_family": "simulator",
            "num_qubits": 2,
            "operations": [
                {"name": "H", "qubits": [0]},
                {"name": "CNOT", "qubits": [0, 1]},
            ],
        },
        "calibration": {
            "t1": [100.0, 110.0],
            "t2": [150.0, 160.0],
            "detuning": [0.0, 0.0],
            "readout_matrices": [
                [[0.98, 0.03], [0.02, 0.97]],
                [[0.97, 0.04], [0.03, 0.96]],
            ],
            "reset_excited_probability": [0.01, 0.01],
            "gate_error_rates": {"H": 0.001, "CNOT": 0.01},
        },
        "measurement_counts": {"00": 510, "11": 514},
        "state": {
            "kind": "statevector",
            "values": [[2 ** -0.5, 0.0], [0.0, 0.0], [0.0, 0.0], [2 ** -0.5, 0.0]],
        },
    }
    for key, value in changes.items():
        data[key] = value
    return SecuritySnapshot.from_dict(data)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = QuantumSecurityEngine()
        self.baseline = snapshot()

    def test_clean_snapshot_passes(self):
        report = self.engine.inspect(snapshot(), self.baseline)
        self.assertTrue(report.passed)
        self.assertEqual(report.findings, ())

    def test_current_only_policy_is_enforced(self):
        from qsec.circuit import CircuitPolicy
        from qsec.engine import QSecPolicy

        engine = QuantumSecurityEngine(QSecPolicy(circuit=CircuitPolicy(allowed_gates=("H",), require_exact_manifest=False)))
        report = engine.inspect(snapshot(), baseline=None)
        self.assertTrue(any(item.threat == "Shadow Circuit" for item in report.findings))

    def test_invalid_reset_probability_is_detected(self):
        calibration = dict(snapshot().calibration.__dict__)
        calibration["reset_excited_probability"] = [1.2, 0.01]
        report = self.engine.inspect(snapshot(calibration=calibration), self.baseline)
        self.assertTrue(any(item.threat == "Reset Ghost" for item in report.findings))

    def test_backend_mismatch_is_oracle_mimic(self):
        report = self.engine.inspect(snapshot(backend_fingerprint="sha256:other"), self.baseline)
        self.assertTrue(any(item.threat == "Oracle Mimic" for item in report.findings))

    def test_added_gate_is_shadow_circuit(self):
        circuit = dict(self.baseline.circuit)
        circuit["operations"] = list(circuit["operations"]) + [{"name": "X", "qubits": [1]}]
        report = self.engine.inspect(snapshot(circuit=circuit), self.baseline)
        self.assertTrue(any(item.threat == "Shadow Circuit" for item in report.findings))

    def test_bad_entropy_is_entropy_leech(self):
        report = self.engine.inspect(snapshot(entropy_sample_hex=(b"\x00" * 4096).hex()), self.baseline)
        self.assertTrue(any(item.threat == "Entropy Leech" for item in report.findings))

    def test_invalid_state_is_state_doppelganger(self):
        state = {"kind": "statevector", "values": [[1.0, 0.0], [1.0, 0.0], [0.0, 0.0], [0.0, 0.0]]}
        report = self.engine.inspect(snapshot(state=state), self.baseline)
        self.assertTrue(any(item.threat == "State Doppelgänger" for item in report.findings))

    def test_coherence_drop_is_detected(self):
        calibration = {
            "t1": [100.0, 110.0],
            "t2": [50.0, 55.0],
            "detuning": [0.0, 0.0],
            "readout_matrices": [
                [[0.98, 0.03], [0.02, 0.97]],
                [[0.97, 0.04], [0.03, 0.96]],
            ],
            "reset_excited_probability": [0.01, 0.01],
            "gate_error_rates": {"H": 0.001, "CNOT": 0.01},
        }
        report = self.engine.inspect(snapshot(calibration=calibration), self.baseline)
        self.assertTrue(any(item.threat == "Coherence Eater" for item in report.findings))

    def test_reset_contamination_is_detected(self):
        calibration = {
            "t1": [100.0, 110.0],
            "t2": [150.0, 160.0],
            "detuning": [0.0, 0.0],
            "readout_matrices": [
                [[0.98, 0.03], [0.02, 0.97]],
                [[0.97, 0.04], [0.03, 0.96]],
            ],
            "reset_excited_probability": [0.20, 0.01],
            "gate_error_rates": {"H": 0.001, "CNOT": 0.01},
        }
        report = self.engine.inspect(snapshot(calibration=calibration), self.baseline)
        self.assertTrue(any(item.threat == "Reset Ghost" for item in report.findings))

    def test_measurement_divergence_is_detected(self):
        current = snapshot(measurement_counts={"00": 50, "11": 974})
        report = self.engine.inspect(current, self.baseline)
        self.assertTrue(any(item.threat == "Readout Phantom" for item in report.findings))


if __name__ == "__main__":
    unittest.main()
