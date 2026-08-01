from __future__ import annotations

from dataclasses import dataclass, field, replace
from math import sqrt
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

from .circuit import CircuitManifest, CircuitPolicy, compare_circuits
from .entropy import EntropyPolicy, assess_entropy
from .model import Finding, FindingStatus, InspectionReport, SecuritySnapshot, Severity
from .physics import (
    pure_state_fidelity,
    total_variation_distance,
    validate_readout_matrix,
    validate_relaxation_times,
    validate_state_payload,
)
from .threats import get_threat


@dataclass(frozen=True)
class QSecPolicy:
    circuit: CircuitPolicy = field(default_factory=CircuitPolicy)
    entropy: EntropyPolicy = field(default_factory=EntropyPolicy)
    physical_tolerance: float = 1e-9
    maximum_relative_calibration_drift: float = 0.25
    maximum_detuning_delta: float = 0.05
    maximum_readout_matrix_delta: float = 0.08
    maximum_reset_excitation_delta: float = 0.05
    minimum_state_fidelity: float = 0.99
    measurement_tvd_threshold: float = 0.15
    measurement_sigma_multiplier: float = 4.0
    minimum_measurement_shots: int = 128


class QuantumSecurityEngine:
    def __init__(self, policy: QSecPolicy = QSecPolicy()):
        self.policy = policy

    def _finding(
        self,
        threat_name: str,
        technique: str,
        severity: Severity,
        confidence: float,
        summary: str,
        evidence: Dict[str, Any],
        status: FindingStatus = FindingStatus.DISTURBANCE,
    ) -> Finding:
        threat = get_threat(threat_name)
        return Finding(
            code=threat.code,
            threat=threat.name,
            technique=technique,
            severity=severity,
            confidence=confidence,
            status=status,
            summary=summary,
            evidence=evidence,
        )

    @staticmethod
    def _relative_drift(baseline: Sequence[float], current: Sequence[float]) -> Tuple[float, int]:
        if not baseline or not current or len(baseline) != len(current):
            return 0.0, -1
        base = np.asarray(baseline, dtype=float)
        now = np.asarray(current, dtype=float)
        denominator = np.maximum(np.abs(base), 1e-15)
        drift = np.abs(now - base) / denominator
        index = int(np.argmax(drift))
        return float(drift[index]), index

    @staticmethod
    def _maximum_drop(baseline: Sequence[float], current: Sequence[float]) -> Tuple[float, int]:
        if not baseline or not current or len(baseline) != len(current):
            return 0.0, -1
        base = np.asarray(baseline, dtype=float)
        now = np.asarray(current, dtype=float)
        denominator = np.maximum(np.abs(base), 1e-15)
        drop = (base - now) / denominator
        index = int(np.argmax(drop))
        return max(0.0, float(drop[index])), index

    def inspect(
        self,
        current: SecuritySnapshot,
        baseline: Optional[SecuritySnapshot] = None,
    ) -> InspectionReport:
        findings: List[Finding] = []
        checks: Dict[str, Any] = {}

        current_circuit = CircuitManifest.from_dict(current.circuit)
        checks["current_circuit_digest"] = current_circuit.digest()
        checks["current_circuit_depth"] = current_circuit.depth()

        if baseline is not None:
            identity_match = (
                current.backend_id == baseline.backend_id
                and current.backend_fingerprint == baseline.backend_fingerprint
            )
            checks["backend_identity_match"] = identity_match
            if not identity_match:
                findings.append(
                    self._finding(
                        "oracle_mimic",
                        "Backend Impersonation",
                        Severity.CRITICAL,
                        0.99,
                        "The current backend identity does not match the trusted baseline.",
                        {
                            "baseline_backend_id": baseline.backend_id,
                            "current_backend_id": current.backend_id,
                            "baseline_fingerprint": baseline.backend_fingerprint,
                            "current_fingerprint": current.backend_fingerprint,
                        },
                    )
                )

            baseline_circuit = CircuitManifest.from_dict(baseline.circuit)
            circuit_delta = compare_circuits(baseline_circuit, current_circuit, self.policy.circuit)
            checks["circuit"] = circuit_delta.to_dict()
            if not circuit_delta.matched:
                findings.append(
                    self._finding(
                        "shadow_circuit",
                        "Gate Grafting",
                        Severity.CRITICAL,
                        0.98,
                        "The executed circuit differs from the trusted circuit contract.",
                        circuit_delta.to_dict(),
                    )
                )
        else:
            checks["backend_identity_match"] = None
            current_policy = replace(self.policy.circuit, require_exact_manifest=False)
            policy_delta = compare_circuits(current_circuit, current_circuit, current_policy)
            checks["circuit"] = policy_delta.to_dict()
            if not policy_delta.matched:
                findings.append(
                    self._finding(
                        "shadow_circuit",
                        "Circuit Splicing",
                        Severity.CRITICAL,
                        0.95,
                        "The current circuit violates the configured execution policy.",
                        policy_delta.to_dict(),
                    )
                )

        entropy_sample = current.entropy_sample()
        if entropy_sample is not None:
            entropy_report = assess_entropy(entropy_sample, self.policy.entropy)
            checks["entropy"] = entropy_report.to_dict()
            if not entropy_report.healthy:
                findings.append(
                    self._finding(
                        "entropy_leech",
                        "Entropy Biasing",
                        Severity.HIGH,
                        0.90,
                        "The supplied entropy sample failed one or more health thresholds.",
                        entropy_report.to_dict(),
                    )
                )
        else:
            checks["entropy"] = {"checked": False}

        if current.state is not None:
            state_report = validate_state_payload(current.state, tolerance=self.policy.physical_tolerance)
            checks["state_physics"] = state_report.to_dict()
            if not state_report.valid:
                findings.append(
                    self._finding(
                        "state_doppelganger",
                        "State Replacement",
                        Severity.CRITICAL,
                        0.97,
                        "The supplied quantum state violates physical state constraints.",
                        state_report.to_dict(),
                    )
                )
            elif baseline is not None and baseline.state is not None:
                if current.state.get("kind", "").lower() == "statevector" and baseline.state.get("kind", "").lower() == "statevector":
                    fidelity = pure_state_fidelity(baseline.state.get("values"), current.state.get("values"))
                    checks["state_fidelity"] = fidelity
                    if fidelity < self.policy.minimum_state_fidelity:
                        findings.append(
                            self._finding(
                                "state_doppelganger",
                                "State Replacement",
                                Severity.HIGH,
                                min(0.99, 1.0 - fidelity + 0.5),
                                "The current state is physically valid but does not match the trusted preparation.",
                                {"fidelity": fidelity, "minimum": self.policy.minimum_state_fidelity},
                            )
                        )
        else:
            checks["state_physics"] = {"checked": False}

        calibration = current.calibration
        invalid_detuning = [index for index, value in enumerate(calibration.detuning) if not np.isfinite(value)]
        invalid_reset = [
            index for index, value in enumerate(calibration.reset_excited_probability)
            if not np.isfinite(value) or value < 0.0 or value > 1.0
        ]
        invalid_gate_rates = {
            gate: value for gate, value in calibration.gate_error_rates.items()
            if not np.isfinite(value) or value < 0.0 or value > 1.0
        }
        checks["calibration_scalar_physics"] = {
            "valid": not invalid_detuning and not invalid_reset and not invalid_gate_rates,
            "invalid_detuning_indexes": invalid_detuning,
            "invalid_reset_indexes": invalid_reset,
            "invalid_gate_error_rates": invalid_gate_rates,
        }
        if invalid_detuning or invalid_gate_rates:
            findings.append(
                self._finding(
                    "driftroot",
                    "Calibration Poisoning",
                    Severity.HIGH,
                    0.96,
                    "Calibration contains nonphysical detuning or gate-error values.",
                    checks["calibration_scalar_physics"],
                )
            )
        if invalid_reset:
            findings.append(
                self._finding(
                    "reset_ghost",
                    "Reset Contamination",
                    Severity.HIGH,
                    0.96,
                    "Reset excitation probability is outside physical probability bounds.",
                    checks["calibration_scalar_physics"],
                )
            )

        relaxation_report = validate_relaxation_times(calibration.t1, calibration.t2, self.policy.physical_tolerance)
        checks["relaxation_physics"] = relaxation_report.to_dict()
        if not relaxation_report.valid:
            findings.append(
                self._finding(
                    "driftroot",
                    "Calibration Poisoning",
                    Severity.HIGH,
                    0.95,
                    "The current relaxation calibration violates physical constraints.",
                    relaxation_report.to_dict(),
                )
            )

        readout_checks = []
        for index, matrix in enumerate(calibration.readout_matrices):
            report = validate_readout_matrix(matrix, self.policy.physical_tolerance)
            readout_checks.append({"qubit": index, **report.to_dict()})
            if not report.valid:
                findings.append(
                    self._finding(
                        "readout_phantom",
                        "Readout Forgery",
                        Severity.HIGH,
                        0.95,
                        f"Readout calibration for qubit {index} is not a valid conditional probability matrix.",
                        {"qubit": index, **report.to_dict()},
                    )
                )
        checks["readout_physics"] = readout_checks

        if baseline is not None:
            self._inspect_calibration(baseline, current, checks, findings)
            self._inspect_measurements(baseline, current, checks, findings)

        return InspectionReport(
            findings=tuple(sorted(findings, key=lambda item: int(item.severity), reverse=True)),
            checks=checks,
            baseline_fingerprint=baseline.backend_fingerprint if baseline is not None else None,
            current_fingerprint=current.backend_fingerprint,
        )

    def _inspect_calibration(
        self,
        baseline: SecuritySnapshot,
        current: SecuritySnapshot,
        checks: Dict[str, Any],
        findings: List[Finding],
    ) -> None:
        base = baseline.calibration
        now = current.calibration
        calibration_checks: Dict[str, Any] = {}

        t1_drift, t1_index = self._relative_drift(base.t1, now.t1)
        t2_drift, t2_index = self._relative_drift(base.t2, now.t2)
        t2_drop, t2_drop_index = self._maximum_drop(base.t2, now.t2)
        calibration_checks["maximum_t1_relative_drift"] = t1_drift
        calibration_checks["maximum_t2_relative_drift"] = t2_drift
        calibration_checks["maximum_t2_drop"] = t2_drop

        if max(t1_drift, t2_drift) > self.policy.maximum_relative_calibration_drift:
            findings.append(
                self._finding(
                    "driftroot",
                    "Calibration Poisoning",
                    Severity.HIGH,
                    0.88,
                    "T1 or T2 changed beyond the accepted calibration envelope.",
                    {
                        "maximum_t1_relative_drift": t1_drift,
                        "t1_qubit": t1_index,
                        "maximum_t2_relative_drift": t2_drift,
                        "t2_qubit": t2_index,
                        "threshold": self.policy.maximum_relative_calibration_drift,
                    },
                )
            )
        if t2_drop > self.policy.maximum_relative_calibration_drift:
            findings.append(
                self._finding(
                    "coherence_eater",
                    "Coherence Starvation",
                    Severity.HIGH,
                    0.90,
                    "Coherence time dropped beyond the accepted baseline envelope.",
                    {
                        "maximum_t2_drop": t2_drop,
                        "qubit": t2_drop_index,
                        "threshold": self.policy.maximum_relative_calibration_drift,
                    },
                )
            )

        if base.detuning and now.detuning and len(base.detuning) == len(now.detuning):
            deltas = np.abs(np.asarray(now.detuning) - np.asarray(base.detuning))
            maximum_delta = float(np.max(deltas))
            detuning_index = int(np.argmax(deltas))
            calibration_checks["maximum_detuning_delta"] = maximum_delta
            if maximum_delta > self.policy.maximum_detuning_delta:
                findings.append(
                    self._finding(
                        "driftroot",
                        "Phase Injection",
                        Severity.HIGH,
                        0.86,
                        "Detuning changed beyond the accepted calibration envelope.",
                        {
                            "maximum_delta": maximum_delta,
                            "qubit": detuning_index,
                            "threshold": self.policy.maximum_detuning_delta,
                        },
                    )
                )

        if base.readout_matrices and now.readout_matrices and len(base.readout_matrices) == len(now.readout_matrices):
            matrix_deltas = []
            for baseline_matrix, current_matrix in zip(base.readout_matrices, now.readout_matrices):
                matrix_deltas.append(float(np.max(np.abs(np.asarray(current_matrix) - np.asarray(baseline_matrix)))))
            maximum_readout_delta = max(matrix_deltas, default=0.0)
            readout_index = int(np.argmax(matrix_deltas)) if matrix_deltas else -1
            calibration_checks["maximum_readout_matrix_delta"] = maximum_readout_delta
            if maximum_readout_delta > self.policy.maximum_readout_matrix_delta:
                findings.append(
                    self._finding(
                        "readout_phantom",
                        "Readout Forgery",
                        Severity.HIGH,
                        0.88,
                        "Readout calibration changed beyond the accepted baseline envelope.",
                        {
                            "maximum_delta": maximum_readout_delta,
                            "qubit": readout_index,
                            "threshold": self.policy.maximum_readout_matrix_delta,
                        },
                    )
                )

        if base.reset_excited_probability and now.reset_excited_probability and len(base.reset_excited_probability) == len(now.reset_excited_probability):
            reset_deltas = np.asarray(now.reset_excited_probability) - np.asarray(base.reset_excited_probability)
            maximum_reset_delta = max(0.0, float(np.max(reset_deltas)))
            reset_index = int(np.argmax(reset_deltas))
            calibration_checks["maximum_reset_excitation_delta"] = maximum_reset_delta
            if maximum_reset_delta > self.policy.maximum_reset_excitation_delta:
                findings.append(
                    self._finding(
                        "reset_ghost",
                        "Reset Contamination",
                        Severity.HIGH,
                        0.91,
                        "Post-reset excitation increased beyond the accepted baseline envelope.",
                        {
                            "maximum_delta": maximum_reset_delta,
                            "qubit": reset_index,
                            "threshold": self.policy.maximum_reset_excitation_delta,
                        },
                    )
                )

        shared_gates = set(base.gate_error_rates) & set(now.gate_error_rates)
        gate_drift: Dict[str, float] = {}
        for gate in shared_gates:
            baseline_rate = max(abs(base.gate_error_rates[gate]), 1e-15)
            gate_drift[gate] = abs(now.gate_error_rates[gate] - base.gate_error_rates[gate]) / baseline_rate
        calibration_checks["gate_error_relative_drift"] = dict(sorted(gate_drift.items()))
        if gate_drift:
            worst_gate = max(gate_drift, key=gate_drift.get)
            if gate_drift[worst_gate] > self.policy.maximum_relative_calibration_drift:
                findings.append(
                    self._finding(
                        "driftroot",
                        "Calibration Poisoning",
                        Severity.HIGH,
                        0.86,
                        "A gate error rate changed beyond the accepted calibration envelope.",
                        {
                            "gate": worst_gate,
                            "relative_drift": gate_drift[worst_gate],
                            "threshold": self.policy.maximum_relative_calibration_drift,
                        },
                    )
                )

        checks["calibration_drift"] = calibration_checks

    def _inspect_measurements(
        self,
        baseline: SecuritySnapshot,
        current: SecuritySnapshot,
        checks: Dict[str, Any],
        findings: List[Finding],
    ) -> None:
        baseline_shots = sum(baseline.measurement_counts.values())
        current_shots = sum(current.measurement_counts.values())
        if baseline_shots < self.policy.minimum_measurement_shots or current_shots < self.policy.minimum_measurement_shots:
            checks["measurement_distribution"] = {
                "checked": False,
                "baseline_shots": baseline_shots,
                "current_shots": current_shots,
                "minimum_shots": self.policy.minimum_measurement_shots,
            }
            return
        distance = total_variation_distance(baseline.measurement_counts, current.measurement_counts)
        noise_floor = self.policy.measurement_sigma_multiplier * sqrt((1.0 / baseline_shots) + (1.0 / current_shots))
        threshold = max(self.policy.measurement_tvd_threshold, noise_floor)
        checks["measurement_distribution"] = {
            "checked": True,
            "total_variation_distance": distance,
            "threshold": threshold,
            "baseline_shots": baseline_shots,
            "current_shots": current_shots,
        }
        if distance > threshold:
            findings.append(
                self._finding(
                    "readout_phantom",
                    "Readout Forgery",
                    Severity.HIGH,
                    min(0.98, 0.65 + distance),
                    "The measurement distribution diverged beyond the configured statistical envelope.",
                    checks["measurement_distribution"],
                )
            )
