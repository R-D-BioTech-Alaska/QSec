from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import numpy as np


@dataclass(frozen=True)
class PhysicalCheck:
    valid: bool
    violations: Tuple[str, ...]
    metrics: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "violations": list(self.violations),
            "metrics": dict(self.metrics),
        }


def _complex_value(value: Any) -> complex:
    if isinstance(value, complex):
        return value
    if isinstance(value, (int, float)):
        return complex(float(value), 0.0)
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return complex(float(value[0]), float(value[1]))
    if isinstance(value, dict) and "real" in value:
        return complex(float(value["real"]), float(value.get("imag", 0.0)))
    raise ValueError(f"cannot parse complex value: {value!r}")


def complex_array(values: Any) -> np.ndarray:
    def parse(value: Any):
        if isinstance(value, (complex, int, float, dict)):
            return _complex_value(value)
        if isinstance(value, (list, tuple)):
            if len(value) == 2 and all(isinstance(item, (int, float)) for item in value):
                return _complex_value(value)
            return [parse(item) for item in value]
        raise ValueError(f"cannot parse complex array value: {value!r}")

    return np.asarray(parse(values), dtype=np.complex128)


def validate_probabilities(values: Sequence[float], tolerance: float = 1e-9) -> PhysicalCheck:
    p = np.asarray(values, dtype=float)
    violations: List[str] = []
    if p.ndim != 1 or p.size == 0:
        return PhysicalCheck(False, ("probabilities must be a nonempty vector",), {})
    if not np.all(np.isfinite(p)):
        violations.append("probabilities contain nonfinite values")
    if np.any(p < -tolerance):
        violations.append("probabilities contain negative values")
    total = float(np.sum(p))
    if abs(total - 1.0) > tolerance:
        violations.append("probabilities do not sum to one")
    return PhysicalCheck(
        not violations,
        tuple(violations),
        {"sum": total, "minimum": float(np.min(p)), "maximum": float(np.max(p))},
    )


def validate_statevector(values: Any, tolerance: float = 1e-9) -> PhysicalCheck:
    state = complex_array(values)
    violations: List[str] = []
    if state.ndim != 1 or state.size == 0:
        return PhysicalCheck(False, ("statevector must be a nonempty vector",), {})
    if state.size & (state.size - 1):
        violations.append("statevector length is not a power of two")
    finite = np.all(np.isfinite(state.real)) and np.all(np.isfinite(state.imag))
    if not finite:
        violations.append("statevector contains nonfinite amplitudes")
    norm = float(np.vdot(state, state).real)
    if abs(norm - 1.0) > tolerance:
        violations.append("statevector norm is not one")
    return PhysicalCheck(
        not violations,
        tuple(violations),
        {"norm_squared": norm, "dimension": float(state.size)},
    )


def validate_density_matrix(values: Any, tolerance: float = 1e-9) -> PhysicalCheck:
    rho = complex_array(values)
    violations: List[str] = []
    if rho.ndim != 2 or rho.shape[0] != rho.shape[1] or rho.shape[0] == 0:
        return PhysicalCheck(False, ("density matrix must be a nonempty square matrix",), {})
    if rho.shape[0] & (rho.shape[0] - 1):
        violations.append("density matrix dimension is not a power of two")
    if not (np.all(np.isfinite(rho.real)) and np.all(np.isfinite(rho.imag))):
        violations.append("density matrix contains nonfinite values")
    hermitian_error = float(np.max(np.abs(rho - rho.conj().T)))
    if hermitian_error > tolerance:
        violations.append("density matrix is not Hermitian")
    trace = complex(np.trace(rho))
    if abs(trace.real - 1.0) > tolerance or abs(trace.imag) > tolerance:
        violations.append("density matrix trace is not one")
    hermitian_part = 0.5 * (rho + rho.conj().T)
    eigenvalues = np.linalg.eigvalsh(hermitian_part)
    min_eigenvalue = float(np.min(eigenvalues).real)
    if min_eigenvalue < -tolerance:
        violations.append("density matrix is not positive semidefinite")
    purity = float(np.trace(rho @ rho).real)
    if purity < -tolerance or purity > 1.0 + tolerance:
        violations.append("density matrix purity is outside physical bounds")
    return PhysicalCheck(
        not violations,
        tuple(violations),
        {
            "trace_real": float(trace.real),
            "trace_imag": float(trace.imag),
            "hermitian_error": hermitian_error,
            "minimum_eigenvalue": min_eigenvalue,
            "purity": purity,
            "dimension": float(rho.shape[0]),
        },
    )


def validate_bloch_vector(values: Sequence[float], tolerance: float = 1e-9) -> PhysicalCheck:
    vector = np.asarray(values, dtype=float)
    violations: List[str] = []
    if vector.shape != (3,):
        return PhysicalCheck(False, ("Bloch vector must contain exactly three values",), {})
    if not np.all(np.isfinite(vector)):
        violations.append("Bloch vector contains nonfinite values")
    radius = float(np.linalg.norm(vector))
    if radius > 1.0 + tolerance:
        violations.append("Bloch vector lies outside the unit ball")
    return PhysicalCheck(not violations, tuple(violations), {"radius": radius})


def validate_readout_matrix(values: Any, tolerance: float = 1e-9) -> PhysicalCheck:
    matrix = np.asarray(values, dtype=float)
    violations: List[str] = []
    if matrix.shape != (2, 2):
        return PhysicalCheck(False, ("readout matrix must be 2x2",), {})
    if not np.all(np.isfinite(matrix)):
        violations.append("readout matrix contains nonfinite values")
    if np.any(matrix < -tolerance) or np.any(matrix > 1.0 + tolerance):
        violations.append("readout matrix entries are outside probability bounds")
    column_sums = np.sum(matrix, axis=0)
    if np.max(np.abs(column_sums - 1.0)) > tolerance:
        violations.append("readout matrix columns do not sum to one")
    return PhysicalCheck(
        not violations,
        tuple(violations),
        {
            "column_0_sum": float(column_sums[0]),
            "column_1_sum": float(column_sums[1]),
        },
    )


def validate_relaxation_times(t1: Sequence[float], t2: Sequence[float], tolerance: float = 1e-9) -> PhysicalCheck:
    t1_values = np.asarray(t1, dtype=float)
    t2_values = np.asarray(t2, dtype=float)
    violations: List[str] = []
    if t1_values.shape != t2_values.shape:
        return PhysicalCheck(False, ("T1 and T2 lengths do not match",), {})
    if t1_values.ndim != 1:
        return PhysicalCheck(False, ("T1 and T2 must be vectors",), {})
    if t1_values.size == 0:
        return PhysicalCheck(True, (), {"qubits": 0.0})
    if not (np.all(np.isfinite(t1_values)) and np.all(np.isfinite(t2_values))):
        violations.append("T1 or T2 contains nonfinite values")
    if np.any(t1_values <= 0.0) or np.any(t2_values <= 0.0):
        violations.append("T1 and T2 must be positive")
    excess = t2_values - (2.0 * t1_values)
    if np.any(excess > tolerance):
        violations.append("T2 exceeds the Markovian bound of 2*T1")
    ratio = np.divide(t2_values, t1_values, out=np.zeros_like(t2_values), where=t1_values != 0)
    return PhysicalCheck(
        not violations,
        tuple(violations),
        {
            "qubits": float(t1_values.size),
            "minimum_t1": float(np.min(t1_values)),
            "minimum_t2": float(np.min(t2_values)),
            "maximum_t2_over_t1": float(np.max(ratio)),
        },
    )


def total_variation_distance(first: Dict[str, int], second: Dict[str, int]) -> float:
    first_total = float(sum(first.values()))
    second_total = float(sum(second.values()))
    if first_total <= 0 or second_total <= 0:
        raise ValueError("both count dictionaries must contain at least one observation")
    keys = set(first) | set(second)
    distance = 0.0
    for key in keys:
        p = first.get(key, 0) / first_total
        q = second.get(key, 0) / second_total
        distance += abs(p - q)
    return 0.5 * distance


def pure_state_fidelity(first: Any, second: Any) -> float:
    a = complex_array(first).reshape(-1)
    b = complex_array(second).reshape(-1)
    if a.shape != b.shape:
        raise ValueError("statevector dimensions do not match")
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na <= 0.0 or nb <= 0.0:
        raise ValueError("statevectors must have nonzero norm")
    overlap = np.vdot(a / na, b / nb)
    return float(np.clip(abs(overlap) ** 2, 0.0, 1.0))


def validate_state_payload(payload: Dict[str, Any], tolerance: float = 1e-9) -> PhysicalCheck:
    kind = str(payload.get("kind", "")).strip().lower()
    values = payload.get("values")
    if kind == "statevector":
        return validate_statevector(values, tolerance=tolerance)
    if kind == "density_matrix":
        return validate_density_matrix(values, tolerance=tolerance)
    if kind == "probabilities":
        return validate_probabilities(values, tolerance=tolerance)
    if kind == "bloch":
        return validate_bloch_vector(values, tolerance=tolerance)
    return PhysicalCheck(False, (f"unsupported state kind: {kind or '<missing>'}",), {})
