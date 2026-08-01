from __future__ import annotations

from typing import Any

from .quantum_core import QuantumProtocolError, QuantumRequest, QuantumWitness, witness_from_state


def _complex_value(value: Any) -> complex:
    if isinstance(value, complex):
        return value
    if hasattr(value, "real") and hasattr(value, "imag"):
        real = value.real() if callable(value.real) else value.real
        imag = value.imag() if callable(value.imag) else value.imag
        return complex(float(real), float(imag))
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return complex(float(value[0]), float(value[1]))
    return complex(value)


def execute_with_qsa(request: QuantumRequest) -> QuantumWitness:
    try:
        from qsa import QubitRegister
    except ImportError as exc:
        try:
            from qubit_native import QubitRegister
        except ImportError:
            raise RuntimeError("QSA is not installed or its native library is unavailable") from exc

    state = QubitRegister(request.qubits)
    try:
        for qubit in range(request.qubits):
            if request.initial_basis & (1 << qubit):
                state.x(qubit)
        for gate in request.gates:
            name = gate.name.lower()
            if name in {"x", "y", "z", "h", "s", "t"}:
                getattr(state, name)(gate.first)
            elif name in {"rx", "ry", "rz"}:
                getattr(state, name)(gate.first, gate.angle_nanoradians * 1e-9)
            elif name == "cnot":
                state.cnot(gate.first, gate.second)
            elif name == "cz":
                state.cz(gate.first, gate.second)
            elif name == "swap":
                state.swap(gate.first, gate.second)
            else:
                raise QuantumProtocolError(f"QSA adapter does not support {gate.name}")
        amplitudes = [_complex_value(state.amplitude(index)) for index in range(1 << request.qubits)]
        return witness_from_state(request, amplitudes, "qsa-native")
    finally:
        state.close()
