from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .quantum_core import QuantumGate, QuantumRequest, witness_from_state

_MAX_QUBITS = 64
_MAX_GATES = 100000
_SCALE = 10_000_000_000
_HEX64 = frozenset("0123456789abcdef")


def _hex64(value: str, field: str, *, allow_dash: bool = False) -> str:
    text = str(value).strip().lower()
    if allow_dash and text == "-":
        return text
    if len(text) != 64 or any(ch not in _HEX64 for ch in text):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return text


def _version(value: str) -> tuple[int, int, int]:
    parts = [int(item) for item in re.findall(r"\d+", str(value))[:3]]
    parts.extend([0] * (3 - len(parts)))
    return tuple(parts)  # type: ignore[return-value]


def _scaled(value: float) -> int:
    scaled = float(value) * _SCALE
    return int(math.floor(scaled + 0.5)) if scaled >= 0.0 else int(math.ceil(scaled - 0.5))


def _canonical(data: Mapping[str, object]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _operations(request: "QSAEvidenceRequest") -> tuple[tuple[object, ...], ...]:
    values: list[tuple[object, ...]] = []
    for qubit in range(request.qubits):
        if request.initial_basis & (1 << qubit):
            values.append(("x", qubit))
    for gate in request.gates:
        name = gate.name.lower()
        if gate.second >= 0:
            values.append((name, gate.first, gate.second))
        elif name in {"rx", "ry", "rz"}:
            values.append((name, gate.first, gate.angle_nanoradians * 1e-9))
        else:
            values.append((name, gate.first))
    return tuple(values)


def _probe_indices(request: "QSAEvidenceRequest", count: int) -> tuple[int, ...]:
    limit = 1 << request.qubits
    target = min(max(1, int(count)), limit)
    values = [0, request.initial_basis, limit - 1]
    seen: set[int] = set()
    ordered: list[int] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
        if len(ordered) >= target:
            return tuple(ordered)
    seed = bytes.fromhex(request.digest)
    counter = 0
    while len(ordered) < target:
        raw = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        value = int.from_bytes(raw[:8], "big")
        if request.qubits < 64:
            value &= (1 << request.qubits) - 1
        if value not in seen:
            seen.add(value)
            ordered.append(value)
        counter += 1
    return tuple(ordered)


def _probe_state(
    state: object,
    request: "QSAEvidenceRequest",
    indices: Sequence[int],
) -> tuple[tuple[dict[str, object], ...], str, int, int]:
    probes: list[dict[str, object]] = []
    for index in indices:
        value = complex(state.amplitude(index))
        probes.append(
            {
                "basis": str(index),
                "real_scaled": _scaled(value.real),
                "imag_scaled": _scaled(value.imag),
            }
        )
    marginals = [_scaled(float(state.probability_one(qubit))) for qubit in range(request.qubits)]
    marginal_digest = hashlib.sha256(
        ";".join(f"{index}:{value}" for index, value in enumerate(marginals)).encode("ascii")
    ).hexdigest()
    return tuple(probes), marginal_digest, min(marginals, default=0), max(marginals, default=0)


def _structure(state: object, qubits: int) -> tuple[str, dict[str, int], int, int]:
    digest = hashlib.sha256()
    by_kind: dict[str, int] = {}
    peak_size = 0
    peak_nonzero = 0
    for qubit in range(qubits):
        kind = str(state.component_kind(qubit))
        size = int(state.component_size(qubit))
        nonzero = int(state.component_nonzero_count(qubit))
        by_kind[kind] = by_kind.get(kind, 0) + 1
        peak_size = max(peak_size, size)
        peak_nonzero = max(peak_nonzero, nonzero)
        digest.update(f"{qubit}:{kind}:{size}:{nonzero}\n".encode("utf-8"))
    return digest.hexdigest(), dict(sorted(by_kind.items())), peak_size, peak_nonzero


@dataclass(frozen=True)
class QSAEvidenceRequest:
    request_id: str
    nonce: str
    policy_digest: str
    parent_digest: str
    qubits: int
    initial_basis: int
    gates: tuple[QuantumGate, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _hex64(self.request_id, "request_id"))
        object.__setattr__(self, "nonce", _hex64(self.nonce, "nonce"))
        object.__setattr__(self, "policy_digest", _hex64(self.policy_digest, "policy_digest", allow_dash=True))
        object.__setattr__(self, "parent_digest", _hex64(self.parent_digest, "parent_digest", allow_dash=True))
        qubits = int(self.qubits)
        initial = int(self.initial_basis)
        gates = tuple(self.gates)
        if qubits < 1 or qubits > _MAX_QUBITS:
            raise ValueError(f"qubits must be between 1 and {_MAX_QUBITS}")
        if initial < 0 or initial >= (1 << qubits):
            raise ValueError("initial_basis is outside the register")
        if len(gates) > _MAX_GATES:
            raise ValueError(f"gate count exceeds {_MAX_GATES}")
        for gate in gates:
            if gate.first >= qubits or (gate.second >= qubits and gate.second >= 0):
                raise ValueError("gate target is outside the register")
        object.__setattr__(self, "qubits", qubits)
        object.__setattr__(self, "initial_basis", initial)
        object.__setattr__(self, "gates", gates)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSAEvidenceRequest":
        raw_gates = data.get("gates", ())
        if not isinstance(raw_gates, Sequence) or isinstance(raw_gates, (str, bytes)):
            raise ValueError("gates must be a list")
        gates: list[QuantumGate] = []
        for item in raw_gates:
            if not isinstance(item, Mapping):
                raise ValueError("every gate must be an object")
            gates.append(QuantumGate.from_dict(item))
        return cls(
            request_id=str(data.get("request_id", "")),
            nonce=str(data.get("nonce", "")),
            policy_digest=str(data.get("policy_digest", "-")),
            parent_digest=str(data.get("parent_digest", "-")),
            qubits=int(data.get("qubits", 0)),
            initial_basis=int(data.get("initial_basis", 0)),
            gates=tuple(gates),
        )

    @classmethod
    def from_quantum_request(cls, request: QuantumRequest) -> "QSAEvidenceRequest":
        return cls(
            request.request_id,
            request.nonce,
            request.policy_digest,
            request.parent_digest,
            request.qubits,
            request.initial_basis,
            request.gates,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "nonce": self.nonce,
            "policy_digest": self.policy_digest,
            "parent_digest": self.parent_digest,
            "qubits": self.qubits,
            "initial_basis": self.initial_basis,
            "gates": [gate.to_dict() for gate in self.gates],
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class QSAEvidencePolicy:
    min_package_version: str = "0.2.0"
    min_native_version: str = "0.2.0"
    min_abi_version: tuple[int, int, int] = (1, 5, 0)
    max_estimated_bytes: int = 268_435_456
    max_qsc_bytes: int = 268_435_456
    full_state_qubits: int = 12
    probe_count: int = 12

    def __post_init__(self) -> None:
        object.__setattr__(self, "min_abi_version", tuple(int(value) for value in self.min_abi_version))
        for name in ("max_estimated_bytes", "max_qsc_bytes", "full_state_qubits", "probe_count"):
            value = int(getattr(self, name))
            if value < 1:
                raise ValueError(f"{name} must be positive")
            object.__setattr__(self, name, value)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSAEvidencePolicy":
        abi = data.get("min_abi_version", (1, 5, 0))
        if not isinstance(abi, Sequence) or isinstance(abi, (str, bytes)) or len(abi) != 3:
            raise ValueError("min_abi_version must contain three integers")
        return cls(
            min_package_version=str(data.get("min_package_version", "0.2.0")),
            min_native_version=str(data.get("min_native_version", "0.2.0")),
            min_abi_version=tuple(int(value) for value in abi),
            max_estimated_bytes=int(data.get("max_estimated_bytes", 268_435_456)),
            max_qsc_bytes=int(data.get("max_qsc_bytes", 268_435_456)),
            full_state_qubits=int(data.get("full_state_qubits", 12)),
            probe_count=int(data.get("probe_count", 12)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "min_package_version": self.min_package_version,
            "min_native_version": self.min_native_version,
            "min_abi_version": list(self.min_abi_version),
            "max_estimated_bytes": self.max_estimated_bytes,
            "max_qsc_bytes": self.max_qsc_bytes,
            "full_state_qubits": self.full_state_qubits,
            "probe_count": self.probe_count,
        }


@dataclass(frozen=True)
class QSAEvidenceReceipt:
    accepted: bool
    request_digest: str
    package_version: str
    native_version: str
    abi_version: tuple[int, int, int]
    qubits: int
    gate_count: int
    operation_count: int
    compiled_steps: int
    validated: bool
    component_count: int
    component_kinds: dict[str, int]
    peak_component_size: int
    peak_component_nonzero: int
    structure_digest: str
    estimated_bytes: int
    dense_statevector_bytes: int
    dense_reduction: int
    qsc_bytes: int
    qsc_digest: str
    qsc_roundtrip_digest: str
    qsc_byte_stable: bool
    roundtrip_equivalent: bool
    marginal_digest: str
    marginal_min_scaled: int
    marginal_max_scaled: int
    probes: tuple[dict[str, object], ...]
    state_digest: str | None
    probability_digest: str | None
    failures: tuple[str, ...]
    receipt_digest: str

    def _body(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "request_digest": self.request_digest,
            "package_version": self.package_version,
            "native_version": self.native_version,
            "abi_version": list(self.abi_version),
            "qubits": self.qubits,
            "gate_count": self.gate_count,
            "operation_count": self.operation_count,
            "compiled_steps": self.compiled_steps,
            "validated": self.validated,
            "component_count": self.component_count,
            "component_kinds": dict(sorted(self.component_kinds.items())),
            "peak_component_size": self.peak_component_size,
            "peak_component_nonzero": self.peak_component_nonzero,
            "structure_digest": self.structure_digest,
            "estimated_bytes": self.estimated_bytes,
            "dense_statevector_bytes": self.dense_statevector_bytes,
            "dense_reduction": self.dense_reduction,
            "qsc_bytes": self.qsc_bytes,
            "qsc_digest": self.qsc_digest,
            "qsc_roundtrip_digest": self.qsc_roundtrip_digest,
            "qsc_byte_stable": self.qsc_byte_stable,
            "roundtrip_equivalent": self.roundtrip_equivalent,
            "marginal_digest": self.marginal_digest,
            "marginal_min_scaled": self.marginal_min_scaled,
            "marginal_max_scaled": self.marginal_max_scaled,
            "probes": list(self.probes),
            "state_digest": self.state_digest,
            "probability_digest": self.probability_digest,
            "failures": list(self.failures),
        }

    def to_dict(self) -> dict[str, object]:
        data = self._body()
        data["receipt_digest"] = self.receipt_digest
        return data

    @classmethod
    def create(cls, **values: object) -> "QSAEvidenceReceipt":
        placeholder = cls(receipt_digest="0" * 64, **values)  # type: ignore[arg-type]
        digest = hashlib.sha256(_canonical(placeholder._body())).hexdigest()
        return cls(receipt_digest=digest, **values)  # type: ignore[arg-type]

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSAEvidenceReceipt":
        probes = data.get("probes", ())
        if not isinstance(probes, Sequence) or isinstance(probes, (str, bytes)):
            raise ValueError("probes must be a list")
        receipt = cls(
            accepted=bool(data.get("accepted", False)),
            request_digest=str(data.get("request_digest", "")),
            package_version=str(data.get("package_version", "")),
            native_version=str(data.get("native_version", "")),
            abi_version=tuple(int(value) for value in data.get("abi_version", (0, 0, 0))),  # type: ignore[arg-type]
            qubits=int(data.get("qubits", 0)),
            gate_count=int(data.get("gate_count", 0)),
            operation_count=int(data.get("operation_count", 0)),
            compiled_steps=int(data.get("compiled_steps", 0)),
            validated=bool(data.get("validated", False)),
            component_count=int(data.get("component_count", 0)),
            component_kinds={str(key): int(value) for key, value in dict(data.get("component_kinds", {})).items()},
            peak_component_size=int(data.get("peak_component_size", 0)),
            peak_component_nonzero=int(data.get("peak_component_nonzero", 0)),
            structure_digest=str(data.get("structure_digest", "")),
            estimated_bytes=int(data.get("estimated_bytes", 0)),
            dense_statevector_bytes=int(data.get("dense_statevector_bytes", 0)),
            dense_reduction=int(data.get("dense_reduction", 0)),
            qsc_bytes=int(data.get("qsc_bytes", 0)),
            qsc_digest=str(data.get("qsc_digest", "")),
            qsc_roundtrip_digest=str(data.get("qsc_roundtrip_digest", "")),
            qsc_byte_stable=bool(data.get("qsc_byte_stable", False)),
            roundtrip_equivalent=bool(data.get("roundtrip_equivalent", False)),
            marginal_digest=str(data.get("marginal_digest", "")),
            marginal_min_scaled=int(data.get("marginal_min_scaled", 0)),
            marginal_max_scaled=int(data.get("marginal_max_scaled", 0)),
            probes=tuple(dict(value) for value in probes),  # type: ignore[arg-type]
            state_digest=None if data.get("state_digest") is None else str(data.get("state_digest")),
            probability_digest=None if data.get("probability_digest") is None else str(data.get("probability_digest")),
            failures=tuple(str(value) for value in data.get("failures", ())),  # type: ignore[arg-type]
            receipt_digest=str(data.get("receipt_digest", "")),
        )
        expected = hashlib.sha256(_canonical(receipt._body())).hexdigest()
        if receipt.receipt_digest != expected:
            raise ValueError("QSA evidence receipt digest mismatch")
        return receipt


def collect_qsa_evidence(
    request: QSAEvidenceRequest,
    policy: QSAEvidencePolicy | None = None,
) -> QSAEvidenceReceipt:
    policy = policy or QSAEvidencePolicy()
    try:
        import qsa
        from qsa import OperationPlan, QubitRegister
    except ImportError as exc:
        raise RuntimeError("QSA is not installed or its native library is unavailable") from exc

    package_version = str(getattr(qsa, "__version__", "unknown"))
    operations = _operations(request)
    plan = OperationPlan(operations)
    state = QubitRegister(request.qubits)
    restored = None
    try:
        native_version = str(state.native_version)
        abi_version = tuple(int(value) for value in state.abi_version)
        compiled_steps = int(plan.compiled_step_count(state))
        state.apply_plan(plan)
        validated = bool(state.validate())
        component_count = int(state.component_count)
        estimated_bytes = int(state.estimated_bytes)
        structure_digest, component_kinds, peak_size, peak_nonzero = _structure(state, request.qubits)
        indices = _probe_indices(request, policy.probe_count)
        probes, marginal_digest, marginal_min, marginal_max = _probe_state(state, request, indices)

        failures: list[str] = []
        if _version(package_version) < _version(policy.min_package_version):
            failures.append("QSA_PACKAGE_VERSION")
        if _version(native_version) < _version(policy.min_native_version):
            failures.append("QSA_NATIVE_VERSION")
        if abi_version < policy.min_abi_version:
            failures.append("QSA_ABI_VERSION")
        if not validated:
            failures.append("QSA_VALIDATE")
        if estimated_bytes > policy.max_estimated_bytes:
            failures.append("STATE_MEMORY_LIMIT")

        qsc = state.encode_qsc()
        qsc_digest = hashlib.sha256(qsc).hexdigest()
        qsc_bytes = len(qsc)
        if qsc_bytes > policy.max_qsc_bytes:
            failures.append("QSC_SIZE_LIMIT")

        restored = QubitRegister.decode_qsc(qsc)
        restored_valid = bool(restored.validate())
        restored_qsc = restored.encode_qsc()
        roundtrip_digest = hashlib.sha256(restored_qsc).hexdigest()
        restored_probes, restored_marginal_digest, _, _ = _probe_state(restored, request, indices)
        roundtrip_equivalent = (
            restored_valid
            and restored_probes == probes
            and restored_marginal_digest == marginal_digest
        )

        state_digest: str | None = None
        probability_digest: str | None = None
        if request.qubits <= policy.full_state_qubits and request.qubits <= 12:
            legacy_request = QuantumRequest(
                request.request_id,
                request.nonce,
                request.policy_digest,
                request.parent_digest,
                request.qubits,
                request.initial_basis,
                request.gates,
            )
            amplitudes = [complex(state.amplitude(index)) for index in range(1 << request.qubits)]
            restored_amplitudes = [
                complex(restored.amplitude(index)) for index in range(1 << request.qubits)
            ]
            original = witness_from_state(legacy_request, amplitudes, "qsa-native")
            replay = witness_from_state(legacy_request, restored_amplitudes, "qsa-native")
            state_digest = original.state_digest
            probability_digest = original.probability_digest
            roundtrip_equivalent = (
                roundtrip_equivalent and original.consensus_digest == replay.consensus_digest
            )

        if not roundtrip_equivalent:
            failures.append("QSC_ROUNDTRIP")

        dense_bytes = 16 * (1 << request.qubits)
        return QSAEvidenceReceipt.create(
            accepted=not failures,
            request_digest=request.digest,
            package_version=package_version,
            native_version=native_version,
            abi_version=abi_version,
            qubits=request.qubits,
            gate_count=len(request.gates),
            operation_count=len(operations),
            compiled_steps=compiled_steps,
            validated=validated,
            component_count=component_count,
            component_kinds=component_kinds,
            peak_component_size=peak_size,
            peak_component_nonzero=peak_nonzero,
            structure_digest=structure_digest,
            estimated_bytes=estimated_bytes,
            dense_statevector_bytes=dense_bytes,
            dense_reduction=dense_bytes // max(1, estimated_bytes),
            qsc_bytes=qsc_bytes,
            qsc_digest=qsc_digest,
            qsc_roundtrip_digest=roundtrip_digest,
            qsc_byte_stable=qsc_digest == roundtrip_digest,
            roundtrip_equivalent=roundtrip_equivalent,
            marginal_digest=marginal_digest,
            marginal_min_scaled=marginal_min,
            marginal_max_scaled=marginal_max,
            probes=probes,
            state_digest=state_digest,
            probability_digest=probability_digest,
            failures=tuple(failures),
        )
    finally:
        if restored is not None:
            restored.close()
        state.close()
        plan.close()


def run_qsa_evidence(
    request: QSAEvidenceRequest,
    policy: QSAEvidencePolicy | None = None,
    *,
    timeout_seconds: float = 30.0,
) -> QSAEvidenceReceipt:
    policy = policy or QSAEvidencePolicy()
    worker = Path(__file__).with_name("qsa_worker.py").resolve()
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
    }
    for key in (
        "SYSTEMROOT",
        "WINDIR",
        "PATHEXT",
        "QSA_NATIVE_LIB",
        "QUBIT_NATIVE_LIB",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ):
        if key in os.environ:
            environment[key] = os.environ[key]
    payload = _canonical({"request": request.to_dict(), "policy": policy.to_dict()})
    completed = subprocess.run(
        (sys.executable, "-I", "-B", str(worker), "--evidence"),
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_seconds,
        env=environment,
        cwd=str(Path.cwd()),
    )
    if not completed.stdout:
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"QSA evidence worker failed: {error or completed.returncode}")
    try:
        data = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("QSA evidence worker returned malformed output") from exc
    if not isinstance(data, Mapping):
        raise ValueError("QSA evidence worker returned a non-object receipt")
    return QSAEvidenceReceipt.from_dict(data)
