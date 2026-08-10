from __future__ import annotations

import cmath
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

_MAX_QUBITS = 62
_SCALE = 1_000_000_000_000_000
_PHASE_SPAN = 6_283_185_307
_PHASE_OFFSET = 3_141_592_653
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
    return parts[0], parts[1], parts[2]


def _canonical(data: Mapping[str, object]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _scaled(value: float) -> int:
    scaled = float(value) * _SCALE
    return int(math.floor(scaled + 0.5)) if scaled >= 0.0 else int(math.ceil(scaled - 0.5))


def _phases(request: "QSASymmetryRequest") -> tuple[int, ...]:
    seed = bytes.fromhex(request.request_id) + bytes.fromhex(request.nonce)
    values: list[int] = []
    for weight in range(request.qubits + 1):
        raw = hashlib.sha256(seed + weight.to_bytes(2, "big")).digest()
        values.append(int.from_bytes(raw[:8], "big") % _PHASE_SPAN - _PHASE_OFFSET)
    return tuple(values)


def _phase_digest(values: Sequence[int]) -> str:
    return hashlib.sha256(
        ";".join(f"{index}:{value}" for index, value in enumerate(values)).encode("ascii")
    ).hexdigest()


def _probe_weights(qubits: int) -> tuple[int, ...]:
    return tuple(dict.fromkeys((0, 1, qubits // 2, qubits - 1, qubits)))


def _reference(qubits: int, weight: int, phase_nanoradians: int) -> tuple[int, complex, float]:
    size = math.comb(qubits, weight)
    amplitude = cmath.rect(1.0 / math.sqrt(1 << qubits), phase_nanoradians * 1e-9)
    return size, amplitude, size / (1 << qubits)


@dataclass(frozen=True)
class QSASymmetryRequest:
    request_id: str
    nonce: str
    policy_digest: str
    parent_digest: str
    qubits: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _hex64(self.request_id, "request_id"))
        object.__setattr__(self, "nonce", _hex64(self.nonce, "nonce"))
        object.__setattr__(self, "policy_digest", _hex64(self.policy_digest, "policy_digest", allow_dash=True))
        object.__setattr__(self, "parent_digest", _hex64(self.parent_digest, "parent_digest", allow_dash=True))
        qubits = int(self.qubits)
        if qubits < 1 or qubits > _MAX_QUBITS:
            raise ValueError(f"qubits must be between 1 and {_MAX_QUBITS}")
        object.__setattr__(self, "qubits", qubits)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSASymmetryRequest":
        return cls(
            request_id=str(data.get("request_id", "")),
            nonce=str(data.get("nonce", "")),
            policy_digest=str(data.get("policy_digest", "-")),
            parent_digest=str(data.get("parent_digest", "-")),
            qubits=int(data.get("qubits", 0)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "QSEC-QSA-SYMMETRY/1",
            "request_id": self.request_id,
            "nonce": self.nonce,
            "policy_digest": self.policy_digest,
            "parent_digest": self.parent_digest,
            "qubits": self.qubits,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class QSASymmetryPolicy:
    min_package_version: str = "0.2.0"
    min_native_version: str = "0.2.0"
    min_abi_version: tuple[int, int, int] = (1, 5, 0)
    max_estimated_bytes: int = 1_048_576
    tolerance_scaled: int = 10_000

    def __post_init__(self) -> None:
        abi = tuple(int(value) for value in self.min_abi_version)
        if len(abi) != 3:
            raise ValueError("min_abi_version must contain three integers")
        if int(self.max_estimated_bytes) < 1 or int(self.tolerance_scaled) < 0:
            raise ValueError("symmetry policy limits are invalid")
        object.__setattr__(self, "min_abi_version", abi)
        object.__setattr__(self, "max_estimated_bytes", int(self.max_estimated_bytes))
        object.__setattr__(self, "tolerance_scaled", int(self.tolerance_scaled))

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSASymmetryPolicy":
        abi = data.get("min_abi_version", (1, 5, 0))
        if not isinstance(abi, Sequence) or isinstance(abi, (str, bytes)) or len(abi) != 3:
            raise ValueError("min_abi_version must contain three integers")
        return cls(
            min_package_version=str(data.get("min_package_version", "0.2.0")),
            min_native_version=str(data.get("min_native_version", "0.2.0")),
            min_abi_version=(int(abi[0]), int(abi[1]), int(abi[2])),
            max_estimated_bytes=int(data.get("max_estimated_bytes", 1_048_576)),
            tolerance_scaled=int(data.get("tolerance_scaled", 10_000)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "QSEC-QSA-SYMMETRY-POLICY/1",
            "min_package_version": self.min_package_version,
            "min_native_version": self.min_native_version,
            "min_abi_version": list(self.min_abi_version),
            "max_estimated_bytes": self.max_estimated_bytes,
            "tolerance_scaled": self.tolerance_scaled,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class QSASymmetryReceipt:
    accepted: bool
    request_digest: str
    package_version: str
    native_version: str
    abi_version: tuple[int, int, int]
    qubits: int
    logical_states: int
    membership: str
    class_count: int
    phase_digest: str
    validated: bool
    estimated_bytes: int
    dense_statevector_bytes: int
    dense_reduction: int
    classes: tuple[dict[str, int], ...]
    probes: tuple[dict[str, int], ...]
    max_amplitude_error_scaled: int
    max_probability_error_scaled: int
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
            "logical_states": self.logical_states,
            "membership": self.membership,
            "class_count": self.class_count,
            "phase_digest": self.phase_digest,
            "validated": self.validated,
            "estimated_bytes": self.estimated_bytes,
            "dense_statevector_bytes": self.dense_statevector_bytes,
            "dense_reduction": self.dense_reduction,
            "classes": list(self.classes),
            "probes": list(self.probes),
            "max_amplitude_error_scaled": self.max_amplitude_error_scaled,
            "max_probability_error_scaled": self.max_probability_error_scaled,
            "failures": list(self.failures),
        }

    def to_dict(self) -> dict[str, object]:
        data = self._body()
        data["receipt_digest"] = self.receipt_digest
        return data

    @classmethod
    def create(cls, **values: object) -> "QSASymmetryReceipt":
        normalized = dict(values)
        normalized["abi_version"] = tuple(int(value) for value in normalized["abi_version"])
        normalized["classes"] = tuple(dict(entry) for entry in normalized["classes"])
        normalized["probes"] = tuple(dict(entry) for entry in normalized["probes"])
        normalized["failures"] = tuple(str(value) for value in normalized["failures"])
        placeholder = cls(receipt_digest="0" * 64, **normalized)
        digest = hashlib.sha256(_canonical(placeholder._body())).hexdigest()
        return cls(receipt_digest=digest, **normalized)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSASymmetryReceipt":
        abi = data.get("abi_version", ())
        classes = data.get("classes", ())
        probes = data.get("probes", ())
        failures = data.get("failures", ())
        if not isinstance(abi, Sequence) or isinstance(abi, (str, bytes)) or len(abi) != 3:
            raise ValueError("abi_version must contain three integers")
        for name, values in (("classes", classes), ("probes", probes), ("failures", failures)):
            if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
                raise ValueError(f"{name} must be a list")
        class_values = tuple({str(key): int(value) for key, value in dict(entry).items()} for entry in classes)
        probe_values = tuple({str(key): int(value) for key, value in dict(entry).items()} for entry in probes)
        receipt = cls(
            accepted=bool(data.get("accepted", False)),
            request_digest=_hex64(str(data.get("request_digest", "")), "request_digest"),
            package_version=str(data.get("package_version", "")),
            native_version=str(data.get("native_version", "")),
            abi_version=(int(abi[0]), int(abi[1]), int(abi[2])),
            qubits=int(data.get("qubits", 0)),
            logical_states=int(data.get("logical_states", 0)),
            membership=str(data.get("membership", "")),
            class_count=int(data.get("class_count", 0)),
            phase_digest=_hex64(str(data.get("phase_digest", "")), "phase_digest"),
            validated=bool(data.get("validated", False)),
            estimated_bytes=int(data.get("estimated_bytes", 0)),
            dense_statevector_bytes=int(data.get("dense_statevector_bytes", 0)),
            dense_reduction=int(data.get("dense_reduction", 0)),
            classes=class_values,
            probes=probe_values,
            max_amplitude_error_scaled=int(data.get("max_amplitude_error_scaled", 0)),
            max_probability_error_scaled=int(data.get("max_probability_error_scaled", 0)),
            failures=tuple(str(value) for value in failures),
            receipt_digest=_hex64(str(data.get("receipt_digest", "")), "receipt_digest"),
        )
        expected = hashlib.sha256(_canonical(receipt._body())).hexdigest()
        if receipt.receipt_digest != expected:
            raise ValueError("QSA symmetry receipt digest mismatch")
        return receipt


def _class_errors(
    request: QSASymmetryRequest,
    phases: Sequence[int],
    entries: Sequence[Mapping[str, int]],
) -> tuple[int, int, bool]:
    if len(entries) != request.qubits + 1:
        return 0, 0, False
    max_amplitude = 0
    max_probability = 0
    valid = True
    for weight, entry in enumerate(entries):
        size, amplitude, probability = _reference(request.qubits, weight, phases[weight])
        if (
            int(entry.get("weight", -1)) != weight
            or int(entry.get("size", -1)) != size
            or int(entry.get("phase_nanoradians", 0)) != phases[weight]
        ):
            valid = False
            continue
        amplitude_error = max(
            abs(int(entry.get("real_scaled", 0)) - _scaled(amplitude.real)),
            abs(int(entry.get("imag_scaled", 0)) - _scaled(amplitude.imag)),
        )
        probability_error = abs(int(entry.get("probability_scaled", 0)) - _scaled(probability))
        max_amplitude = max(max_amplitude, amplitude_error)
        max_probability = max(max_probability, probability_error)
    return max_amplitude, max_probability, valid


def _probe_errors(
    request: QSASymmetryRequest,
    phases: Sequence[int],
    probes: Sequence[Mapping[str, int]],
) -> tuple[int, bool]:
    weights = _probe_weights(request.qubits)
    if len(probes) != len(weights):
        return 0, False
    maximum = 0
    valid = True
    for weight, probe in zip(weights, probes):
        basis = (1 << weight) - 1 if weight else 0
        _, amplitude, _ = _reference(request.qubits, weight, phases[weight])
        if int(probe.get("weight", -1)) != weight or int(probe.get("basis", -1)) != basis:
            valid = False
            continue
        maximum = max(
            maximum,
            abs(int(probe.get("real_scaled", 0)) - _scaled(amplitude.real)),
            abs(int(probe.get("imag_scaled", 0)) - _scaled(amplitude.imag)),
        )
    return maximum, valid


def _expected_failures(
    request: QSASymmetryRequest,
    policy: QSASymmetryPolicy,
    receipt: QSASymmetryReceipt,
) -> tuple[str, ...]:
    failures: list[str] = []
    if request.policy_digest not in {"-", policy.digest}:
        failures.append("POLICY_DIGEST")
    if _version(receipt.package_version) < _version(policy.min_package_version):
        failures.append("QSA_PACKAGE_VERSION")
    if _version(receipt.native_version) < _version(policy.min_native_version):
        failures.append("QSA_NATIVE_VERSION")
    if receipt.abi_version < policy.min_abi_version:
        failures.append("QSA_ABI_VERSION")
    if not receipt.validated:
        failures.append("QSA_VALIDATE")
    if receipt.membership != "hamming_weight":
        failures.append("SYMMETRY_MEMBERSHIP")
    if (
        receipt.qubits != request.qubits
        or receipt.logical_states != (1 << request.qubits)
        or receipt.class_count != request.qubits + 1
    ):
        failures.append("SYMMETRY_SHAPE")
    if receipt.estimated_bytes > policy.max_estimated_bytes:
        failures.append("STATE_MEMORY_LIMIT")
    phases = _phases(request)
    amplitude_error, probability_error, classes_valid = _class_errors(request, phases, receipt.classes)
    probe_error, probes_valid = _probe_errors(request, phases, receipt.probes)
    if not classes_valid or amplitude_error > policy.tolerance_scaled or probability_error > policy.tolerance_scaled:
        failures.append("CLASS_MISMATCH")
    if not probes_valid or probe_error > policy.tolerance_scaled:
        failures.append("MEMBERSHIP_PROBE")
    return tuple(dict.fromkeys(failures))


def _verify_receipt(
    request: QSASymmetryRequest,
    policy: QSASymmetryPolicy,
    receipt: QSASymmetryReceipt,
) -> None:
    phases = _phases(request)
    if receipt.phase_digest != _phase_digest(phases):
        raise ValueError("QSA symmetry receipt phase digest mismatch")
    if receipt.dense_statevector_bytes != 16 * (1 << request.qubits):
        raise ValueError("QSA symmetry receipt dense size mismatch")
    if receipt.dense_reduction != receipt.dense_statevector_bytes // max(1, receipt.estimated_bytes):
        raise ValueError("QSA symmetry receipt reduction mismatch")
    amplitude_error, probability_error, _ = _class_errors(request, phases, receipt.classes)
    if receipt.max_amplitude_error_scaled != amplitude_error:
        raise ValueError("QSA symmetry receipt amplitude error mismatch")
    if receipt.max_probability_error_scaled != probability_error:
        raise ValueError("QSA symmetry receipt probability error mismatch")
    failures = _expected_failures(request, policy, receipt)
    if receipt.failures != failures:
        raise ValueError("QSA symmetry receipt failure set mismatch")
    if receipt.accepted != (not failures):
        raise ValueError("QSA symmetry receipt acceptance mismatch")


def collect_qsa_symmetry(
    request: QSASymmetryRequest,
    policy: QSASymmetryPolicy | None = None,
) -> QSASymmetryReceipt:
    policy = policy or QSASymmetryPolicy()
    try:
        import qsa
        from qsa import QubitRegister, SymmetryState
    except ImportError as exc:
        raise RuntimeError("QSA is not installed or its native library is unavailable") from exc

    identity = QubitRegister(1)
    state = None
    try:
        package_version = str(getattr(qsa, "__version__", "unknown"))
        native_version = str(identity.native_version)
        abi_version = tuple(int(value) for value in identity.abi_version)
        phases = _phases(request)
        state = SymmetryState.hamming_weight(request.qubits)
        state.phases(value * 1e-9 for value in phases)
        validated = bool(state.validate())
        entries: list[dict[str, int]] = []
        for weight, phase in enumerate(phases):
            amplitude = complex(state.class_amplitude(weight))
            entries.append(
                {
                    "weight": weight,
                    "size": int(state.class_size(weight)),
                    "phase_nanoradians": phase,
                    "real_scaled": _scaled(amplitude.real),
                    "imag_scaled": _scaled(amplitude.imag),
                    "probability_scaled": _scaled(float(state.class_probability(weight))),
                }
            )
        probes: list[dict[str, int]] = []
        for weight in _probe_weights(request.qubits):
            basis = (1 << weight) - 1 if weight else 0
            amplitude = complex(state.amplitude(basis))
            probes.append(
                {
                    "weight": weight,
                    "basis": basis,
                    "real_scaled": _scaled(amplitude.real),
                    "imag_scaled": _scaled(amplitude.imag),
                }
            )

        class_tuple = tuple(entries)
        probe_tuple = tuple(probes)
        amplitude_error, probability_error, _ = _class_errors(request, phases, class_tuple)
        estimated_bytes = int(state.estimated_bytes)
        dense_bytes = 16 * (1 << request.qubits)
        provisional = QSASymmetryReceipt.create(
            accepted=True,
            request_digest=request.digest,
            package_version=package_version,
            native_version=native_version,
            abi_version=abi_version,
            qubits=int(state.qubit_count),
            logical_states=int(state.space_size),
            membership=str(state.membership),
            class_count=int(state.class_count),
            phase_digest=_phase_digest(phases),
            validated=validated,
            estimated_bytes=estimated_bytes,
            dense_statevector_bytes=dense_bytes,
            dense_reduction=dense_bytes // max(1, estimated_bytes),
            classes=class_tuple,
            probes=probe_tuple,
            max_amplitude_error_scaled=amplitude_error,
            max_probability_error_scaled=probability_error,
            failures=(),
        )
        failures = _expected_failures(request, policy, provisional)
        if not failures:
            return provisional
        return QSASymmetryReceipt.create(
            **{**provisional._body(), "accepted": False, "failures": failures}
        )
    finally:
        if state is not None:
            state.close()
        identity.close()


def run_qsa_symmetry(
    request: QSASymmetryRequest,
    policy: QSASymmetryPolicy | None = None,
    *,
    timeout_seconds: float = 30.0,
) -> QSASymmetryReceipt:
    policy = policy or QSASymmetryPolicy()
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
        (sys.executable, "-I", "-B", str(worker), "--symmetry"),
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
        raise ValueError(f"QSA symmetry worker failed: {error or completed.returncode}")
    try:
        data = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("QSA symmetry worker returned malformed output") from exc
    if not isinstance(data, Mapping):
        raise ValueError("QSA symmetry worker returned a non-object receipt")
    receipt = QSASymmetryReceipt.from_dict(data)
    if receipt.request_digest != request.digest:
        raise ValueError("QSA symmetry worker returned a receipt for a different request")
    _verify_receipt(request, policy, receipt)
    if completed.returncode not in {0, 2}:
        raise ValueError(f"QSA symmetry worker exited with status {completed.returncode}")
    if (completed.returncode == 0) != receipt.accepted:
        raise ValueError("QSA symmetry worker status does not match its receipt")
    return receipt
