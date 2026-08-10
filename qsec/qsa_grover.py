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

_MAX_QUBITS = 62
_MAX_MARKED = 4096
_SCALE = 1_000_000_000_000_000
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


def _reference(qubits: int, marked_count: int, iterations: int) -> tuple[float, complex, complex]:
    space = 1 << qubits
    theta = math.asin(math.sqrt(marked_count / space))
    angle = (2 * iterations + 1) * theta
    marked = complex(math.sin(angle) / math.sqrt(marked_count), 0.0)
    unmarked = complex(math.cos(angle) / math.sqrt(space - marked_count), 0.0)
    return math.sin(angle) ** 2, marked, unmarked


def _optimal_iterations(qubits: int, marked_count: int) -> int:
    theta = math.asin(math.sqrt(marked_count / (1 << qubits)))
    ideal = math.pi / (4.0 * theta) - 0.5
    if ideal <= 0.0:
        return 0
    lower = int(math.floor(ideal))
    upper = lower + 1

    def probability(count: int) -> float:
        return math.sin((2 * count + 1) * theta) ** 2

    return upper if probability(upper) > probability(lower) else lower


def _challenge_indices(request: "QSAGroverRequest") -> tuple[int, ...]:
    space = 1 << request.qubits
    seed = bytes.fromhex(request.request_id) + bytes.fromhex(request.nonce)
    values: list[int] = []
    seen: set[int] = set()
    counter = 0
    while len(values) < request.marked_count:
        raw = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        value = int.from_bytes(raw[:8], "big") & (space - 1)
        if value not in seen:
            seen.add(value)
            values.append(value)
        counter += 1
    return tuple(sorted(values))


def _unmarked_probe(request: "QSAGroverRequest", marked: set[int]) -> int:
    space = 1 << request.qubits
    seed = bytes.fromhex(request.digest)
    counter = 0
    while True:
        raw = hashlib.sha256(seed + b"probe" + counter.to_bytes(8, "big")).digest()
        value = int.from_bytes(raw[:8], "big") & (space - 1)
        if value not in marked:
            return value
        counter += 1


@dataclass(frozen=True)
class QSAGroverRequest:
    request_id: str
    nonce: str
    policy_digest: str
    parent_digest: str
    qubits: int
    marked_count: int
    iterations: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _hex64(self.request_id, "request_id"))
        object.__setattr__(self, "nonce", _hex64(self.nonce, "nonce"))
        object.__setattr__(self, "policy_digest", _hex64(self.policy_digest, "policy_digest", allow_dash=True))
        object.__setattr__(self, "parent_digest", _hex64(self.parent_digest, "parent_digest", allow_dash=True))
        qubits = int(self.qubits)
        marked_count = int(self.marked_count)
        if qubits < 1 or qubits > _MAX_QUBITS:
            raise ValueError(f"qubits must be between 1 and {_MAX_QUBITS}")
        if marked_count < 1 or marked_count >= (1 << qubits):
            raise ValueError("marked_count must be inside the search space")
        if marked_count > _MAX_MARKED:
            raise ValueError(f"marked_count exceeds {_MAX_MARKED}")
        if self.iterations is not None and int(self.iterations) < 0:
            raise ValueError("iterations cannot be negative")
        object.__setattr__(self, "qubits", qubits)
        object.__setattr__(self, "marked_count", marked_count)
        if self.iterations is not None:
            object.__setattr__(self, "iterations", int(self.iterations))

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSAGroverRequest":
        raw_iterations = data.get("iterations", "optimal")
        iterations = None if str(raw_iterations).strip().lower() == "optimal" else int(raw_iterations)
        return cls(
            request_id=str(data.get("request_id", "")),
            nonce=str(data.get("nonce", "")),
            policy_digest=str(data.get("policy_digest", "-")),
            parent_digest=str(data.get("parent_digest", "-")),
            qubits=int(data.get("qubits", 0)),
            marked_count=int(data.get("marked_count", 0)),
            iterations=iterations,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "nonce": self.nonce,
            "policy_digest": self.policy_digest,
            "parent_digest": self.parent_digest,
            "qubits": self.qubits,
            "marked_count": self.marked_count,
            "iterations": "optimal" if self.iterations is None else self.iterations,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class QSAGroverPolicy:
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
            raise ValueError("Grover policy limits are invalid")
        object.__setattr__(self, "min_abi_version", abi)
        object.__setattr__(self, "max_estimated_bytes", int(self.max_estimated_bytes))
        object.__setattr__(self, "tolerance_scaled", int(self.tolerance_scaled))

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSAGroverPolicy":
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
class QSAGroverReceipt:
    accepted: bool
    request_digest: str
    package_version: str
    native_version: str
    abi_version: tuple[int, int, int]
    qubits: int
    logical_states: int
    marked_count: int
    challenge_digest: str
    marked_probe: int
    unmarked_probe: int
    iterations: int
    optimal_iterations: int
    reference_optimal_iterations: int
    validated: bool
    explicit_marked_indices: bool
    estimated_bytes: int
    dense_statevector_bytes: int
    dense_reduction: int
    success_probability_scaled: int
    reference_probability_scaled: int
    probability_error_scaled: int
    marked_amplitude_real_scaled: int
    marked_amplitude_imag_scaled: int
    reference_marked_real_scaled: int
    unmarked_amplitude_real_scaled: int
    unmarked_amplitude_imag_scaled: int
    reference_unmarked_real_scaled: int
    marked_probe_real_scaled: int
    marked_probe_imag_scaled: int
    unmarked_probe_real_scaled: int
    unmarked_probe_imag_scaled: int
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
            "marked_count": self.marked_count,
            "challenge_digest": self.challenge_digest,
            "marked_probe": str(self.marked_probe),
            "unmarked_probe": str(self.unmarked_probe),
            "iterations": self.iterations,
            "optimal_iterations": self.optimal_iterations,
            "reference_optimal_iterations": self.reference_optimal_iterations,
            "validated": self.validated,
            "explicit_marked_indices": self.explicit_marked_indices,
            "estimated_bytes": self.estimated_bytes,
            "dense_statevector_bytes": self.dense_statevector_bytes,
            "dense_reduction": self.dense_reduction,
            "success_probability_scaled": self.success_probability_scaled,
            "reference_probability_scaled": self.reference_probability_scaled,
            "probability_error_scaled": self.probability_error_scaled,
            "marked_amplitude_real_scaled": self.marked_amplitude_real_scaled,
            "marked_amplitude_imag_scaled": self.marked_amplitude_imag_scaled,
            "reference_marked_real_scaled": self.reference_marked_real_scaled,
            "unmarked_amplitude_real_scaled": self.unmarked_amplitude_real_scaled,
            "unmarked_amplitude_imag_scaled": self.unmarked_amplitude_imag_scaled,
            "reference_unmarked_real_scaled": self.reference_unmarked_real_scaled,
            "marked_probe_real_scaled": self.marked_probe_real_scaled,
            "marked_probe_imag_scaled": self.marked_probe_imag_scaled,
            "unmarked_probe_real_scaled": self.unmarked_probe_real_scaled,
            "unmarked_probe_imag_scaled": self.unmarked_probe_imag_scaled,
            "failures": list(self.failures),
        }

    def to_dict(self) -> dict[str, object]:
        data = self._body()
        data["receipt_digest"] = self.receipt_digest
        return data

    @classmethod
    def create(cls, **values: object) -> "QSAGroverReceipt":
        placeholder = cls(receipt_digest="0" * 64, **values)
        digest = hashlib.sha256(_canonical(placeholder._body())).hexdigest()
        return cls(receipt_digest=digest, **values)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QSAGroverReceipt":
        abi = data.get("abi_version", ())
        failures = data.get("failures", ())
        if not isinstance(abi, Sequence) or isinstance(abi, (str, bytes)) or len(abi) != 3:
            raise ValueError("abi_version must contain three integers")
        if not isinstance(failures, Sequence) or isinstance(failures, (str, bytes)):
            raise ValueError("failures must be a list")
        values = dict(data)
        values.pop("receipt_digest", None)
        values["abi_version"] = (int(abi[0]), int(abi[1]), int(abi[2]))
        values["marked_probe"] = int(data.get("marked_probe", 0))
        values["unmarked_probe"] = int(data.get("unmarked_probe", 0))
        values["failures"] = tuple(str(value) for value in failures)
        receipt = cls(receipt_digest=_hex64(str(data.get("receipt_digest", "")), "receipt_digest"), **values)
        expected = hashlib.sha256(_canonical(receipt._body())).hexdigest()
        if receipt.receipt_digest != expected:
            raise ValueError("QSA Grover receipt digest mismatch")
        return receipt


def _verify_receipt(
    request: QSAGroverRequest,
    policy: QSAGroverPolicy,
    receipt: QSAGroverReceipt,
) -> None:
    marked_indices = _challenge_indices(request)
    marked_set = set(marked_indices)
    unmarked_probe = _unmarked_probe(request, marked_set)
    challenge_digest = hashlib.sha256(
        ",".join(str(value) for value in marked_indices).encode("ascii")
    ).hexdigest()
    expected_optimal = _optimal_iterations(request.qubits, request.marked_count)
    iterations = expected_optimal if request.iterations is None else request.iterations
    reference_probability, reference_marked, reference_unmarked = _reference(
        request.qubits, request.marked_count, iterations
    )
    expected = {
        "qubits": request.qubits,
        "logical_states": 1 << request.qubits,
        "marked_count": request.marked_count,
        "challenge_digest": challenge_digest,
        "marked_probe": marked_indices[0],
        "unmarked_probe": unmarked_probe,
        "iterations": iterations,
        "reference_optimal_iterations": expected_optimal,
        "dense_statevector_bytes": 16 * (1 << request.qubits),
        "reference_probability_scaled": _scaled(reference_probability),
        "reference_marked_real_scaled": _scaled(reference_marked.real),
        "reference_unmarked_real_scaled": _scaled(reference_unmarked.real),
    }
    for field, value in expected.items():
        if getattr(receipt, field) != value:
            raise ValueError(f"QSA Grover receipt {field} mismatch")
    if receipt.optimal_iterations != expected_optimal:
        raise ValueError("QSA Grover receipt optimal iteration mismatch")
    if receipt.dense_reduction != receipt.dense_statevector_bytes // max(1, receipt.estimated_bytes):
        raise ValueError("QSA Grover receipt reduction mismatch")

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
    if not receipt.explicit_marked_indices:
        failures.append("CHALLENGE_MEMBERSHIP")
    if receipt.estimated_bytes > policy.max_estimated_bytes:
        failures.append("STATE_MEMORY_LIMIT")
    probability_error = abs(receipt.success_probability_scaled - receipt.reference_probability_scaled)
    if abs(receipt.probability_error_scaled - probability_error) > 1:
        raise ValueError("QSA Grover receipt probability error mismatch")
    if probability_error > policy.tolerance_scaled:
        failures.append("PROBABILITY_MISMATCH")
    marked_error = abs(receipt.marked_amplitude_real_scaled - receipt.reference_marked_real_scaled)
    unmarked_error = abs(receipt.unmarked_amplitude_real_scaled - receipt.reference_unmarked_real_scaled)
    if max(marked_error, unmarked_error, abs(receipt.marked_amplitude_imag_scaled), abs(receipt.unmarked_amplitude_imag_scaled)) > policy.tolerance_scaled:
        failures.append("AMPLITUDE_MISMATCH")
    marked_probe_error = max(
        abs(receipt.marked_probe_real_scaled - receipt.marked_amplitude_real_scaled),
        abs(receipt.marked_probe_imag_scaled - receipt.marked_amplitude_imag_scaled),
    )
    unmarked_probe_error = max(
        abs(receipt.unmarked_probe_real_scaled - receipt.unmarked_amplitude_real_scaled),
        abs(receipt.unmarked_probe_imag_scaled - receipt.unmarked_amplitude_imag_scaled),
    )
    if max(marked_probe_error, unmarked_probe_error) > policy.tolerance_scaled:
        failures.append("CHALLENGE_MEMBERSHIP")

    expected_failures = tuple(dict.fromkeys(failures))
    if receipt.failures != expected_failures:
        raise ValueError("QSA Grover receipt failure set mismatch")
    if receipt.accepted != (not expected_failures):
        raise ValueError("QSA Grover receipt acceptance mismatch")


def collect_qsa_grover(
    request: QSAGroverRequest,
    policy: QSAGroverPolicy | None = None,
) -> QSAGroverReceipt:
    policy = policy or QSAGroverPolicy()
    try:
        import qsa
        from qsa import GroverSearch, QubitRegister
    except ImportError as exc:
        raise RuntimeError("QSA is not installed or its native library is unavailable") from exc

    identity = QubitRegister(1)
    search = None
    try:
        package_version = str(getattr(qsa, "__version__", "unknown"))
        native_version = str(identity.native_version)
        abi_version = tuple(int(value) for value in identity.abi_version)
        marked_indices = _challenge_indices(request)
        marked_set = set(marked_indices)
        unmarked_probe = _unmarked_probe(request, marked_set)
        challenge_digest = hashlib.sha256(
            ",".join(str(value) for value in marked_indices).encode("ascii")
        ).hexdigest()

        search = GroverSearch(request.qubits, marked_indices)
        qsa_optimal = int(search.optimal_iterations)
        reference_optimal = _optimal_iterations(request.qubits, request.marked_count)
        iterations = qsa_optimal if request.iterations is None else request.iterations
        if request.iterations is None:
            search.run_optimal()
        else:
            search.iterate(iterations)

        validated = bool(search.validate())
        actual_qubits = int(search.qubit_count)
        actual_space = int(search.space_size)
        actual_marked = int(search.marked_count)
        actual_iterations = int(search.iteration_count)
        explicit_marked = bool(search.has_explicit_marked_indices)
        probability = float(search.success_probability)
        marked_amplitude = complex(search.marked_amplitude)
        unmarked_amplitude = complex(search.unmarked_amplitude)
        marked_probe_amplitude = complex(search.amplitude(marked_indices[0]))
        unmarked_probe_amplitude = complex(search.amplitude(unmarked_probe))
        reference_probability, reference_marked, reference_unmarked = _reference(
            request.qubits, request.marked_count, iterations
        )
        probability_error = abs(probability - reference_probability)
        marked_error = abs(marked_amplitude - reference_marked)
        unmarked_error = abs(unmarked_amplitude - reference_unmarked)
        marked_probe_error = abs(marked_probe_amplitude - marked_amplitude)
        unmarked_probe_error = abs(unmarked_probe_amplitude - unmarked_amplitude)
        estimated_bytes = int(search.estimated_bytes)

        failures: list[str] = []
        if request.policy_digest not in {"-", policy.digest}:
            failures.append("POLICY_DIGEST")
        if _version(package_version) < _version(policy.min_package_version):
            failures.append("QSA_PACKAGE_VERSION")
        if _version(native_version) < _version(policy.min_native_version):
            failures.append("QSA_NATIVE_VERSION")
        if abi_version < policy.min_abi_version:
            failures.append("QSA_ABI_VERSION")
        if not validated:
            failures.append("QSA_VALIDATE")
        if not explicit_marked:
            failures.append("CHALLENGE_MEMBERSHIP")
        if actual_qubits != request.qubits or actual_space != (1 << request.qubits) or actual_marked != request.marked_count:
            failures.append("CHALLENGE_SHAPE")
        if actual_iterations != iterations:
            failures.append("ITERATION_COUNT")
        if qsa_optimal != reference_optimal:
            failures.append("OPTIMAL_ITERATION_MISMATCH")
        if estimated_bytes > policy.max_estimated_bytes:
            failures.append("STATE_MEMORY_LIMIT")
        if _scaled(probability_error) > policy.tolerance_scaled:
            failures.append("PROBABILITY_MISMATCH")
        if max(_scaled(marked_error), _scaled(unmarked_error)) > policy.tolerance_scaled:
            failures.append("AMPLITUDE_MISMATCH")
        if max(_scaled(marked_probe_error), _scaled(unmarked_probe_error)) > policy.tolerance_scaled:
            failures.append("CHALLENGE_MEMBERSHIP")

        dense_bytes = 16 * (1 << request.qubits)
        return QSAGroverReceipt.create(
            accepted=not failures,
            request_digest=request.digest,
            package_version=package_version,
            native_version=native_version,
            abi_version=abi_version,
            qubits=actual_qubits,
            logical_states=actual_space,
            marked_count=actual_marked,
            challenge_digest=challenge_digest,
            marked_probe=marked_indices[0],
            unmarked_probe=unmarked_probe,
            iterations=actual_iterations,
            optimal_iterations=qsa_optimal,
            reference_optimal_iterations=reference_optimal,
            validated=validated,
            explicit_marked_indices=explicit_marked,
            estimated_bytes=estimated_bytes,
            dense_statevector_bytes=dense_bytes,
            dense_reduction=dense_bytes // max(1, estimated_bytes),
            success_probability_scaled=_scaled(probability),
            reference_probability_scaled=_scaled(reference_probability),
            probability_error_scaled=_scaled(probability_error),
            marked_amplitude_real_scaled=_scaled(marked_amplitude.real),
            marked_amplitude_imag_scaled=_scaled(marked_amplitude.imag),
            reference_marked_real_scaled=_scaled(reference_marked.real),
            unmarked_amplitude_real_scaled=_scaled(unmarked_amplitude.real),
            unmarked_amplitude_imag_scaled=_scaled(unmarked_amplitude.imag),
            reference_unmarked_real_scaled=_scaled(reference_unmarked.real),
            marked_probe_real_scaled=_scaled(marked_probe_amplitude.real),
            marked_probe_imag_scaled=_scaled(marked_probe_amplitude.imag),
            unmarked_probe_real_scaled=_scaled(unmarked_probe_amplitude.real),
            unmarked_probe_imag_scaled=_scaled(unmarked_probe_amplitude.imag),
            failures=tuple(dict.fromkeys(failures)),
        )
    finally:
        if search is not None:
            search.close()
        identity.close()


def run_qsa_grover(
    request: QSAGroverRequest,
    policy: QSAGroverPolicy | None = None,
    *,
    timeout_seconds: float = 30.0,
) -> QSAGroverReceipt:
    policy = policy or QSAGroverPolicy()
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
        (sys.executable, "-I", "-B", str(worker), "--grover"),
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
        raise ValueError(f"QSA Grover worker failed: {error or completed.returncode}")
    try:
        data = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("QSA Grover worker returned malformed output") from exc
    if not isinstance(data, Mapping):
        raise ValueError("QSA Grover worker returned a non-object receipt")
    receipt = QSAGroverReceipt.from_dict(data)
    if receipt.request_digest != request.digest:
        raise ValueError("QSA Grover worker returned a receipt for a different request")
    _verify_receipt(request, policy, receipt)
    if completed.returncode not in {0, 2}:
        raise ValueError(f"QSA Grover worker exited with status {completed.returncode}")
    if (completed.returncode == 0) != receipt.accepted:
        raise ValueError("QSA Grover worker status does not match its receipt")
    return receipt
