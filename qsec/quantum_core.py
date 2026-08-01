from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence, TextIO

_PROTOCOL_MAGIC = "QSEC-QH/1"
_WITNESS_MAGIC = "QSEC-QW/1"
_MAX_QUBITS = 12
_MAX_GATES = 4096
_SCALE = 10_000_000_000
QUANTUM_SCALE = _SCALE
NORM_TOLERANCE_SCALED = 100
_MAX_ANGLE_NANORADIANS = 25_132_741_229
_HEX64 = frozenset("0123456789abcdef")
_ONE_QUBIT = frozenset({"X", "Y", "Z", "H", "S", "T", "RX", "RY", "RZ"})
_TWO_QUBIT = frozenset({"CNOT", "CZ", "SWAP"})
_ROTATIONS = frozenset({"RX", "RY", "RZ"})


class QuantumProtocolError(ValueError):
    """Raised when a cross-code request or witness violates the protocol."""


def _require_hex64(value: str, field: str, *, allow_dash: bool = False) -> str:
    text = str(value).strip().lower()
    if allow_dash and text == "-":
        return text
    if len(text) != 64 or any(ch not in _HEX64 for ch in text):
        raise QuantumProtocolError(f"{field} must be 64 lowercase hexadecimal characters")
    return text


def _quantize(value: float) -> int:
    scaled = float(value) * _SCALE
    if scaled >= 0.0:
        return int(math.floor(scaled + 0.5))
    return int(math.ceil(scaled - 0.5))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class QuantumGate:
    name: str
    first: int
    second: int = -1
    angle_nanoradians: int = 0

    def __post_init__(self) -> None:
        name = str(self.name).strip().upper()
        if name not in _ONE_QUBIT and name not in _TWO_QUBIT:
            raise QuantumProtocolError(f"unsupported gate: {name}")
        first = int(self.first)
        second = int(self.second)
        angle = int(self.angle_nanoradians)
        if first < 0:
            raise QuantumProtocolError("gate target cannot be negative")
        if name in _TWO_QUBIT:
            if second < 0 or second == first:
                raise QuantumProtocolError(f"{name} requires two distinct qubits")
            if angle != 0:
                raise QuantumProtocolError(f"{name} does not accept an angle")
        else:
            if second != -1:
                raise QuantumProtocolError(f"{name} accepts one qubit")
            if name not in _ROTATIONS and angle != 0:
                raise QuantumProtocolError(f"{name} does not accept an angle")
            if name in _ROTATIONS and abs(angle) > _MAX_ANGLE_NANORADIANS:
                raise QuantumProtocolError("rotation angle exceeds the cross-code bound")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "first", first)
        object.__setattr__(self, "second", second)
        object.__setattr__(self, "angle_nanoradians", angle)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QuantumGate":
        name = str(data.get("name", ""))
        targets = data.get("targets")
        if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes)):
            raise QuantumProtocolError("gate targets must be a list")
        values = tuple(int(value) for value in targets)
        if len(values) == 1:
            first, second = values[0], -1
        elif len(values) == 2:
            first, second = values
        else:
            raise QuantumProtocolError("gate targets must contain one or two qubits")
        return cls(
            name=name,
            first=first,
            second=second,
            angle_nanoradians=int(data.get("angle_nanoradians", 0)),
        )

    def to_dict(self) -> dict[str, object]:
        targets = [self.first] if self.second < 0 else [self.first, self.second]
        data: dict[str, object] = {"name": self.name, "targets": targets}
        if self.name in _ROTATIONS:
            data["angle_nanoradians"] = self.angle_nanoradians
        return data

    def protocol_line(self) -> str:
        if self.name in _TWO_QUBIT:
            return f"gate={self.name},{self.first},{self.second},0"
        return f"gate={self.name},{self.first},-1,{self.angle_nanoradians}"


@dataclass(frozen=True)
class QuantumRequest:
    request_id: str
    nonce: str
    policy_digest: str
    parent_digest: str
    qubits: int
    initial_basis: int
    gates: tuple[QuantumGate, ...]

    def __post_init__(self) -> None:
        request_id = _require_hex64(self.request_id, "request_id")
        nonce = _require_hex64(self.nonce, "nonce")
        policy = _require_hex64(self.policy_digest, "policy_digest", allow_dash=True)
        parent = _require_hex64(self.parent_digest, "parent_digest", allow_dash=True)
        qubits = int(self.qubits)
        initial = int(self.initial_basis)
        gates = tuple(self.gates)
        if qubits < 1 or qubits > _MAX_QUBITS:
            raise QuantumProtocolError(f"qubits must be between 1 and {_MAX_QUBITS}")
        if initial < 0 or initial >= (1 << qubits):
            raise QuantumProtocolError("initial_basis is outside the register")
        if len(gates) > _MAX_GATES:
            raise QuantumProtocolError(f"gate count exceeds {_MAX_GATES}")
        for gate in gates:
            if gate.first >= qubits or (gate.second >= qubits and gate.second >= 0):
                raise QuantumProtocolError("gate target is outside the register")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "policy_digest", policy)
        object.__setattr__(self, "parent_digest", parent)
        object.__setattr__(self, "qubits", qubits)
        object.__setattr__(self, "initial_basis", initial)
        object.__setattr__(self, "gates", gates)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "QuantumRequest":
        raw_gates = data.get("gates", ())
        if not isinstance(raw_gates, Sequence) or isinstance(raw_gates, (str, bytes)):
            raise QuantumProtocolError("gates must be a list")
        gates: list[QuantumGate] = []
        for item in raw_gates:
            if not isinstance(item, Mapping):
                raise QuantumProtocolError("every gate must be an object")
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

    def encode(self) -> bytes:
        lines = [
            _PROTOCOL_MAGIC,
            f"request_id={self.request_id}",
            f"nonce={self.nonce}",
            f"policy_digest={self.policy_digest}",
            f"parent_digest={self.parent_digest}",
            f"qubits={self.qubits}",
            f"initial_basis={self.initial_basis}",
            f"gate_count={len(self.gates)}",
        ]
        lines.extend(gate.protocol_line() for gate in self.gates)
        lines.append("END")
        return ("\n".join(lines) + "\n").encode("ascii")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.encode()).hexdigest()

    @classmethod
    def decode(cls, payload: bytes | str) -> "QuantumRequest":
        raw = payload.encode("ascii") if isinstance(payload, str) else bytes(payload)
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise QuantumProtocolError("request must be ASCII") from exc
        if not text.endswith("\n"):
            raise QuantumProtocolError("request must end with a newline")
        lines = text.splitlines()
        if len(lines) < 9 or lines[0] != _PROTOCOL_MAGIC or lines[-1] != "END":
            raise QuantumProtocolError("invalid request framing")
        expected = (
            "request_id",
            "nonce",
            "policy_digest",
            "parent_digest",
            "qubits",
            "initial_basis",
            "gate_count",
        )
        values: dict[str, str] = {}
        for line, key in zip(lines[1:8], expected):
            prefix = key + "="
            if not line.startswith(prefix):
                raise QuantumProtocolError(f"expected {key}")
            values[key] = line[len(prefix) :]
        gate_count = int(values["gate_count"])
        if gate_count < 0 or gate_count > _MAX_GATES:
            raise QuantumProtocolError("invalid gate_count")
        if len(lines) != gate_count + 9:
            raise QuantumProtocolError("gate_count does not match payload")
        gates: list[QuantumGate] = []
        for line in lines[8:-1]:
            if not line.startswith("gate="):
                raise QuantumProtocolError("expected gate record")
            fields = line[5:].split(",")
            if len(fields) != 4:
                raise QuantumProtocolError("gate record must have four fields")
            gates.append(QuantumGate(fields[0], int(fields[1]), int(fields[2]), int(fields[3])))
        request = cls(
            request_id=values["request_id"],
            nonce=values["nonce"],
            policy_digest=values["policy_digest"],
            parent_digest=values["parent_digest"],
            qubits=int(values["qubits"]),
            initial_basis=int(values["initial_basis"]),
            gates=tuple(gates),
        )
        if request.encode() != raw:
            raise QuantumProtocolError("request is not in canonical form")
        return request


def consensus_digest_for(
    request_digest: str,
    state_digest: str,
    probability_digest: str,
    norm_scaled: int,
    qubits: int,
) -> str:
    return _sha256_text(
        "|".join(
            [
                request_digest,
                state_digest,
                probability_digest,
                str(int(norm_scaled)),
                str(int(qubits)),
            ]
        )
    )


@dataclass(frozen=True)
class QuantumWitness:
    request_digest: str
    backend_id: str
    state_digest: str
    probability_digest: str
    norm_scaled: int
    consensus_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_digest", _require_hex64(self.request_digest, "request_digest"))
        object.__setattr__(self, "state_digest", _require_hex64(self.state_digest, "state_digest"))
        object.__setattr__(self, "probability_digest", _require_hex64(self.probability_digest, "probability_digest"))
        object.__setattr__(self, "consensus_digest", _require_hex64(self.consensus_digest, "consensus_digest"))
        backend = str(self.backend_id).strip()
        if not backend or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for ch in backend):
            raise QuantumProtocolError("invalid backend_id")
        object.__setattr__(self, "backend_id", backend)
        object.__setattr__(self, "norm_scaled", int(self.norm_scaled))

    def encode(self) -> bytes:
        text = "\n".join(
            [
                _WITNESS_MAGIC,
                f"request_digest={self.request_digest}",
                f"backend_id={self.backend_id}",
                f"state_digest={self.state_digest}",
                f"probability_digest={self.probability_digest}",
                f"norm_scaled={self.norm_scaled}",
                f"consensus_digest={self.consensus_digest}",
                "END",
                "",
            ]
        )
        return text.encode("ascii")

    @property
    def witness_digest(self) -> str:
        return hashlib.sha256(self.encode()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "request_digest": self.request_digest,
            "backend_id": self.backend_id,
            "state_digest": self.state_digest,
            "probability_digest": self.probability_digest,
            "norm_scaled": self.norm_scaled,
            "consensus_digest": self.consensus_digest,
            "witness_digest": self.witness_digest,
        }

    @classmethod
    def decode(cls, payload: bytes | str) -> "QuantumWitness":
        raw = payload.encode("ascii") if isinstance(payload, str) else bytes(payload)
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise QuantumProtocolError("witness must be ASCII") from exc
        if not text.endswith("\n"):
            raise QuantumProtocolError("witness must end with a newline")
        lines = text.splitlines()
        if len(lines) != 8 or lines[0] != _WITNESS_MAGIC or lines[-1] != "END":
            raise QuantumProtocolError("invalid witness framing")
        keys = (
            "request_digest",
            "backend_id",
            "state_digest",
            "probability_digest",
            "norm_scaled",
            "consensus_digest",
        )
        values: dict[str, str] = {}
        for line, key in zip(lines[1:7], keys):
            prefix = key + "="
            if not line.startswith(prefix):
                raise QuantumProtocolError(f"expected {key}")
            values[key] = line[len(prefix) :]
        witness = cls(
            request_digest=values["request_digest"],
            backend_id=values["backend_id"],
            state_digest=values["state_digest"],
            probability_digest=values["probability_digest"],
            norm_scaled=int(values["norm_scaled"]),
            consensus_digest=values["consensus_digest"],
        )
        if witness.encode() != raw:
            raise QuantumProtocolError("witness is not in canonical form")
        return witness


def _apply_one(state: list[complex], qubit: int, a: complex, b: complex, c: complex, d: complex) -> None:
    step = 1 << qubit
    span = step << 1
    for base in range(0, len(state), span):
        for offset in range(step):
            low = base + offset
            high = low + step
            x = state[low]
            y = state[high]
            state[low] = a * x + b * y
            state[high] = c * x + d * y


def _apply_gate(state: list[complex], gate: QuantumGate) -> None:
    name = gate.name
    if name == "X":
        _apply_one(state, gate.first, 0j, 1 + 0j, 1 + 0j, 0j)
    elif name == "Y":
        _apply_one(state, gate.first, 0j, -1j, 1j, 0j)
    elif name == "Z":
        _apply_one(state, gate.first, 1 + 0j, 0j, 0j, -1 + 0j)
    elif name == "H":
        k = 1.0 / math.sqrt(2.0)
        _apply_one(state, gate.first, k + 0j, k + 0j, k + 0j, -k + 0j)
    elif name == "S":
        _apply_one(state, gate.first, 1 + 0j, 0j, 0j, 1j)
    elif name == "T":
        phase = complex(math.cos(math.pi / 4.0), math.sin(math.pi / 4.0))
        _apply_one(state, gate.first, 1 + 0j, 0j, 0j, phase)
    elif name in _ROTATIONS:
        angle = gate.angle_nanoradians * 1e-9
        half = angle / 2.0
        cosine = math.cos(half)
        sine = math.sin(half)
        if name == "RX":
            _apply_one(state, gate.first, cosine + 0j, -1j * sine, -1j * sine, cosine + 0j)
        elif name == "RY":
            _apply_one(state, gate.first, cosine + 0j, -sine + 0j, sine + 0j, cosine + 0j)
        else:
            low = complex(math.cos(-half), math.sin(-half))
            high = complex(math.cos(half), math.sin(half))
            _apply_one(state, gate.first, low, 0j, 0j, high)
    elif name == "CNOT":
        control_mask = 1 << gate.first
        target_mask = 1 << gate.second
        for index in range(len(state)):
            if index & control_mask and not index & target_mask:
                other = index | target_mask
                state[index], state[other] = state[other], state[index]
    elif name == "CZ":
        control_mask = 1 << gate.first
        target_mask = 1 << gate.second
        for index in range(len(state)):
            if index & control_mask and index & target_mask:
                state[index] = -state[index]
    elif name == "SWAP":
        first_mask = 1 << gate.first
        second_mask = 1 << gate.second
        for index in range(len(state)):
            first = bool(index & first_mask)
            second = bool(index & second_mask)
            if first and not second:
                other = (index ^ first_mask) | second_mask
                state[index], state[other] = state[other], state[index]
    else:
        raise QuantumProtocolError(f"unsupported gate: {name}")


def simulate(request: QuantumRequest) -> list[complex]:
    state = [0j] * (1 << request.qubits)
    state[request.initial_basis] = 1 + 0j
    for gate in request.gates:
        _apply_gate(state, gate)
    return state


def witness_from_state(request: QuantumRequest, state: Iterable[complex], backend_id: str) -> QuantumWitness:
    amplitudes = tuple(complex(value) for value in state)
    if len(amplitudes) != (1 << request.qubits):
        raise QuantumProtocolError("state dimension does not match request")
    phase_anchor = next((value for value in amplitudes if abs(value) > 1e-15), 1 + 0j)
    phase = phase_anchor.conjugate() / abs(phase_anchor)
    canonical = tuple(value * phase for value in amplitudes)
    state_text = ";".join(f"{_quantize(value.real)},{_quantize(value.imag)}" for value in canonical)
    probabilities = tuple(value.real * value.real + value.imag * value.imag for value in amplitudes)
    probability_text = ",".join(str(_quantize(value)) for value in probabilities)
    norm_scaled = _quantize(sum(probabilities))
    state_digest = _sha256_text(state_text)
    probability_digest = _sha256_text(probability_text)
    return QuantumWitness(
        request_digest=request.digest,
        backend_id=backend_id,
        state_digest=state_digest,
        probability_digest=probability_digest,
        norm_scaled=norm_scaled,
        consensus_digest=consensus_digest_for(
            request.digest,
            state_digest,
            probability_digest,
            norm_scaled,
            request.qubits,
        ),
    )


def execute_request(request: QuantumRequest, *, backend_id: str = "python-dense") -> QuantumWitness:
    return witness_from_state(request, simulate(request), backend_id)


def run_worker(input_stream: TextIO, output_stream: TextIO, *, backend_id: str = "python-dense") -> int:
    payload = input_stream.buffer.read() if hasattr(input_stream, "buffer") else input_stream.read().encode("ascii")
    request = QuantumRequest.decode(payload)
    witness = execute_request(request, backend_id=backend_id)
    if hasattr(output_stream, "buffer"):
        output_stream.buffer.write(witness.encode())
        output_stream.buffer.flush()
    else:
        output_stream.write(witness.encode().decode("ascii"))
        output_stream.flush()
    return 0
