from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class CircuitOperation:
    name: str
    qubits: Tuple[int, ...]
    parameters: Tuple[float, ...] = ()
    label: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CircuitOperation":
        name = str(data.get("name", "")).strip().upper()
        if not name:
            raise ValueError("circuit operation name is required")
        qubits = tuple(int(value) for value in data.get("qubits", []))
        if not qubits:
            raise ValueError(f"operation {name} has no qubits")
        if any(value < 0 for value in qubits):
            raise ValueError("qubit indexes cannot be negative")
        parameters = tuple(float(value) for value in data.get("parameters", data.get("params", [])))
        if any(not math.isfinite(value) for value in parameters):
            raise ValueError(f"operation {name} contains a nonfinite parameter")
        return cls(name=name, qubits=qubits, parameters=parameters, label=str(data.get("label", "")))

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"name": self.name, "qubits": list(self.qubits)}
        if self.parameters:
            data["parameters"] = list(self.parameters)
        if self.label:
            data["label"] = self.label
        return data


@dataclass(frozen=True)
class CircuitManifest:
    num_qubits: int
    operations: Tuple[CircuitOperation, ...]
    name: str = ""
    backend_family: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CircuitManifest":
        num_qubits = int(data.get("num_qubits", 0))
        if num_qubits <= 0:
            raise ValueError("num_qubits must be positive")
        operations = tuple(CircuitOperation.from_dict(item) for item in data.get("operations", []))
        for operation in operations:
            if any(qubit >= num_qubits for qubit in operation.qubits):
                raise ValueError(f"operation {operation.name} references an out-of-range qubit")
        return cls(
            num_qubits=num_qubits,
            operations=operations,
            name=str(data.get("name", "")),
            backend_family=str(data.get("backend_family", "")),
            metadata=dict(data.get("metadata", {})),
        )

    def to_dict(self, include_metadata: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "name": self.name,
            "backend_family": self.backend_family,
            "num_qubits": self.num_qubits,
            "operations": [item.to_dict() for item in self.operations],
        }
        if include_metadata and self.metadata:
            data["metadata"] = self.metadata
        return data

    def canonical_bytes(self) -> bytes:
        payload = self.to_dict(include_metadata=False)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def depth(self) -> int:
        levels = [0] * self.num_qubits
        for operation in self.operations:
            next_level = max(levels[q] for q in operation.qubits) + 1
            for qubit in operation.qubits:
                levels[qubit] = next_level
        return max(levels, default=0)


@dataclass(frozen=True)
class CircuitPolicy:
    allowed_gates: Optional[Tuple[str, ...]] = None
    maximum_qubits: Optional[int] = None
    maximum_depth: Optional[int] = None
    maximum_operations: Optional[int] = None
    parameter_tolerance: float = 1e-9
    approved_digests: Tuple[str, ...] = ()
    require_exact_manifest: bool = True


@dataclass(frozen=True)
class CircuitDelta:
    matched: bool
    baseline_digest: str
    current_digest: str
    added_operations: Tuple[Dict[str, Any], ...]
    removed_operations: Tuple[Dict[str, Any], ...]
    changed_operations: Tuple[Dict[str, Any], ...]
    policy_violations: Tuple[str, ...]
    baseline_depth: int
    current_depth: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.matched,
            "baseline_digest": self.baseline_digest,
            "current_digest": self.current_digest,
            "added_operations": list(self.added_operations),
            "removed_operations": list(self.removed_operations),
            "changed_operations": list(self.changed_operations),
            "policy_violations": list(self.policy_violations),
            "baseline_depth": self.baseline_depth,
            "current_depth": self.current_depth,
        }


def _operation_change(
    index: int,
    baseline: CircuitOperation,
    current: CircuitOperation,
    tolerance: float,
) -> Optional[Dict[str, Any]]:
    changes: Dict[str, Any] = {"index": index}
    if baseline.name != current.name:
        changes["name"] = {"baseline": baseline.name, "current": current.name}
    if baseline.qubits != current.qubits:
        changes["qubits"] = {"baseline": list(baseline.qubits), "current": list(current.qubits)}
    if len(baseline.parameters) != len(current.parameters):
        changes["parameters"] = {
            "baseline": list(baseline.parameters),
            "current": list(current.parameters),
        }
    elif any(abs(a - b) > tolerance for a, b in zip(baseline.parameters, current.parameters)):
        changes["parameters"] = {
            "baseline": list(baseline.parameters),
            "current": list(current.parameters),
        }
    if baseline.label != current.label:
        changes["label"] = {"baseline": baseline.label, "current": current.label}
    return changes if len(changes) > 1 else None


def compare_circuits(
    baseline: CircuitManifest,
    current: CircuitManifest,
    policy: CircuitPolicy = CircuitPolicy(),
) -> CircuitDelta:
    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []
    violations: List[str] = []

    common = min(len(baseline.operations), len(current.operations))
    for index in range(common):
        change = _operation_change(index, baseline.operations[index], current.operations[index], policy.parameter_tolerance)
        if change is not None:
            changed.append(change)
    for index in range(common, len(current.operations)):
        added.append({"index": index, "operation": current.operations[index].to_dict()})
    for index in range(common, len(baseline.operations)):
        removed.append({"index": index, "operation": baseline.operations[index].to_dict()})

    allowed = None
    if policy.allowed_gates is not None:
        allowed = {gate.strip().upper() for gate in policy.allowed_gates}
        disallowed = sorted({operation.name for operation in current.operations if operation.name not in allowed})
        if disallowed:
            violations.append("unapproved gates: " + ", ".join(disallowed))
    if policy.maximum_qubits is not None and current.num_qubits > policy.maximum_qubits:
        violations.append("circuit exceeds maximum qubit count")
    current_depth = current.depth()
    if policy.maximum_depth is not None and current_depth > policy.maximum_depth:
        violations.append("circuit exceeds maximum depth")
    if policy.maximum_operations is not None and len(current.operations) > policy.maximum_operations:
        violations.append("circuit exceeds maximum operation count")
    if current.num_qubits != baseline.num_qubits:
        violations.append("circuit qubit count changed")
    if current.name != baseline.name:
        violations.append("circuit name changed")
    if baseline.backend_family and current.backend_family != baseline.backend_family:
        violations.append("circuit backend family changed")
    if policy.approved_digests and current.digest() not in set(policy.approved_digests):
        violations.append("circuit digest is not approved")

    exact_match = baseline.digest() == current.digest() and not added and not removed and not changed
    matched = exact_match if policy.require_exact_manifest else not violations
    if violations:
        matched = False

    return CircuitDelta(
        matched=matched,
        baseline_digest=baseline.digest(),
        current_digest=current.digest(),
        added_operations=tuple(added),
        removed_operations=tuple(removed),
        changed_operations=tuple(changed),
        policy_violations=tuple(violations),
        baseline_depth=baseline.depth(),
        current_depth=current_depth,
    )
