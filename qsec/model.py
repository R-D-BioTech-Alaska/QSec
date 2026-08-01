from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Tuple


class Severity(IntEnum):
    INFORMATIONAL = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


class FindingStatus(str, Enum):
    OBSERVATION = "observation"
    DISTURBANCE = "disturbance"
    BREACH = "breach"
    COMPROMISE = "compromise"
    COLLAPSE = "collapse"


@dataclass(frozen=True)
class Finding:
    code: str
    threat: str
    technique: str
    severity: Severity
    confidence: float
    status: FindingStatus
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        data["severity_value"] = int(self.severity)
        data["status"] = self.status.value
        return data


@dataclass(frozen=True)
class CalibrationSnapshot:
    t1: Tuple[float, ...] = ()
    t2: Tuple[float, ...] = ()
    detuning: Tuple[float, ...] = ()
    readout_matrices: Tuple[Tuple[Tuple[float, float], Tuple[float, float]], ...] = ()
    reset_excited_probability: Tuple[float, ...] = ()
    gate_error_rates: Dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CalibrationSnapshot":
        matrices = []
        for matrix in data.get("readout_matrices", []):
            if len(matrix) != 2 or any(len(row) != 2 for row in matrix):
                raise ValueError("each readout matrix must be 2x2")
            matrices.append(
                (
                    (float(matrix[0][0]), float(matrix[0][1])),
                    (float(matrix[1][0]), float(matrix[1][1])),
                )
            )
        return cls(
            t1=tuple(float(v) for v in data.get("t1", [])),
            t2=tuple(float(v) for v in data.get("t2", [])),
            detuning=tuple(float(v) for v in data.get("detuning", [])),
            readout_matrices=tuple(matrices),
            reset_excited_probability=tuple(float(v) for v in data.get("reset_excited_probability", [])),
            gate_error_rates={str(k): float(v) for k, v in data.get("gate_error_rates", {}).items()},
        )


@dataclass(frozen=True)
class SecuritySnapshot:
    backend_id: str
    backend_fingerprint: str
    circuit: Dict[str, Any]
    calibration: CalibrationSnapshot = field(default_factory=CalibrationSnapshot)
    entropy_sample_hex: Optional[str] = None
    measurement_counts: Dict[str, int] = field(default_factory=dict)
    state: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecuritySnapshot":
        if not data.get("backend_id"):
            raise ValueError("backend_id is required")
        if not data.get("backend_fingerprint"):
            raise ValueError("backend_fingerprint is required")
        if not isinstance(data.get("circuit"), dict):
            raise ValueError("circuit must be an object")
        counts = {str(k): int(v) for k, v in data.get("measurement_counts", {}).items()}
        if any(v < 0 for v in counts.values()):
            raise ValueError("measurement counts cannot be negative")
        return cls(
            backend_id=str(data["backend_id"]),
            backend_fingerprint=str(data["backend_fingerprint"]),
            circuit=dict(data["circuit"]),
            calibration=CalibrationSnapshot.from_dict(data.get("calibration", {})),
            entropy_sample_hex=data.get("entropy_sample_hex"),
            measurement_counts=counts,
            state=data.get("state"),
            metadata=dict(data.get("metadata", {})),
        )

    def entropy_sample(self) -> Optional[bytes]:
        if self.entropy_sample_hex is None:
            return None
        try:
            return bytes.fromhex(self.entropy_sample_hex)
        except ValueError as exc:
            raise ValueError("entropy_sample_hex is not valid hexadecimal") from exc


@dataclass(frozen=True)
class InspectionReport:
    findings: Tuple[Finding, ...]
    checks: Dict[str, Any]
    baseline_fingerprint: Optional[str]
    current_fingerprint: str

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFORMATIONAL
        return max((item.severity for item in self.findings), default=Severity.INFORMATIONAL)

    @property
    def passed(self) -> bool:
        return not any(item.severity >= Severity.HIGH for item in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "highest_severity": self.highest_severity.name.lower(),
            "baseline_fingerprint": self.baseline_fingerprint,
            "current_fingerprint": self.current_fingerprint,
            "checks": self.checks,
            "findings": [item.to_dict() for item in self.findings],
        }
