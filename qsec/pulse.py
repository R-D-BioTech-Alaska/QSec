from __future__ import annotations

from dataclasses import asdict, dataclass, field
from math import atan2, cos, pi, sin, sqrt
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

import numpy as np

from .model import Finding, FindingStatus, Severity
from .trust import canonical_json, make_finding, sha256_bytes


def circular_phase_delta(a: float, b: float) -> float:
    return abs(atan2(sin(a - b), cos(a - b)))


@dataclass(frozen=True)
class PulseSegment:
    channel: str
    start: float
    duration: float
    amplitude: float
    phase: float = 0.0
    frequency: float = 0.0
    shape: str = "constant"
    samples: Tuple[float, ...] = ()
    label: str = ""

    def __post_init__(self):
        values = (self.start, self.duration, self.amplitude, self.phase, self.frequency)
        if not self.channel:
            raise ValueError("pulse channel is required")
        if not all(np.isfinite(value) for value in values):
            raise ValueError("pulse values must be finite")
        if self.start < 0.0 or self.duration <= 0.0:
            raise ValueError("pulse start must be nonnegative and duration positive")
        if any(not np.isfinite(value) for value in self.samples):
            raise ValueError("pulse samples must be finite")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PulseSegment":
        return cls(
            channel=str(data["channel"]), start=float(data["start"]), duration=float(data["duration"]),
            amplitude=float(data["amplitude"]), phase=float(data.get("phase", 0.0)),
            frequency=float(data.get("frequency", 0.0)), shape=str(data.get("shape", "constant")),
            samples=tuple(float(v) for v in data.get("samples", [])), label=str(data.get("label", "")),
        )

    @property
    def stop(self) -> float:
        return self.start + self.duration

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PulseSchedule:
    backend_id: str
    clock_period: float
    segments: Tuple[PulseSegment, ...]
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "qsec.pulse.v1"

    def __post_init__(self):
        if not self.backend_id:
            raise ValueError("backend_id is required")
        if not np.isfinite(self.clock_period) or self.clock_period <= 0.0:
            raise ValueError("clock_period must be positive and finite")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PulseSchedule":
        return cls(
            backend_id=str(data["backend_id"]), clock_period=float(data["clock_period"]),
            segments=tuple(PulseSegment.from_dict(item) for item in data.get("segments", [])),
            metadata=dict(data.get("metadata", {})), schema_version=str(data.get("schema_version", "qsec.pulse.v1")),
        )

    def to_dict(self, include_metadata: bool = True) -> Dict[str, Any]:
        data = {
            "schema_version": self.schema_version, "backend_id": self.backend_id,
            "clock_period": self.clock_period, "segments": [item.to_dict() for item in self.segments],
        }
        if include_metadata:
            data["metadata"] = self.metadata
        return data

    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict(include_metadata=False)))


@dataclass(frozen=True)
class PulsePolicy:
    allowed_channels: Tuple[str, ...] = ()
    allowed_shapes: Tuple[str, ...] = ("constant", "gaussian", "drag", "gaussian_square", "sampled")
    maximum_absolute_amplitude: float = 1.0
    maximum_duration: float = 1.0
    maximum_schedule_duration: float = 10.0
    maximum_duty_cycle: float = 0.85
    maximum_slew_rate: float = 25.0
    maximum_control_energy: float = 10.0
    start_tolerance: float = 1e-9
    duration_tolerance: float = 1e-9
    amplitude_tolerance: float = 1e-6
    phase_tolerance: float = 1e-6
    frequency_tolerance: float = 1e-6
    waveform_rms_tolerance: float = 1e-5
    spectral_residual_tolerance: float = 1e-4
    require_exact_digest: bool = True


@dataclass(frozen=True)
class PulseReport:
    valid: bool
    current_digest: str
    baseline_digest: Optional[str]
    checks: Dict[str, Any]
    findings: Tuple[Finding, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid, "current_digest": self.current_digest, "baseline_digest": self.baseline_digest,
            "checks": self.checks, "findings": [item.to_dict() for item in self.findings],
        }


def _waveform_metrics(baseline: PulseSegment, current: PulseSegment) -> Dict[str, Any]:
    if not baseline.samples and not current.samples:
        return {"checked": False}
    if len(baseline.samples) != len(current.samples) or not baseline.samples:
        return {"checked": True, "same_length": False, "rms_residual": float("inf"), "spectral_residual": float("inf")}
    base = np.asarray(baseline.samples, dtype=float)
    now = np.asarray(current.samples, dtype=float)
    residual = now - base
    rms = float(np.sqrt(np.mean(np.square(residual))))
    base_spectrum = np.abs(np.fft.rfft(base))
    now_spectrum = np.abs(np.fft.rfft(now))
    denominator = max(float(np.linalg.norm(base_spectrum)), 1e-15)
    spectral = float(np.linalg.norm(now_spectrum - base_spectrum) / denominator)
    return {"checked": True, "same_length": True, "rms_residual": rms, "spectral_residual": spectral}


def inspect_pulse_schedule(
    current: PulseSchedule,
    baseline: Optional[PulseSchedule] = None,
    policy: PulsePolicy = PulsePolicy(),
) -> PulseReport:
    findings = []
    checks: Dict[str, Any] = {}
    schedule_end = max((item.stop for item in current.segments), default=0.0)
    checks["schedule_duration"] = schedule_end
    if schedule_end > policy.maximum_schedule_duration:
        findings.append(make_finding("pulse_parasite", "Pulse Tampering", Severity.HIGH, 0.94, "The pulse schedule exceeds the approved duration budget.", {"duration": schedule_end, "maximum": policy.maximum_schedule_duration}))

    per_channel: Dict[str, list[PulseSegment]] = {}
    energy = 0.0
    for segment in current.segments:
        per_channel.setdefault(segment.channel, []).append(segment)
        energy += segment.amplitude * segment.amplitude * segment.duration
        if policy.allowed_channels and segment.channel not in policy.allowed_channels:
            findings.append(make_finding("pulse_parasite", "Pulse Substitution", Severity.CRITICAL, 0.98, "An unapproved control channel is present.", {"channel": segment.channel}, FindingStatus.BREACH))
        if segment.shape not in policy.allowed_shapes:
            findings.append(make_finding("pulse_parasite", "Waveform Grafting", Severity.CRITICAL, 0.98, "An unapproved waveform shape is present.", {"shape": segment.shape}, FindingStatus.BREACH))
        if abs(segment.amplitude) > policy.maximum_absolute_amplitude or segment.duration > policy.maximum_duration:
            findings.append(make_finding("pulse_parasite", "Pulse Tampering", Severity.HIGH, 0.96, "A pulse exceeds the approved amplitude or duration envelope.", {"segment": segment.to_dict(), "maximum_amplitude": policy.maximum_absolute_amplitude, "maximum_duration": policy.maximum_duration}))
        if segment.samples and len(segment.samples) > 1:
            dt = segment.duration / (len(segment.samples) - 1)
            slew = float(np.max(np.abs(np.diff(np.asarray(segment.samples))) / max(dt, 1e-15)))
            if slew > policy.maximum_slew_rate:
                findings.append(make_finding("pulse_parasite", "Waveform Grafting", Severity.HIGH, 0.92, "A sampled waveform exceeds the approved slew-rate envelope.", {"slew_rate": slew, "maximum": policy.maximum_slew_rate}))

    overlap_rows = []
    duty_rows = []
    for channel, segments in per_channel.items():
        ordered = sorted(segments, key=lambda item: (item.start, item.stop))
        occupied = sum(item.duration for item in ordered)
        duty = occupied / max(schedule_end, 1e-15) if schedule_end else 0.0
        duty_rows.append({"channel": channel, "duty_cycle": duty})
        if duty > policy.maximum_duty_cycle:
            findings.append(make_finding("pulse_parasite", "Pulse Tampering", Severity.HIGH, 0.90, "A control channel exceeds the approved duty-cycle envelope.", {"channel": channel, "duty_cycle": duty, "maximum": policy.maximum_duty_cycle}))
        for left, right in zip(ordered, ordered[1:]):
            if right.start < left.stop - policy.start_tolerance:
                row = {"channel": channel, "left": left.to_dict(), "right": right.to_dict()}
                overlap_rows.append(row)
                findings.append(make_finding("pulse_parasite", "Waveform Grafting", Severity.CRITICAL, 0.99, "Control pulses overlap on the same channel without authorization.", row, FindingStatus.BREACH))
    checks["overlaps"] = overlap_rows
    checks["duty_cycle"] = duty_rows
    checks["control_energy"] = energy
    if energy > policy.maximum_control_energy:
        findings.append(make_finding("coherence_eater", "Thermal Loading", Severity.HIGH, 0.91, "The integrated control-energy proxy exceeds the approved budget.", {"control_energy": energy, "maximum": policy.maximum_control_energy}))

    baseline_digest = baseline.digest() if baseline is not None else None
    current_digest = current.digest()
    checks["digest_match"] = None if baseline is None else current_digest == baseline_digest
    comparisons = []
    if baseline is not None:
        if current.backend_id != baseline.backend_id:
            findings.append(make_finding("oracle_mimic", "Backend Impersonation", Severity.CRITICAL, 0.99, "The pulse schedule targets a different backend.", {"baseline": baseline.backend_id, "current": current.backend_id}, FindingStatus.BREACH))
        if len(current.segments) != len(baseline.segments):
            findings.append(make_finding("pulse_parasite", "Waveform Grafting", Severity.CRITICAL, 0.99, "The pulse schedule contains a different number of segments.", {"baseline_count": len(baseline.segments), "current_count": len(current.segments)}, FindingStatus.BREACH))
        for index, (base, now) in enumerate(zip(baseline.segments, current.segments)):
            waveform = _waveform_metrics(base, now)
            row = {
                "index": index, "channel_match": base.channel == now.channel, "shape_match": base.shape == now.shape,
                "start_delta": abs(base.start - now.start), "duration_delta": abs(base.duration - now.duration),
                "amplitude_delta": abs(base.amplitude - now.amplitude), "phase_delta": circular_phase_delta(base.phase, now.phase),
                "frequency_delta": abs(base.frequency - now.frequency), "waveform": waveform,
            }
            comparisons.append(row)
            mismatch = (
                not row["channel_match"] or not row["shape_match"] or row["start_delta"] > policy.start_tolerance
                or row["duration_delta"] > policy.duration_tolerance or row["amplitude_delta"] > policy.amplitude_tolerance
                or row["phase_delta"] > policy.phase_tolerance or row["frequency_delta"] > policy.frequency_tolerance
                or (waveform.get("checked") and (not waveform.get("same_length", True) or waveform.get("rms_residual", 0.0) > policy.waveform_rms_tolerance or waveform.get("spectral_residual", 0.0) > policy.spectral_residual_tolerance))
            )
            if mismatch:
                findings.append(make_finding("pulse_parasite", "Pulse Tampering", Severity.CRITICAL, 0.99, f"Pulse segment {index} differs from the authenticated schedule.", row, FindingStatus.BREACH))
        if policy.require_exact_digest and current_digest != baseline_digest and not comparisons:
            findings.append(make_finding("pulse_parasite", "Pulse Substitution", Severity.CRITICAL, 0.99, "The pulse schedule digest differs from the trusted schedule.", {"baseline_digest": baseline_digest, "current_digest": current_digest}, FindingStatus.BREACH))
    checks["segment_comparisons"] = comparisons
    ordered = tuple(sorted(findings, key=lambda item: int(item.severity), reverse=True))
    return PulseReport(not any(item.severity >= Severity.HIGH for item in ordered), current_digest, baseline_digest, checks, ordered)
