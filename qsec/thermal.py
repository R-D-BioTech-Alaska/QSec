from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple

import numpy as np

from .model import Finding, Severity
from .trust import make_finding, parse_time


@dataclass(frozen=True)
class ThermalSample:
    timestamp: str
    temperature: float
    input_power: float
    cooling_power: float

    def __post_init__(self):
        if not all(np.isfinite(v) for v in (self.temperature, self.input_power, self.cooling_power)):
            raise ValueError("thermal telemetry values must be finite")
        parse_time(self.timestamp)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ThermalSample":
        return cls(str(data["timestamp"]), float(data["temperature"]), float(data["input_power"]), float(data["cooling_power"]))

    def to_dict(self) -> Dict[str, Any]:
        return {"timestamp": self.timestamp, "temperature": self.temperature, "input_power": self.input_power, "cooling_power": self.cooling_power}


@dataclass(frozen=True)
class ThermalPolicy:
    minimum_temperature: float
    maximum_temperature: float
    maximum_temperature_rate: float
    maximum_sensor_step: float
    heat_capacity: float
    ambient_temperature: float
    passive_conductance: float = 0.0
    maximum_first_law_residual: float = 1.0
    maximum_input_power: float = float("inf")
    maximum_cooling_power: float = float("inf")

    def __post_init__(self):
        if self.maximum_temperature <= self.minimum_temperature:
            raise ValueError("maximum_temperature must exceed minimum_temperature")
        if self.heat_capacity <= 0.0 or self.maximum_temperature_rate <= 0.0 or self.maximum_sensor_step <= 0.0:
            raise ValueError("thermal policy rates and heat capacity must be positive")
        if self.passive_conductance < 0.0 or self.maximum_first_law_residual < 0.0:
            raise ValueError("conductance and residual tolerance cannot be negative")


@dataclass(frozen=True)
class ThermalReport:
    valid: bool
    checks: Dict[str, Any]
    findings: Tuple[Finding, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {"valid": self.valid, "checks": self.checks, "findings": [item.to_dict() for item in self.findings]}


def inspect_thermal_telemetry(samples: Sequence[ThermalSample], policy: ThermalPolicy) -> ThermalReport:
    if len(samples) < 2:
        raise ValueError("at least two thermal samples are required")
    ordered_samples = tuple(samples)
    findings = []
    intervals = []
    for index, sample in enumerate(ordered_samples):
        if sample.temperature < policy.minimum_temperature or sample.temperature > policy.maximum_temperature:
            findings.append(make_finding("coherence_eater", "Thermal Loading", Severity.HIGH, 0.96, "Device temperature is outside the calibrated operating envelope.", {"index": index, "temperature": sample.temperature, "minimum": policy.minimum_temperature, "maximum": policy.maximum_temperature}))
        if sample.input_power < 0.0 or sample.input_power > policy.maximum_input_power:
            findings.append(make_finding("driftroot", "Calibration Poisoning", Severity.HIGH, 0.93, "Input-power telemetry is outside the calibrated physical envelope.", {"index": index, "input_power": sample.input_power, "maximum": policy.maximum_input_power}))
        if sample.cooling_power < 0.0 or sample.cooling_power > policy.maximum_cooling_power:
            findings.append(make_finding("driftroot", "Calibration Poisoning", Severity.HIGH, 0.93, "Cooling-power telemetry is outside the calibrated physical envelope.", {"index": index, "cooling_power": sample.cooling_power, "maximum": policy.maximum_cooling_power}))

    for index, (left, right) in enumerate(zip(ordered_samples, ordered_samples[1:])):
        dt = (parse_time(right.timestamp) - parse_time(left.timestamp)).total_seconds()
        if dt <= 0.0:
            findings.append(make_finding("correlation_forge", "Sample Replay", Severity.HIGH, 0.97, "Thermal telemetry timestamps are duplicated or reversed.", {"index": index, "dt": dt}))
            continue
        delta_temperature = right.temperature - left.temperature
        rate = delta_temperature / dt
        average_temperature = 0.5 * (left.temperature + right.temperature)
        average_input = 0.5 * (left.input_power + right.input_power)
        average_cooling = 0.5 * (left.cooling_power + right.cooling_power)
        passive_loss = policy.passive_conductance * (average_temperature - policy.ambient_temperature)
        expected_energy = (average_input - average_cooling - passive_loss) * dt
        observed_energy = policy.heat_capacity * delta_temperature
        residual = observed_energy - expected_energy
        row = {
            "index": index, "dt": dt, "temperature_delta": delta_temperature, "temperature_rate": rate,
            "average_input_power": average_input, "average_cooling_power": average_cooling,
            "passive_heat_flow": passive_loss, "expected_energy_change": expected_energy,
            "observed_energy_change": observed_energy, "first_law_residual": residual,
        }
        intervals.append(row)
        if abs(rate) > policy.maximum_temperature_rate:
            findings.append(make_finding("coherence_eater", "Thermal Loading", Severity.HIGH, 0.95, "Temperature changed faster than the calibrated device envelope.", {**row, "maximum_rate": policy.maximum_temperature_rate}))
        if abs(delta_temperature) > policy.maximum_sensor_step:
            findings.append(make_finding("noisecloak", "Noise Camouflage", Severity.HIGH, 0.92, "A thermal sensor step exceeds the accepted continuity envelope.", {**row, "maximum_step": policy.maximum_sensor_step}))
        if abs(residual) > policy.maximum_first_law_residual:
            findings.append(make_finding("coherence_eater", "Thermal Loading", Severity.HIGH, 0.94, "Measured temperature and power do not close the calibrated first-law energy balance.", {**row, "maximum_residual": policy.maximum_first_law_residual}))

    ordered = tuple(sorted(findings, key=lambda item: int(item.severity), reverse=True))
    checks = {
        "sample_count": len(ordered_samples), "intervals": intervals,
        "maximum_absolute_rate": max((abs(row["temperature_rate"]) for row in intervals), default=0.0),
        "maximum_absolute_first_law_residual": max((abs(row["first_law_residual"]) for row in intervals), default=0.0),
    }
    return ThermalReport(not any(item.severity >= Severity.HIGH for item in ordered), checks, ordered)
