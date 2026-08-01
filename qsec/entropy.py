from __future__ import annotations

from dataclasses import dataclass
from math import log2, sqrt
from typing import Any, Dict, Tuple

import numpy as np


@dataclass(frozen=True)
class EntropyPolicy:
    minimum_bytes: int = 256
    minimum_min_entropy_per_byte: float = 6.0
    maximum_bit_bias: float = 0.03
    maximum_serial_correlation: float = 0.12
    maximum_repeated_byte_run: int = 8


@dataclass(frozen=True)
class EntropyReport:
    healthy: bool
    violations: Tuple[str, ...]
    sample_bytes: int
    shannon_entropy_per_byte: float
    min_entropy_per_byte: float
    bit_bias: float
    serial_correlation: float
    longest_repeated_byte_run: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "healthy": self.healthy,
            "violations": list(self.violations),
            "sample_bytes": self.sample_bytes,
            "shannon_entropy_per_byte": self.shannon_entropy_per_byte,
            "min_entropy_per_byte": self.min_entropy_per_byte,
            "bit_bias": self.bit_bias,
            "serial_correlation": self.serial_correlation,
            "longest_repeated_byte_run": self.longest_repeated_byte_run,
        }


def _longest_run(values: np.ndarray) -> int:
    if values.size == 0:
        return 0
    longest = 1
    current = 1
    for index in range(1, values.size):
        if values[index] == values[index - 1]:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return int(longest)


def assess_entropy(sample: bytes, policy: EntropyPolicy = EntropyPolicy()) -> EntropyReport:
    if not isinstance(sample, (bytes, bytearray, memoryview)):
        raise TypeError("entropy sample must be bytes-like")
    raw = bytes(sample)
    values = np.frombuffer(raw, dtype=np.uint8)
    violations = []
    if values.size < policy.minimum_bytes:
        violations.append(f"sample contains fewer than {policy.minimum_bytes} bytes")
    if values.size == 0:
        return EntropyReport(False, tuple(violations or ["sample is empty"]), 0, 0.0, 0.0, 0.5, 1.0, 0)

    counts = np.bincount(values, minlength=256).astype(float)
    probabilities = counts[counts > 0] / float(values.size)
    shannon = float(-np.sum(probabilities * np.log2(probabilities)))
    maximum_probability = float(np.max(probabilities))
    min_entropy = float(-log2(maximum_probability))

    bits = np.unpackbits(values)
    one_fraction = float(np.mean(bits))
    bit_bias = abs(one_fraction - 0.5)

    if values.size < 2 or float(np.std(values[:-1])) == 0.0 or float(np.std(values[1:])) == 0.0:
        serial = 1.0 if values.size >= 2 and np.all(values == values[0]) else 0.0
    else:
        serial = float(np.corrcoef(values[:-1].astype(float), values[1:].astype(float))[0, 1])
        if not np.isfinite(serial):
            serial = 0.0

    longest_run = _longest_run(values)

    if min_entropy < policy.minimum_min_entropy_per_byte:
        violations.append("estimated min-entropy is below policy")
    if bit_bias > policy.maximum_bit_bias:
        violations.append("bit balance is outside policy")
    if abs(serial) > policy.maximum_serial_correlation:
        violations.append("serial correlation is outside policy")
    if longest_run > policy.maximum_repeated_byte_run:
        violations.append("repeated-byte run is outside policy")

    return EntropyReport(
        healthy=not violations,
        violations=tuple(violations),
        sample_bytes=int(values.size),
        shannon_entropy_per_byte=shannon,
        min_entropy_per_byte=min_entropy,
        bit_bias=bit_bias,
        serial_correlation=serial,
        longest_repeated_byte_run=longest_run,
    )


def approximate_monobit_z_score(sample: bytes) -> float:
    values = np.frombuffer(bytes(sample), dtype=np.uint8)
    if values.size == 0:
        raise ValueError("sample cannot be empty")
    bits = np.unpackbits(values)
    ones = float(np.sum(bits))
    n = float(bits.size)
    return (ones - (n / 2.0)) / sqrt(n / 4.0)
