from __future__ import annotations

import hashlib
import json
import secrets
import tempfile
import time
from pathlib import Path

from qsec.circuit import CircuitManifest, compare_circuits
from qsec.entropy import assess_entropy
from qsec.evidence import EvidenceLedger


def timed(function, repeats: int = 5):
    measurements = []
    for _ in range(repeats):
        started = time.perf_counter()
        function()
        measurements.append(time.perf_counter() - started)
    measurements.sort()
    return measurements[len(measurements) // 2]


def circuit_with_operations(count: int):
    operations = []
    for index in range(count):
        operations.append({"name": "RZ", "qubits": [index % 16], "parameters": [index * 1e-6]})
    return CircuitManifest.from_dict({"name": "benchmark", "num_qubits": 16, "operations": operations})


def main():
    entropy_sample = secrets.token_bytes(1024 * 1024)
    entropy_seconds = timed(lambda: assess_entropy(entropy_sample))

    baseline = circuit_with_operations(10_000)
    current = circuit_with_operations(10_000)
    circuit_seconds = timed(lambda: compare_circuits(baseline, current))

    with tempfile.TemporaryDirectory() as directory:
        ledger = EvidenceLedger(Path(directory) / "evidence.jsonl", key=secrets.token_bytes(32))
        started = time.perf_counter()
        for index in range(1_000):
            ledger.append({"index": index, "digest": hashlib.sha256(str(index).encode()).hexdigest()})
        ledger_append_seconds = time.perf_counter() - started
        ledger_verify_seconds = timed(ledger.verify)

    result = {
        "schema": "qsec.benchmark.v1",
        "entropy": {
            "bytes": len(entropy_sample),
            "median_seconds": entropy_seconds,
            "mib_per_second": (len(entropy_sample) / (1024 * 1024)) / entropy_seconds,
        },
        "circuit_comparison": {
            "operations": len(baseline.operations),
            "median_seconds": circuit_seconds,
            "operations_per_second": len(baseline.operations) / circuit_seconds,
        },
        "evidence_ledger": {
            "records": 1_000,
            "append_seconds": ledger_append_seconds,
            "append_records_per_second": 1_000 / ledger_append_seconds,
            "verify_median_seconds": ledger_verify_seconds,
            "verify_records_per_second": 1_000 / ledger_verify_seconds,
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
