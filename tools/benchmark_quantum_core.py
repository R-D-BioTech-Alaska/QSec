from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from qsec.quantum_core import QuantumGate, QuantumRequest
from qsec.quantum_hopper import HopperMesh, native_worker, python_worker
from qsec.quantum_scenarios import run_quantum_scenarios, summarize_quantum_scenarios


def rate(operation, iterations: int) -> float:
    samples = []
    for _ in range(3):
        start = time.perf_counter()
        for _ in range(iterations):
            operation()
        elapsed = time.perf_counter() - start
        samples.append(iterations / elapsed)
    return statistics.median(samples)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the QSec cross-code quantum law mesh")
    parser.add_argument("--native", required=True)
    parser.add_argument("--iterations", type=int, default=25)
    args = parser.parse_args()

    native_path = Path(args.native).resolve()
    request = QuantumRequest(
        request_id="1" * 64,
        nonce="2" * 64,
        policy_digest="3" * 64,
        parent_digest="4" * 64,
        qubits=4,
        initial_basis=0,
        gates=(
            QuantumGate("H", 0),
            QuantumGate("CNOT", 0, 1),
            QuantumGate("CNOT", 0, 2),
            QuantumGate("CNOT", 0, 3),
            QuantumGate("RZ", 2, angle_nanoradians=314159265),
            QuantumGate("RX", 1, angle_nanoradians=-225000000),
            QuantumGate("SWAP", 1, 3),
        ),
    )
    py = python_worker()
    native = native_worker(native_path)
    mesh = HopperMesh([py, native])
    result = {
        "protocol": "QSEC-QH/1",
        "qubits": request.qubits,
        "gates": len(request.gates),
        "python_isolated_ops_per_second": rate(lambda: py.verify(request), args.iterations),
        "native_cpp_ops_per_second": rate(lambda: native.verify(request), args.iterations),
        "unanimous_mesh_ops_per_second": rate(lambda: mesh.verify(request), args.iterations),
        "controlled_scenarios": summarize_quantum_scenarios(run_quantum_scenarios(native_path)),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["controlled_scenarios"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
