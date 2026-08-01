from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

CORE_PATH = Path(__file__).with_name("quantum_core.py").resolve()
SPEC = importlib.util.spec_from_file_location("_qsec_quantum_core_worker", CORE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load the QSec quantum core")
CORE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CORE
SPEC.loader.exec_module(CORE)


def main() -> int:
    try:
        return CORE.run_worker(sys.stdin, sys.stdout, backend_id="python-isolated")
    except (CORE.QuantumProtocolError, ValueError, OverflowError) as exc:
        print(f"QSEC-QE/1\nerror={type(exc).__name__}:{exc}\nEND", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
