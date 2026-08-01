from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from qsec.qsa_adapter import execute_with_qsa
from qsec.quantum_core import QuantumProtocolError, QuantumRequest


def main() -> int:
    try:
        request = QuantumRequest.decode(sys.stdin.buffer.read())
        sys.stdout.buffer.write(execute_with_qsa(request).encode())
        sys.stdout.buffer.flush()
        return 0
    except (QuantumProtocolError, RuntimeError, ValueError, OverflowError) as exc:
        print(f"QSEC-QE/1\nerror={type(exc).__name__}:{exc}\nEND", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
