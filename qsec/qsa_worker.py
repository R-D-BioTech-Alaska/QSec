from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Mapping

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from qsec.qsa_adapter import execute_with_qsa
from qsec.qsa_evidence import QSAEvidencePolicy, QSAEvidenceRequest, collect_qsa_evidence
from qsec.quantum_core import QuantumProtocolError, QuantumRequest


def _evidence() -> int:
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("QSA evidence payload must be an object")
    request_data = payload.get("request")
    policy_data = payload.get("policy", {})
    if not isinstance(request_data, Mapping) or not isinstance(policy_data, Mapping):
        raise ValueError("QSA evidence request and policy must be objects")
    receipt = collect_qsa_evidence(
        QSAEvidenceRequest.from_dict(request_data),
        QSAEvidencePolicy.from_dict(policy_data),
    )
    sys.stdout.write(json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0 if receipt.accepted else 2


def main() -> int:
    try:
        if sys.argv[1:] == ["--evidence"]:
            return _evidence()
        request = QuantumRequest.decode(sys.stdin.buffer.read())
        sys.stdout.buffer.write(execute_with_qsa(request).encode())
        sys.stdout.buffer.flush()
        return 0
    except (json.JSONDecodeError, QuantumProtocolError, RuntimeError, TypeError, ValueError, OverflowError) as exc:
        print(f"QSEC-QE/1\nerror={type(exc).__name__}:{exc}\nEND", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
