from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from .circuit import CircuitManifest, CircuitPolicy, compare_circuits
from .crypto import scan_path, summarize_findings
from .engine import QSecPolicy, QuantumSecurityEngine
from .entropy import assess_entropy
from .evidence import EvidenceLedger
from .model import SecuritySnapshot
from .physics import validate_state_payload
from .threat_catalog import THREATS
from .trust_cli import register_trust_subcommands


def _load_json(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))


def _key_from_hex(value: Optional[str]) -> Optional[bytes]:
    if value is None:
        return None
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("ledger key must be hexadecimal") from exc
    if not key:
        raise ValueError("ledger key cannot be empty")
    return key


def command_entropy(args: argparse.Namespace) -> int:
    sample = Path(args.path).read_bytes()
    report = assess_entropy(sample)
    _print_json(report.to_dict())
    return 0 if report.healthy else 2


def command_verify_state(args: argparse.Namespace) -> int:
    payload = _load_json(args.path)
    report = validate_state_payload(payload)
    _print_json(report.to_dict())
    return 0 if report.valid else 2


def command_audit_crypto(args: argparse.Namespace) -> int:
    findings = scan_path(args.path, maximum_file_bytes=args.maximum_file_bytes)
    data = {
        "summary": summarize_findings(findings),
        "findings": [item.to_dict() for item in findings],
    }
    _print_json(data)
    return 2 if data["summary"]["quantum_vulnerable_matches"] else 0


def command_compare_circuit(args: argparse.Namespace) -> int:
    baseline = CircuitManifest.from_dict(_load_json(args.baseline))
    current = CircuitManifest.from_dict(_load_json(args.current))
    allowed_gates = tuple(args.allow_gate) if args.allow_gate else None
    policy = CircuitPolicy(
        allowed_gates=allowed_gates,
        maximum_qubits=args.maximum_qubits,
        maximum_depth=args.maximum_depth,
        maximum_operations=args.maximum_operations,
        parameter_tolerance=args.parameter_tolerance,
        require_exact_manifest=not args.policy_only,
    )
    delta = compare_circuits(baseline, current, policy)
    _print_json(delta.to_dict())
    return 0 if delta.matched else 2


def command_inspect(args: argparse.Namespace) -> int:
    baseline = SecuritySnapshot.from_dict(_load_json(args.baseline)) if args.baseline else None
    current = SecuritySnapshot.from_dict(_load_json(args.current))
    report = QuantumSecurityEngine(QSecPolicy()).inspect(current=current, baseline=baseline)
    data = report.to_dict()
    if args.ledger:
        ledger = EvidenceLedger(args.ledger, key=_key_from_hex(args.ledger_key_hex))
        record = ledger.append({"type": "inspection", "report": data})
        data["evidence_record_hash"] = record["record_hash"]
    _print_json(data)
    return 0 if report.passed else 2


def command_ledger_verify(args: argparse.Namespace) -> int:
    ledger = EvidenceLedger(args.path, key=_key_from_hex(args.key_hex))
    report = ledger.verify()
    _print_json(report.to_dict())
    return 0 if report.valid else 2


def command_ledger_append(args: argparse.Namespace) -> int:
    event = _load_json(args.event)
    ledger = EvidenceLedger(args.path, key=_key_from_hex(args.key_hex))
    record = ledger.append(event)
    _print_json(record)
    return 0


def command_threats(args: argparse.Namespace) -> int:
    rows = []
    for key, threat in sorted(THREATS.items()):
        rows.append(
            {
                "key": key,
                "code": threat.code,
                "name": threat.name,
                "layer": threat.layer,
                "description": threat.description,
                "techniques": list(threat.techniques),
                "evidence": list(threat.evidence),
            }
        )
    _print_json(rows)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qsec", description="Quantum-system and post-quantum security inspection")
    subparsers = parser.add_subparsers(dest="command", required=True)

    entropy = subparsers.add_parser("entropy", help="Assess a raw entropy sample")
    entropy.add_argument("path")
    entropy.set_defaults(function=command_entropy)

    state = subparsers.add_parser("verify-state", help="Verify physical constraints in a JSON state payload")
    state.add_argument("path")
    state.set_defaults(function=command_verify_state)

    crypto = subparsers.add_parser("audit-crypto", help="Inventory classical and post-quantum algorithms in source and configuration files")
    crypto.add_argument("path")
    crypto.add_argument("--maximum-file-bytes", type=int, default=4 * 1024 * 1024)
    crypto.set_defaults(function=command_audit_crypto)

    circuit = subparsers.add_parser("compare-circuit", help="Compare a trusted and current circuit manifest")
    circuit.add_argument("baseline")
    circuit.add_argument("current")
    circuit.add_argument("--allow-gate", action="append", default=[])
    circuit.add_argument("--maximum-qubits", type=int)
    circuit.add_argument("--maximum-depth", type=int)
    circuit.add_argument("--maximum-operations", type=int)
    circuit.add_argument("--parameter-tolerance", type=float, default=1e-9)
    circuit.add_argument("--policy-only", action="store_true", help="Apply policy without requiring an exact manifest match")
    circuit.set_defaults(function=command_compare_circuit)

    inspect = subparsers.add_parser("inspect", help="Inspect a current security snapshot against an optional baseline")
    inspect.add_argument("current")
    inspect.add_argument("--baseline")
    inspect.add_argument("--ledger")
    inspect.add_argument("--ledger-key-hex")
    inspect.set_defaults(function=command_inspect)

    threats = subparsers.add_parser("threats", help="Print the canonical QSec threat taxonomy")
    threats.set_defaults(function=command_threats)

    ledger = subparsers.add_parser("ledger", help="Append or verify tamper-evident evidence")
    ledger_subparsers = ledger.add_subparsers(dest="ledger_command", required=True)
    ledger_verify = ledger_subparsers.add_parser("verify")
    ledger_verify.add_argument("path")
    ledger_verify.add_argument("--key-hex")
    ledger_verify.set_defaults(function=command_ledger_verify)
    ledger_append = ledger_subparsers.add_parser("append")
    ledger_append.add_argument("path")
    ledger_append.add_argument("event")
    ledger_append.add_argument("--key-hex")
    ledger_append.set_defaults(function=command_ledger_append)

    register_trust_subcommands(subparsers)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.function(args))
    except (FileNotFoundError, ValueError, TypeError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
