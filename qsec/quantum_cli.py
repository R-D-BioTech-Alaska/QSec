from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .quantum_core import QuantumRequest
from .quantum_hopper import HopperMesh, QuantumReplayGuard, native_worker, python_worker, qsa_worker
from .quantum_scenarios import run_quantum_scenarios, summarize_quantum_scenarios


def _load_request(path: str | Path) -> QuantumRequest:
    with Path(path).open("r", encoding="utf-8") as handle:
        payload: Any = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("quantum request must contain a JSON object")
    return QuantumRequest.from_dict(payload)


def _default_native() -> Path | None:
    configured = os.environ.get("QSEC_NATIVE_CORE")
    if configured:
        return Path(configured)
    candidate = Path(__file__).resolve().parents[1] / "build" / "qsec-law-core"
    return candidate if candidate.is_file() else None


def command_quantum_verify(args: argparse.Namespace) -> int:
    request = _load_request(args.request)
    workers = [python_worker()]
    native_path = Path(args.native) if args.native else _default_native()
    if native_path is not None:
        workers.append(native_worker(native_path))
    if args.qsa:
        workers.append(qsa_worker())
    if len(workers) < 2:
        raise ValueError("cross-code verification requires --native, QSEC_NATIVE_CORE, or --qsa")
    replay_guard = None if args.no_replay_guard else QuantumReplayGuard(args.replay_db)
    mesh = HopperMesh(
        workers,
        minimum_agreement=args.minimum_agreement,
        require_unanimous=not args.allow_disagreement,
        replay_guard=replay_guard,
    )
    receipt = mesh.verify(request)
    print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
    return 0 if receipt.accepted else 2


def command_quantum_scenarios(args: argparse.Namespace) -> int:
    native_path = Path(args.native) if args.native else _default_native()
    if native_path is None:
        raise ValueError("quantum scenarios require --native or QSEC_NATIVE_CORE")
    summary = summarize_quantum_scenarios(run_quantum_scenarios(native_path))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 2


def register_quantum_subcommands(subparsers: argparse._SubParsersAction) -> None:
    quantum = subparsers.add_parser("quantum", help="Run cross-code quantum-law verification")
    quantum_subparsers = quantum.add_subparsers(dest="quantum_command", required=True)
    verify = quantum_subparsers.add_parser("verify", help="Verify one canonical quantum request across isolated workers")
    verify.add_argument("request")
    verify.add_argument("--native", help="Path to the compiled qsec-law-core executable")
    verify.add_argument("--qsa", action="store_true", help="Add an isolated QSA worker to the verification route")
    verify.add_argument("--replay-db", default="qsec-quantum-nonces.sqlite3")
    verify.add_argument("--no-replay-guard", action="store_true")
    verify.add_argument("--minimum-agreement", type=int)
    verify.add_argument("--allow-disagreement", action="store_true")
    verify.set_defaults(function=command_quantum_verify)

    scenarios = quantum_subparsers.add_parser("scenarios", help="Run the controlled cross-code acceptance matrix")
    scenarios.add_argument("--native", help="Path to the compiled qsec-law-core executable")
    scenarios.set_defaults(function=command_quantum_scenarios)
