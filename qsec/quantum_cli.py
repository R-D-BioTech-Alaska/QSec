from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .qsa_evidence import QSAEvidencePolicy, QSAEvidenceRequest, run_qsa_evidence
from .qsa_grover import QSAGroverPolicy, QSAGroverRequest, run_qsa_grover
from .quantum_core import QuantumRequest
from .quantum_hopper import HopperMesh, QuantumReplayGuard, native_worker, python_worker, qsa_worker
from .quantum_scenarios import run_quantum_scenarios, summarize_quantum_scenarios


def _load_object(path: str | Path) -> Mapping[str, object]:
    with Path(path).open("r", encoding="utf-8") as handle:
        payload: Any = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _load_request(path: str | Path) -> QuantumRequest:
    return QuantumRequest.from_dict(_load_object(path))


def _load_qsa_request(path: str | Path) -> QSAEvidenceRequest:
    return QSAEvidenceRequest.from_dict(_load_object(path))


def _load_qsa_policy(path: str | Path | None) -> QSAEvidencePolicy:
    return QSAEvidencePolicy() if path is None else QSAEvidencePolicy.from_dict(_load_object(path))


def _load_grover_request(path: str | Path) -> QSAGroverRequest:
    return QSAGroverRequest.from_dict(_load_object(path))


def _load_grover_policy(path: str | Path | None) -> QSAGroverPolicy:
    return QSAGroverPolicy() if path is None else QSAGroverPolicy.from_dict(_load_object(path))


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
    payload = receipt.to_dict()
    accepted = receipt.accepted
    if args.qsa:
        evidence = run_qsa_evidence(
            QSAEvidenceRequest.from_quantum_request(request),
            _load_qsa_policy(args.qsa_policy),
            timeout_seconds=args.qsa_timeout,
        )
        payload["mesh_accepted"] = receipt.accepted
        payload["qsa_evidence"] = evidence.to_dict()
        accepted = accepted and evidence.accepted
        payload["accepted"] = accepted
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if accepted else 2


def command_qsa_evidence(args: argparse.Namespace) -> int:
    receipt = run_qsa_evidence(
        _load_qsa_request(args.request),
        _load_qsa_policy(args.policy),
        timeout_seconds=args.timeout,
    )
    print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
    return 0 if receipt.accepted else 2


def command_qsa_grover(args: argparse.Namespace) -> int:
    request = _load_grover_request(args.request)
    if not args.no_replay_guard:
        QuantumReplayGuard(args.replay_db).consume(request)
    receipt = run_qsa_grover(
        request,
        _load_grover_policy(args.policy),
        timeout_seconds=args.timeout,
    )
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

    verify = quantum_subparsers.add_parser(
        "verify",
        help="Verify one canonical quantum request across isolated workers",
    )
    verify.add_argument("request")
    verify.add_argument("--native", help="Path to the compiled qsec-law-core executable")
    verify.add_argument("--qsa", action="store_true", help="Add QSA cross-code and structural evidence")
    verify.add_argument("--qsa-policy", help="QSA evidence policy JSON")
    verify.add_argument("--qsa-timeout", type=float, default=30.0)
    verify.add_argument("--replay-db", default="qsec-quantum-nonces.sqlite3")
    verify.add_argument("--no-replay-guard", action="store_true")
    verify.add_argument("--minimum-agreement", type=int)
    verify.add_argument("--allow-disagreement", action="store_true")
    verify.set_defaults(function=command_quantum_verify)

    evidence = quantum_subparsers.add_parser(
        "qsa-evidence",
        help="Capture an isolated QSA 0.2 structural state receipt",
    )
    evidence.add_argument("request")
    evidence.add_argument("--policy", help="QSA evidence policy JSON")
    evidence.add_argument("--timeout", type=float, default=30.0)
    evidence.set_defaults(function=command_qsa_evidence)

    grover = quantum_subparsers.add_parser(
        "qsa-grover",
        help="Run a nonce-bound QSA Grover capability challenge",
    )
    grover.add_argument("request")
    grover.add_argument("--policy", help="QSA Grover policy JSON")
    grover.add_argument("--timeout", type=float, default=30.0)
    grover.add_argument("--replay-db", default="qsec-grover-nonces.sqlite3")
    grover.add_argument("--no-replay-guard", action="store_true")
    grover.set_defaults(function=command_qsa_grover)

    scenarios = quantum_subparsers.add_parser(
        "scenarios",
        help="Run the controlled cross-code acceptance matrix",
    )
    scenarios.add_argument("--native", help="Path to the compiled qsec-law-core executable")
    scenarios.set_defaults(function=command_quantum_scenarios)
