from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

from .attestation import AttestationManifest, AttestationPolicy, AttestationVerifier, HMACAttestor, SignedAttestation
from .incidents import IncidentEvent, IncidentPolicy, build_incidents
from .pulse import PulsePolicy, PulseSchedule, inspect_pulse_schedule
from .qec import QECPolicy, StabilizerCode, SyndromeEvidence, verify_syndrome_evidence
from .scenarios import run_controlled_scenarios
from .thermal import ThermalPolicy, ThermalSample, inspect_thermal_telemetry


def load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))


def key_from_hex(value: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("key must be hexadecimal") from exc
    if len(key) < 16:
        raise ValueError("key must contain at least 16 bytes")
    return key


def parse_artifacts(values: list[str]) -> Dict[str, bytes]:
    artifacts = {}
    for value in values:
        if "=" not in value:
            raise ValueError("artifact arguments must use NAME=PATH")
        name, path = value.split("=", 1)
        if not name or name in artifacts:
            raise ValueError("artifact names must be nonempty and unique")
        artifacts[name] = Path(path).read_bytes()
    return artifacts


def command_attest_sign(args: argparse.Namespace) -> int:
    manifest = AttestationManifest.from_dict(load_json(args.manifest))
    signed = HMACAttestor(args.key_id, key_from_hex(args.key_hex)).sign(manifest)
    data = signed.to_dict()
    if args.output:
        Path(args.output).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print_json(data)
    return 0


def command_attest_verify(args: argparse.Namespace) -> int:
    signed = SignedAttestation.from_dict(load_json(args.attestation))
    policy = AttestationPolicy(
        allowed_issuers=tuple(args.allow_issuer), allowed_subject_kinds=tuple(args.allow_subject_kind),
        maximum_age_seconds=args.maximum_age_seconds, require_policy_digest=args.require_policy_digest,
        require_parent_digest=args.require_parent_digest, require_all_artifacts=not args.allow_missing_artifacts,
    )
    verifier = AttestationVerifier({args.key_id: key_from_hex(args.key_hex)}, policy)
    report = verifier.verify(
        signed, expected_nonce=args.expected_nonce, expected_subject_id=args.expected_subject_id,
        minimum_sequence=args.minimum_sequence, expected_policy_digest=args.expected_policy_digest,
        expected_parent_digest=args.expected_parent_digest, artifact_bytes=parse_artifacts(args.artifact),
    )
    print_json(report.to_dict())
    return 0 if report.valid else 2


def command_pulse_inspect(args: argparse.Namespace) -> int:
    current = PulseSchedule.from_dict(load_json(args.current))
    baseline = PulseSchedule.from_dict(load_json(args.baseline)) if args.baseline else None
    policy_data = load_json(args.policy) if args.policy else {}
    report = inspect_pulse_schedule(current, baseline, PulsePolicy(**policy_data))
    print_json(report.to_dict())
    return 0 if report.valid else 2


def command_qec_verify(args: argparse.Namespace) -> int:
    code = StabilizerCode.from_dict(load_json(args.code))
    evidence = SyndromeEvidence.from_dict(load_json(args.evidence))
    policy_data = load_json(args.policy) if args.policy else {}
    report = verify_syndrome_evidence(
        code, evidence, expected_nonce=args.expected_nonce, minimum_round=args.minimum_round,
        expected_previous_digest=args.expected_previous_digest, policy=QECPolicy(**policy_data),
    )
    print_json(report.to_dict())
    return 0 if report.valid else 2


def command_thermal_inspect(args: argparse.Namespace) -> int:
    data = load_json(args.telemetry)
    rows = data["samples"] if isinstance(data, dict) else data
    samples = tuple(ThermalSample.from_dict(item) for item in rows)
    policy = ThermalPolicy(**load_json(args.policy))
    report = inspect_thermal_telemetry(samples, policy)
    print_json(report.to_dict())
    return 0 if report.valid else 2


def command_scenarios(args: argparse.Namespace) -> int:
    report = run_controlled_scenarios()
    print_json(report)
    return 0 if report["false_positive"] == 0 and report["false_negative"] == 0 else 2


def command_incidents(args: argparse.Namespace) -> int:
    data = load_json(args.events)
    rows = data["events"] if isinstance(data, dict) else data
    policy_data = load_json(args.policy) if args.policy else {}
    records = build_incidents((IncidentEvent.from_dict(item) for item in rows), IncidentPolicy(**policy_data))
    print_json([item.to_dict() for item in records])
    return 0


def register_trust_subcommands(subparsers: argparse._SubParsersAction) -> None:
    attest = subparsers.add_parser("attest", help="Create or verify authenticated artifact attestations")
    attest_sub = attest.add_subparsers(dest="attest_command", required=True)
    sign = attest_sub.add_parser("sign", help="Authenticate an attestation manifest with HMAC-SHA-256")
    sign.add_argument("manifest")
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--key-hex", required=True)
    sign.add_argument("--output")
    sign.set_defaults(function=command_attest_sign)
    verify = attest_sub.add_parser("verify", help="Verify an authenticated attestation and its bound artifacts")
    verify.add_argument("attestation")
    verify.add_argument("--key-id", required=True)
    verify.add_argument("--key-hex", required=True)
    verify.add_argument("--expected-nonce")
    verify.add_argument("--expected-subject-id")
    verify.add_argument("--minimum-sequence", type=int)
    verify.add_argument("--expected-policy-digest")
    verify.add_argument("--expected-parent-digest")
    verify.add_argument("--allow-issuer", action="append", default=[])
    verify.add_argument("--allow-subject-kind", action="append", default=[])
    verify.add_argument("--maximum-age-seconds", type=int, default=900)
    verify.add_argument("--require-policy-digest", action="store_true")
    verify.add_argument("--require-parent-digest", action="store_true")
    verify.add_argument("--allow-missing-artifacts", action="store_true")
    verify.add_argument("--artifact", action="append", default=[])
    verify.set_defaults(function=command_attest_verify)

    pulse = subparsers.add_parser("pulse", help="Inspect physical control-pulse schedules")
    pulse_sub = pulse.add_subparsers(dest="pulse_command", required=True)
    pulse_inspect = pulse_sub.add_parser("inspect")
    pulse_inspect.add_argument("current")
    pulse_inspect.add_argument("--baseline")
    pulse_inspect.add_argument("--policy")
    pulse_inspect.set_defaults(function=command_pulse_inspect)

    qec = subparsers.add_parser("qec", help="Verify stabilizer syndrome evidence")
    qec_sub = qec.add_subparsers(dest="qec_command", required=True)
    qec_verify = qec_sub.add_parser("verify")
    qec_verify.add_argument("code")
    qec_verify.add_argument("evidence")
    qec_verify.add_argument("--policy")
    qec_verify.add_argument("--expected-nonce")
    qec_verify.add_argument("--minimum-round", type=int)
    qec_verify.add_argument("--expected-previous-digest")
    qec_verify.set_defaults(function=command_qec_verify)

    thermal = subparsers.add_parser("thermal", help="Inspect calibrated thermodynamic telemetry")
    thermal_sub = thermal.add_subparsers(dest="thermal_command", required=True)
    thermal_inspect = thermal_sub.add_parser("inspect")
    thermal_inspect.add_argument("telemetry")
    thermal_inspect.add_argument("--policy", required=True)
    thermal_inspect.set_defaults(function=command_thermal_inspect)

    scenarios = subparsers.add_parser("scenarios", help="Run the controlled QSec trust-mesh attack matrix")
    scenarios.set_defaults(function=command_scenarios)

    incidents = subparsers.add_parser("incidents", help="Build deterministic incident records from evidence events")
    incidents.add_argument("events")
    incidents.add_argument("--policy")
    incidents.set_defaults(function=command_incidents)
