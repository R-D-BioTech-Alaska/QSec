from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .model import Finding, FindingStatus, Severity
from .trust import canonical_json, make_finding, now_utc, parse_time, sha256_bytes


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> Tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


@dataclass(frozen=True)
class ArtifactBinding:
    name: str
    kind: str
    sha256: str
    size: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        digest = self.sha256.lower()
        if not self.name or not self.kind:
            raise ValueError("artifact name and kind are required")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("artifact sha256 must be a hexadecimal SHA-256 digest")
        if self.size < 0:
            raise ValueError("artifact size cannot be negative")

    @classmethod
    def from_bytes(cls, name: str, kind: str, data: bytes, metadata: Optional[Dict[str, Any]] = None) -> "ArtifactBinding":
        return cls(name=name, kind=kind, sha256=sha256_bytes(data), size=len(data), metadata=dict(metadata or {}))

    @classmethod
    def from_file(cls, name: str, kind: str, path: str | Path, metadata: Optional[Dict[str, Any]] = None) -> "ArtifactBinding":
        digest, size = sha256_file(path)
        return cls(name=name, kind=kind, sha256=digest, size=size, metadata=dict(metadata or {}))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ArtifactBinding":
        return cls(str(data["name"]), str(data["kind"]), str(data["sha256"]).lower(), int(data["size"]), dict(data.get("metadata", {})))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttestationManifest:
    subject_id: str
    subject_kind: str
    issuer: str
    issued_at: str
    expires_at: str
    nonce: str
    sequence: int
    artifacts: Tuple[ArtifactBinding, ...] = ()
    claims: Dict[str, Any] = field(default_factory=dict)
    policy_digest: Optional[str] = None
    parent_digest: Optional[str] = None
    schema_version: str = "qsec.attestation.v1"

    def __post_init__(self):
        if not self.subject_id or not self.subject_kind or not self.issuer or not self.nonce:
            raise ValueError("subject, issuer, and nonce fields are required")
        if self.sequence < 0:
            raise ValueError("sequence cannot be negative")
        if parse_time(self.expires_at) <= parse_time(self.issued_at):
            raise ValueError("expires_at must be after issued_at")
        names = [item.name for item in self.artifacts]
        if len(names) != len(set(names)):
            raise ValueError("artifact names must be unique")

    @classmethod
    def issue(
        cls,
        subject_id: str,
        subject_kind: str,
        issuer: str,
        nonce: str,
        sequence: int,
        artifacts: Iterable[ArtifactBinding] = (),
        claims: Optional[Dict[str, Any]] = None,
        lifetime_seconds: int = 300,
        policy_digest: Optional[str] = None,
        parent_digest: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> "AttestationManifest":
        if lifetime_seconds <= 0:
            raise ValueError("lifetime_seconds must be positive")
        current = (now or now_utc()).astimezone(timezone.utc)
        return cls(
            subject_id=subject_id,
            subject_kind=subject_kind,
            issuer=issuer,
            issued_at=current.isoformat(),
            expires_at=(current + timedelta(seconds=lifetime_seconds)).isoformat(),
            nonce=nonce,
            sequence=sequence,
            artifacts=tuple(artifacts),
            claims=dict(claims or {}),
            policy_digest=policy_digest,
            parent_digest=parent_digest,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AttestationManifest":
        return cls(
            subject_id=str(data["subject_id"]), subject_kind=str(data["subject_kind"]), issuer=str(data["issuer"]),
            issued_at=str(data["issued_at"]), expires_at=str(data["expires_at"]), nonce=str(data["nonce"]),
            sequence=int(data["sequence"]), artifacts=tuple(ArtifactBinding.from_dict(item) for item in data.get("artifacts", [])),
            claims=dict(data.get("claims", {})), policy_digest=data.get("policy_digest"), parent_digest=data.get("parent_digest"),
            schema_version=str(data.get("schema_version", "qsec.attestation.v1")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version, "subject_id": self.subject_id, "subject_kind": self.subject_kind,
            "issuer": self.issuer, "issued_at": self.issued_at, "expires_at": self.expires_at, "nonce": self.nonce,
            "sequence": self.sequence, "artifacts": [item.to_dict() for item in self.artifacts], "claims": self.claims,
            "policy_digest": self.policy_digest, "parent_digest": self.parent_digest,
        }

    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()))


@dataclass(frozen=True)
class SignedAttestation:
    manifest: AttestationManifest
    key_id: str
    signature: str
    algorithm: str = "HMAC-SHA256"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SignedAttestation":
        return cls(AttestationManifest.from_dict(data["manifest"]), str(data["key_id"]), str(data["signature"]).lower(), str(data.get("algorithm", "HMAC-SHA256")))

    def to_dict(self) -> Dict[str, Any]:
        return {"algorithm": self.algorithm, "key_id": self.key_id, "manifest": self.manifest.to_dict(), "signature": self.signature}


class HMACAttestor:
    def __init__(self, key_id: str, key: bytes):
        if not key_id or len(key) < 16:
            raise ValueError("key_id and an attestation key of at least 16 bytes are required")
        self.key_id = key_id
        self._key = bytes(key)

    def sign(self, manifest: AttestationManifest) -> SignedAttestation:
        signature = hmac.new(self._key, canonical_json(manifest.to_dict()), hashlib.sha256).hexdigest()
        return SignedAttestation(manifest, self.key_id, signature)


@dataclass(frozen=True)
class AttestationPolicy:
    allowed_issuers: Tuple[str, ...] = ()
    allowed_subject_kinds: Tuple[str, ...] = ()
    maximum_age_seconds: int = 900
    maximum_future_skew_seconds: int = 30
    require_policy_digest: bool = False
    require_parent_digest: bool = False
    require_all_artifacts: bool = True


@dataclass(frozen=True)
class AttestationReport:
    valid: bool
    manifest_digest: str
    checks: Dict[str, Any]
    findings: Tuple[Finding, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {"valid": self.valid, "manifest_digest": self.manifest_digest, "checks": self.checks, "findings": [item.to_dict() for item in self.findings]}


class AttestationVerifier:
    def __init__(self, keys: Mapping[str, bytes], policy: AttestationPolicy = AttestationPolicy()):
        self.keys = {str(key_id): bytes(key) for key_id, key in keys.items()}
        if any(len(key) < 16 for key in self.keys.values()):
            raise ValueError("all attestation keys must contain at least 16 bytes")
        self.policy = policy

    @staticmethod
    def _artifact_threat(kind: str) -> Tuple[str, str]:
        normalized = kind.lower()
        if "pulse" in normalized or "waveform" in normalized:
            return "pulse_parasite", "Pulse Substitution"
        if "state" in normalized or "model" in normalized:
            return "state_doppelganger", "State Replacement"
        if "policy" in normalized:
            return "policy_parasite", "Policy Substitution"
        if "circuit" in normalized:
            return "shadow_circuit", "Circuit Splicing"
        return "oracle_mimic", "Compiler Poisoning"

    def verify(
        self,
        attestation: SignedAttestation,
        *,
        now: Optional[datetime] = None,
        expected_nonce: Optional[str] = None,
        expected_subject_id: Optional[str] = None,
        minimum_sequence: Optional[int] = None,
        expected_policy_digest: Optional[str] = None,
        expected_parent_digest: Optional[str] = None,
        artifact_bytes: Optional[Mapping[str, bytes]] = None,
    ) -> AttestationReport:
        current = (now or now_utc()).astimezone(timezone.utc)
        manifest = attestation.manifest
        findings = []
        checks: Dict[str, Any] = {"algorithm": attestation.algorithm, "key_id": attestation.key_id}
        key = self.keys.get(attestation.key_id)
        signature_valid = False
        if attestation.algorithm != "HMAC-SHA256" or key is None:
            findings.append(make_finding("oracle_mimic", "Backend Impersonation", Severity.CRITICAL, 0.99, "The attestation authentication method or key is not trusted.", checks, FindingStatus.BREACH))
        else:
            expected = hmac.new(key, canonical_json(manifest.to_dict()), hashlib.sha256).hexdigest()
            signature_valid = hmac.compare_digest(expected, attestation.signature)
            if not signature_valid:
                findings.append(make_finding("oracle_mimic", "Response Replay", Severity.CRITICAL, 0.99, "The attestation signature does not authenticate the manifest.", {"key_id": attestation.key_id}, FindingStatus.BREACH))
        checks["signature_valid"] = signature_valid

        issued, expires = parse_time(manifest.issued_at), parse_time(manifest.expires_at)
        age = (current - issued).total_seconds()
        future = (issued - current).total_seconds()
        checks.update({"age_seconds": age, "future_seconds": future, "expired": current >= expires})
        if future > self.policy.maximum_future_skew_seconds or age > self.policy.maximum_age_seconds or current >= expires:
            findings.append(make_finding("oracle_mimic", "Response Replay", Severity.HIGH, 0.96, "The attestation is outside its accepted freshness window.", checks.copy()))

        issuer_allowed = not self.policy.allowed_issuers or manifest.issuer in self.policy.allowed_issuers
        kind_allowed = not self.policy.allowed_subject_kinds or manifest.subject_kind in self.policy.allowed_subject_kinds
        checks.update({"issuer_allowed": issuer_allowed, "subject_kind_allowed": kind_allowed})
        if not issuer_allowed or not kind_allowed:
            findings.append(make_finding("oracle_mimic", "Backend Impersonation", Severity.CRITICAL, 0.98, "The issuer or subject type is outside the approved trust boundary.", {"issuer": manifest.issuer, "subject_kind": manifest.subject_kind}, FindingStatus.BREACH))
        if expected_nonce is not None and manifest.nonce != expected_nonce:
            findings.append(make_finding("intent_forger", "Context Replay", Severity.CRITICAL, 0.98, "The attestation nonce does not match the active challenge.", {"expected": expected_nonce, "actual": manifest.nonce}, FindingStatus.BREACH))
        if expected_subject_id is not None and manifest.subject_id != expected_subject_id:
            findings.append(make_finding("oracle_mimic", "Backend Impersonation", Severity.CRITICAL, 0.98, "The attestation is bound to a different subject.", {"expected": expected_subject_id, "actual": manifest.subject_id}, FindingStatus.BREACH))
        if minimum_sequence is not None and manifest.sequence < minimum_sequence:
            findings.append(make_finding("intent_forger", "Request Rebinding", Severity.HIGH, 0.96, "The attestation sequence moved backward.", {"minimum": minimum_sequence, "actual": manifest.sequence}))
        if self.policy.require_policy_digest and not manifest.policy_digest:
            findings.append(make_finding("policy_parasite", "Policy Substitution", Severity.CRITICAL, 0.97, "The attestation does not bind the active policy.", {}, FindingStatus.BREACH))
        if expected_policy_digest is not None and manifest.policy_digest != expected_policy_digest:
            findings.append(make_finding("policy_parasite", "Rule Downgrade", Severity.CRITICAL, 0.99, "The policy digest does not match the required policy.", {"expected": expected_policy_digest, "actual": manifest.policy_digest}, FindingStatus.BREACH))
        if self.policy.require_parent_digest and not manifest.parent_digest:
            findings.append(make_finding("oracle_mimic", "Response Replay", Severity.HIGH, 0.93, "The attestation does not bind its parent trust state.", {}))
        if expected_parent_digest is not None and manifest.parent_digest != expected_parent_digest:
            findings.append(make_finding("oracle_mimic", "Response Replay", Severity.CRITICAL, 0.98, "The parent digest does not match the accepted chain.", {"expected": expected_parent_digest, "actual": manifest.parent_digest}, FindingStatus.BREACH))

        supplied = dict(artifact_bytes or {})
        artifact_checks = []
        for binding in manifest.artifacts:
            payload = supplied.get(binding.name)
            if payload is None:
                result = {"name": binding.name, "kind": binding.kind, "checked": False}
                artifact_checks.append(result)
                if self.policy.require_all_artifacts:
                    threat, technique = self._artifact_threat(binding.kind)
                    findings.append(make_finding(threat, technique, Severity.HIGH, 0.90, f"Attested artifact {binding.name} was not supplied for verification.", result))
                continue
            actual_digest, actual_size = sha256_bytes(payload), len(payload)
            matched = actual_digest == binding.sha256 and actual_size == binding.size
            result = {"name": binding.name, "kind": binding.kind, "checked": True, "matched": matched, "expected_sha256": binding.sha256, "actual_sha256": actual_digest, "expected_size": binding.size, "actual_size": actual_size}
            artifact_checks.append(result)
            if not matched:
                threat, technique = self._artifact_threat(binding.kind)
                findings.append(make_finding(threat, technique, Severity.CRITICAL, 0.99, f"Attested artifact {binding.name} does not match its authenticated binding.", result, FindingStatus.BREACH))
        checks["artifacts"] = artifact_checks
        ordered = tuple(sorted(findings, key=lambda item: int(item.severity), reverse=True))
        return AttestationReport(not any(item.severity >= Severity.HIGH for item in ordered), manifest.digest(), checks, ordered)
