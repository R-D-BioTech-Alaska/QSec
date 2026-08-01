from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import IntEnum
import hashlib
import hmac
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .model import Finding, FindingStatus, Severity
from .trust import canonical_json, make_finding, now_utc, parse_time, sha256_bytes


class ActionRisk(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


@dataclass(frozen=True)
class ActionRequest:
    request_id: str
    actor_id: str
    action: str
    resource: str
    scopes: Tuple[str, ...]
    risk: ActionRisk
    nonce: str
    issued_at: str
    expires_at: str
    context: Dict[str, Any] = field(default_factory=dict)
    attestation_digest: Optional[str] = None
    policy_digest: Optional[str] = None
    schema_version: str = "qsec.action-request.v1"

    def __post_init__(self):
        if not all((self.request_id, self.actor_id, self.action, self.resource, self.nonce)):
            raise ValueError("request identity, actor, action, resource, and nonce are required")
        if parse_time(self.expires_at) <= parse_time(self.issued_at):
            raise ValueError("request expires_at must be after issued_at")
        if len(self.scopes) != len(set(self.scopes)):
            raise ValueError("request scopes must be unique")

    @classmethod
    def issue(
        cls,
        request_id: str,
        actor_id: str,
        action: str,
        resource: str,
        scopes: Iterable[str],
        risk: ActionRisk,
        nonce: str,
        *,
        context: Optional[Dict[str, Any]] = None,
        attestation_digest: Optional[str] = None,
        policy_digest: Optional[str] = None,
        lifetime_seconds: int = 120,
        now: Optional[datetime] = None,
    ) -> "ActionRequest":
        if lifetime_seconds <= 0:
            raise ValueError("lifetime_seconds must be positive")
        current = (now or now_utc()).astimezone(timezone.utc)
        return cls(
            request_id=request_id, actor_id=actor_id, action=action, resource=resource,
            scopes=tuple(sorted(set(str(scope) for scope in scopes))), risk=ActionRisk(risk), nonce=nonce,
            issued_at=current.isoformat(), expires_at=(current + timedelta(seconds=lifetime_seconds)).isoformat(),
            context=dict(context or {}), attestation_digest=attestation_digest, policy_digest=policy_digest,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ActionRequest":
        risk = data["risk"]
        if isinstance(risk, str):
            risk_value = ActionRisk[risk.upper()]
        else:
            risk_value = ActionRisk(int(risk))
        return cls(
            request_id=str(data["request_id"]), actor_id=str(data["actor_id"]), action=str(data["action"]),
            resource=str(data["resource"]), scopes=tuple(str(item) for item in data.get("scopes", [])), risk=risk_value,
            nonce=str(data["nonce"]), issued_at=str(data["issued_at"]), expires_at=str(data["expires_at"]),
            context=dict(data.get("context", {})), attestation_digest=data.get("attestation_digest"),
            policy_digest=data.get("policy_digest"), schema_version=str(data.get("schema_version", "qsec.action-request.v1")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version, "request_id": self.request_id, "actor_id": self.actor_id,
            "action": self.action, "resource": self.resource, "scopes": list(self.scopes), "risk": self.risk.name.lower(),
            "nonce": self.nonce, "issued_at": self.issued_at, "expires_at": self.expires_at, "context": self.context,
            "attestation_digest": self.attestation_digest, "policy_digest": self.policy_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()))


@dataclass(frozen=True)
class Approval:
    request_digest: str
    approver_id: str
    approver_role: str
    decision: str
    issued_at: str
    expires_at: str
    key_id: str
    signature: str
    comment: str = ""
    schema_version: str = "qsec.approval.v1"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Approval":
        return cls(
            request_digest=str(data["request_digest"]), approver_id=str(data["approver_id"]),
            approver_role=str(data["approver_role"]), decision=str(data["decision"]).lower(),
            issued_at=str(data["issued_at"]), expires_at=str(data["expires_at"]), key_id=str(data["key_id"]),
            signature=str(data["signature"]).lower(), comment=str(data.get("comment", "")),
            schema_version=str(data.get("schema_version", "qsec.approval.v1")),
        )

    def unsigned_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version, "request_digest": self.request_digest, "approver_id": self.approver_id,
            "approver_role": self.approver_role, "decision": self.decision, "issued_at": self.issued_at,
            "expires_at": self.expires_at, "key_id": self.key_id, "comment": self.comment,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}


class ApprovalSigner:
    def __init__(self, key_id: str, key: bytes):
        if not key_id or len(key) < 16:
            raise ValueError("key_id and a key of at least 16 bytes are required")
        self.key_id = key_id
        self._key = bytes(key)

    def sign(
        self,
        request: ActionRequest,
        approver_id: str,
        approver_role: str,
        decision: str = "approve",
        *,
        comment: str = "",
        lifetime_seconds: int = 120,
        now: Optional[datetime] = None,
    ) -> Approval:
        if decision.lower() not in ("approve", "deny"):
            raise ValueError("decision must be approve or deny")
        current = (now or now_utc()).astimezone(timezone.utc)
        unsigned = Approval(
            request_digest=request.digest, approver_id=approver_id, approver_role=approver_role,
            decision=decision.lower(), issued_at=current.isoformat(),
            expires_at=(current + timedelta(seconds=lifetime_seconds)).isoformat(), key_id=self.key_id,
            signature="", comment=comment,
        )
        signature = hmac.new(self._key, canonical_json(unsigned.unsigned_dict()), hashlib.sha256).hexdigest()
        return replace(unsigned, signature=signature)


@dataclass(frozen=True)
class GovernancePolicy:
    allowed_actors: Tuple[str, ...] = ()
    allowed_actions: Tuple[str, ...] = ()
    allowed_resource_prefixes: Tuple[str, ...] = ()
    allowed_scopes: Tuple[str, ...] = ()
    required_attestation: bool = True
    required_policy_digest: Optional[str] = None
    quorum_low: int = 1
    quorum_medium: int = 1
    quorum_high: int = 2
    quorum_critical: int = 3
    require_distinct_roles_for_high_risk: bool = True
    maximum_request_age_seconds: int = 300
    lease_lifetime_seconds: int = 60
    lease_uses: int = 1

    def quorum_for(self, risk: ActionRisk) -> int:
        return {
            ActionRisk.LOW: self.quorum_low, ActionRisk.MEDIUM: self.quorum_medium,
            ActionRisk.HIGH: self.quorum_high, ActionRisk.CRITICAL: self.quorum_critical,
        }[ActionRisk(risk)]

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json({
            "allowed_actors": list(self.allowed_actors), "allowed_actions": list(self.allowed_actions),
            "allowed_resource_prefixes": list(self.allowed_resource_prefixes), "allowed_scopes": list(self.allowed_scopes),
            "required_attestation": self.required_attestation, "required_policy_digest": self.required_policy_digest,
            "quorum": [self.quorum_low, self.quorum_medium, self.quorum_high, self.quorum_critical],
            "require_distinct_roles_for_high_risk": self.require_distinct_roles_for_high_risk,
            "maximum_request_age_seconds": self.maximum_request_age_seconds,
            "lease_lifetime_seconds": self.lease_lifetime_seconds, "lease_uses": self.lease_uses,
        }))


@dataclass(frozen=True)
class CapabilityLease:
    lease_id: str
    request_digest: str
    actor_id: str
    action: str
    resource: str
    scopes: Tuple[str, ...]
    issued_at: str
    expires_at: str
    remaining_uses: int
    approval_digests: Tuple[str, ...]
    policy_digest: str
    schema_version: str = "qsec.capability-lease.v1"

    def __post_init__(self):
        if self.remaining_uses < 0:
            raise ValueError("remaining_uses cannot be negative")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version, "lease_id": self.lease_id, "request_digest": self.request_digest,
            "actor_id": self.actor_id, "action": self.action, "resource": self.resource, "scopes": list(self.scopes),
            "issued_at": self.issued_at, "expires_at": self.expires_at, "remaining_uses": self.remaining_uses,
            "approval_digests": list(self.approval_digests), "policy_digest": self.policy_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()))

    def consume(self, request: ActionRequest, now: Optional[datetime] = None) -> "CapabilityLease":
        current = (now or now_utc()).astimezone(timezone.utc)
        if current >= parse_time(self.expires_at):
            raise PermissionError("capability lease has expired")
        if self.remaining_uses <= 0:
            raise PermissionError("capability lease has no remaining uses")
        if request.digest != self.request_digest:
            raise PermissionError("capability lease is bound to a different request")
        if (request.actor_id, request.action, request.resource, request.scopes) != (self.actor_id, self.action, self.resource, self.scopes):
            raise PermissionError("capability lease binding mismatch")
        return replace(self, remaining_uses=self.remaining_uses - 1)


@dataclass(frozen=True)
class GovernanceReport:
    authorized: bool
    request_digest: str
    checks: Dict[str, Any]
    findings: Tuple[Finding, ...]
    lease: Optional[CapabilityLease]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authorized": self.authorized, "request_digest": self.request_digest, "checks": self.checks,
            "findings": [item.to_dict() for item in self.findings], "lease": self.lease.to_dict() if self.lease else None,
        }


class ActionGovernor:
    def __init__(self, approval_keys: Mapping[str, bytes], policy: GovernancePolicy):
        self.keys = {str(key_id): bytes(key) for key_id, key in approval_keys.items()}
        if any(len(key) < 16 for key in self.keys.values()):
            raise ValueError("all approval keys must contain at least 16 bytes")
        self.policy = policy

    def authorize(
        self,
        request: ActionRequest,
        approvals: Iterable[Approval],
        *,
        now: Optional[datetime] = None,
        expected_nonce: Optional[str] = None,
        attestation_valid: Optional[bool] = None,
    ) -> GovernanceReport:
        current = (now or now_utc()).astimezone(timezone.utc)
        findings = []
        checks: Dict[str, Any] = {}
        age = (current - parse_time(request.issued_at)).total_seconds()
        expired = current >= parse_time(request.expires_at)
        checks.update({"request_age_seconds": age, "request_expired": expired})
        if age > self.policy.maximum_request_age_seconds or expired:
            findings.append(make_finding("intent_forger", "Context Replay", Severity.HIGH, 0.97, "The action request is stale or expired.", checks.copy()))
        if expected_nonce is not None and request.nonce != expected_nonce:
            findings.append(make_finding("intent_forger", "Context Replay", Severity.CRITICAL, 0.99, "The action request nonce does not match the active challenge.", {"expected": expected_nonce, "actual": request.nonce}, FindingStatus.BREACH))
        if self.policy.allowed_actors and request.actor_id not in self.policy.allowed_actors:
            findings.append(make_finding("intent_forger", "Actor Substitution", Severity.CRITICAL, 0.98, "The actor is not authorized by policy.", {"actor_id": request.actor_id}, FindingStatus.BREACH))
        if self.policy.allowed_actions and request.action not in self.policy.allowed_actions:
            findings.append(make_finding("capability_escalator", "Action Rebinding", Severity.CRITICAL, 0.98, "The requested action is outside policy.", {"action": request.action}, FindingStatus.BREACH))
        if self.policy.allowed_resource_prefixes and not any(request.resource.startswith(prefix) for prefix in self.policy.allowed_resource_prefixes):
            findings.append(make_finding("capability_escalator", "Scope Escalation", Severity.CRITICAL, 0.98, "The requested resource is outside policy.", {"resource": request.resource}, FindingStatus.BREACH))
        unapproved_scopes = sorted(set(request.scopes) - set(self.policy.allowed_scopes)) if self.policy.allowed_scopes else []
        if unapproved_scopes:
            findings.append(make_finding("capability_escalator", "Scope Escalation", Severity.CRITICAL, 0.99, "The request contains scopes not granted by policy.", {"unapproved_scopes": unapproved_scopes}, FindingStatus.BREACH))
        if self.policy.required_attestation and attestation_valid is not True:
            findings.append(make_finding("oracle_mimic", "Backend Impersonation", Severity.CRITICAL, 0.98, "The actor or execution context lacks a valid attestation.", {"attestation_valid": attestation_valid}, FindingStatus.BREACH))
        required_policy_digest = self.policy.required_policy_digest or self.policy.digest
        if request.policy_digest != required_policy_digest:
            findings.append(make_finding("policy_parasite", "Rule Downgrade", Severity.CRITICAL, 0.99, "The request is not bound to the active governance policy.", {"expected": required_policy_digest, "actual": request.policy_digest}, FindingStatus.BREACH))

        valid_approvals = []
        approval_checks = []
        seen_approvers = set()
        invalid_approval = False
        explicit_denial = False
        for approval in approvals:
            key = self.keys.get(approval.key_id)
            signature_valid = False
            if key is not None:
                expected = hmac.new(key, canonical_json(approval.unsigned_dict()), hashlib.sha256).hexdigest()
                signature_valid = hmac.compare_digest(expected, approval.signature)
            row = {
                "approver_id": approval.approver_id, "role": approval.approver_role, "key_id": approval.key_id,
                "signature_valid": signature_valid, "request_match": approval.request_digest == request.digest,
                "expired": current >= parse_time(approval.expires_at), "duplicate": approval.approver_id in seen_approvers,
                "decision": approval.decision,
            }
            seen_approvers.add(approval.approver_id)
            approval_checks.append(row)
            row_valid = signature_valid and row["request_match"] and not row["expired"] and not row["duplicate"] and approval.decision in ("approve", "deny")
            if not row_valid:
                invalid_approval = True
                findings.append(make_finding("consensus_forge", "Approval Forgery", Severity.CRITICAL, 0.99, "An approval is forged, stale, duplicated, or bound to another request.", row, FindingStatus.BREACH))
                continue
            if approval.decision == "deny":
                explicit_denial = True
                findings.append(make_finding("policy_parasite", "Constraint Removal", Severity.CRITICAL, 0.99, "A valid approver denied the requested action.", row, FindingStatus.BREACH))
            else:
                valid_approvals.append(approval)
        checks["approvals"] = approval_checks

        required_quorum = self.policy.quorum_for(request.risk)
        checks["required_quorum"] = required_quorum
        checks["valid_approval_count"] = len(valid_approvals)
        if len(valid_approvals) < required_quorum:
            findings.append(make_finding("consensus_forge", "Quorum Replay", Severity.HIGH, 0.96, "The action does not have the required independent approval quorum.", {"required": required_quorum, "actual": len(valid_approvals)}))
        roles = {item.approver_role for item in valid_approvals}
        if request.risk >= ActionRisk.HIGH and self.policy.require_distinct_roles_for_high_risk and len(roles) < required_quorum:
            findings.append(make_finding("consensus_forge", "Verifier Collusion", Severity.HIGH, 0.95, "High-risk authorization lacks separation of duties.", {"roles": sorted(roles), "required_distinct_roles": required_quorum}))

        ordered = tuple(sorted(findings, key=lambda item: int(item.severity), reverse=True))
        authorized = not invalid_approval and not explicit_denial and not any(item.severity >= Severity.HIGH for item in ordered)
        lease = None
        if authorized:
            expires = min(parse_time(request.expires_at), current + timedelta(seconds=self.policy.lease_lifetime_seconds))
            approval_digests = tuple(sha256_bytes(canonical_json(item.to_dict())) for item in valid_approvals)
            lease_seed = {"request": request.digest, "approvals": approval_digests, "issued_at": current.isoformat(), "policy": required_policy_digest}
            lease = CapabilityLease(
                lease_id=sha256_bytes(canonical_json(lease_seed))[:32], request_digest=request.digest,
                actor_id=request.actor_id, action=request.action, resource=request.resource, scopes=request.scopes,
                issued_at=current.isoformat(), expires_at=expires.isoformat(), remaining_uses=self.policy.lease_uses,
                approval_digests=approval_digests, policy_digest=required_policy_digest,
            )
        return GovernanceReport(authorized, request.digest, checks, ordered, lease)
