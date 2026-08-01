from __future__ import annotations

from typing import Dict

from .threats import THREATS as BASE_THREATS, ThreatDefinition


THREATS: Dict[str, ThreatDefinition] = dict(BASE_THREATS)
THREATS.update({
    "policy_parasite": ThreatDefinition(
        "QSEC-POLICY-001", "Policy Parasite", "policy",
        "Substitutes, weakens, or bypasses the security policy governing an operation.",
        ("Policy Substitution", "Rule Downgrade", "Constraint Removal"),
        ("policy digest mismatch", "unsigned policy", "unexpected rule relaxation"),
    ),
    "capability_escalator": ThreatDefinition(
        "QSEC-CAP-001", "Capability Escalator", "authorization",
        "Expands a bounded permission into broader action, scope, duration, or reuse.",
        ("Scope Escalation", "Lease Reuse", "Action Rebinding"),
        ("scope mismatch", "expired lease", "use-count overflow", "resource mismatch"),
    ),
    "intent_forger": ThreatDefinition(
        "QSEC-INTENT-001", "Intent Forger", "request and context",
        "Rebinds an approved operation to a different request, actor, resource, or context.",
        ("Request Rebinding", "Context Replay", "Actor Substitution"),
        ("nonce mismatch", "request digest mismatch", "actor mismatch", "stale sequence"),
    ),
    "consensus_forge": ThreatDefinition(
        "QSEC-CONSENSUS-001", "Consensus Forge", "approval and verification",
        "Manufactures or corrupts independent approvals so that a false quorum appears valid.",
        ("Approval Forgery", "Quorum Replay", "Verifier Collusion"),
        ("invalid approval signature", "duplicate approver", "quorum mismatch", "role overlap"),
    ),
})


def get_threat(name: str) -> ThreatDefinition:
    key = name.strip().lower().replace(" ", "_").replace("-", "_")
    if key not in THREATS:
        raise KeyError(f"Unknown QSec threat class: {name}")
    return THREATS[key]
