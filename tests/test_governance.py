import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from qsec.governance import ActionGovernor, ActionRequest, ActionRisk, ApprovalSigner, GovernancePolicy


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 1, tzinfo=timezone.utc)
        self.policy = GovernancePolicy(
            allowed_actors=("runtime",), allowed_actions=("model.promote",),
            allowed_resource_prefixes=("model://candidate/",), allowed_scopes=("read", "promote"),
            quorum_high=2, lease_lifetime_seconds=30, lease_uses=1,
        )
        self.request = ActionRequest.issue(
            "r1", "runtime", "model.promote", "model://candidate/7", ("read", "promote"),
            ActionRisk.HIGH, "nonce", policy_digest=self.policy.digest, attestation_digest="attested", now=self.now,
        )
        self.keys = {"a-key": b"approval-key-a-material-32-bytes", "b-key": b"approval-key-b-material-32-bytes"}
        self.approvals = (
            ApprovalSigner("a-key", self.keys["a-key"]).sign(self.request, "alice", "safety", now=self.now),
            ApprovalSigner("b-key", self.keys["b-key"]).sign(self.request, "bob", "operator", now=self.now),
        )
        self.governor = ActionGovernor(self.keys, self.policy)

    def authorize(self, request=None, approvals=None, **kwargs):
        defaults = dict(now=self.now, expected_nonce="nonce", attestation_valid=True)
        defaults.update(kwargs)
        return self.governor.authorize(request or self.request, approvals or self.approvals, **defaults)

    def test_authorized_request_issues_lease(self):
        report = self.authorize()
        self.assertTrue(report.authorized)
        self.assertIsNotNone(report.lease)

    def test_lease_consumption_is_one_time(self):
        lease = self.authorize().lease
        consumed = lease.consume(self.request, now=self.now)
        self.assertEqual(consumed.remaining_uses, 0)
        with self.assertRaises(PermissionError):
            consumed.consume(self.request, now=self.now)

    def test_lease_request_binding(self):
        lease = self.authorize().lease
        changed = replace(self.request, request_id="r2")
        with self.assertRaises(PermissionError):
            lease.consume(changed, now=self.now)

    def test_forged_approval_blocks_quorum(self):
        forged = replace(self.approvals[0], signature="0" * 64)
        self.assertFalse(self.authorize(approvals=(forged, self.approvals[1])).authorized)

    def test_scope_escalation(self):
        request = ActionRequest.issue(
            "r2", "runtime", "model.promote", "model://candidate/7", ("read", "promote", "admin"),
            ActionRisk.HIGH, "nonce", policy_digest=self.policy.digest, attestation_digest="attested", now=self.now,
        )
        approvals = (
            ApprovalSigner("a-key", self.keys["a-key"]).sign(request, "alice", "safety", now=self.now),
            ApprovalSigner("b-key", self.keys["b-key"]).sign(request, "bob", "operator", now=self.now),
        )
        self.assertFalse(self.authorize(request=request, approvals=approvals).authorized)

    def test_attestation_required(self):
        self.assertFalse(self.authorize(attestation_valid=False).authorized)

    def test_separation_of_duties(self):
        approvals = (
            ApprovalSigner("a-key", self.keys["a-key"]).sign(self.request, "alice", "operator", now=self.now),
            ApprovalSigner("b-key", self.keys["b-key"]).sign(self.request, "bob", "operator", now=self.now),
        )
        self.assertFalse(self.authorize(approvals=approvals).authorized)

    def test_explicit_denial_blocks(self):
        denial = ApprovalSigner("a-key", self.keys["a-key"]).sign(self.request, "alice", "safety", decision="deny", now=self.now)
        self.assertFalse(self.authorize(approvals=(denial, self.approvals[1])).authorized)

    def test_expired_request(self):
        self.assertFalse(self.authorize(now=self.now + timedelta(hours=1)).authorized)


if __name__ == "__main__":
    unittest.main()
