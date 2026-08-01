import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from qsec.attestation import ArtifactBinding, AttestationManifest, AttestationPolicy, AttestationVerifier, HMACAttestor


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 1, tzinfo=timezone.utc)
        self.key = b"attestation-key-material-32-bytes"
        self.artifact = ArtifactBinding.from_bytes("model.bin", "model", b"trusted-model")
        self.manifest = AttestationManifest.issue(
            "backend-a", "backend", "qsec-root", "nonce-a", 4, (self.artifact,),
            policy_digest="policy-a", parent_digest="parent-a", now=self.now,
        )
        self.signed = HMACAttestor("root", self.key).sign(self.manifest)
        self.verifier = AttestationVerifier(
            {"root": self.key},
            AttestationPolicy(allowed_issuers=("qsec-root",), allowed_subject_kinds=("backend",), require_policy_digest=True, require_parent_digest=True),
        )

    def verify(self, signed=None, **kwargs):
        defaults = dict(
            now=self.now, expected_nonce="nonce-a", expected_subject_id="backend-a", minimum_sequence=4,
            expected_policy_digest="policy-a", expected_parent_digest="parent-a",
            artifact_bytes={"model.bin": b"trusted-model"},
        )
        defaults.update(kwargs)
        return self.verifier.verify(signed or self.signed, **defaults)

    def test_valid_attestation(self):
        self.assertTrue(self.verify().valid)

    def test_forged_signature_fails(self):
        report = self.verify(replace(self.signed, signature="0" * 64))
        self.assertFalse(report.valid)
        self.assertEqual(report.findings[0].threat, "Oracle Mimic")

    def test_artifact_substitution_fails(self):
        report = self.verify(artifact_bytes={"model.bin": b"modified-model"})
        self.assertFalse(report.valid)
        self.assertEqual(report.findings[0].threat, "State Doppelgänger")

    def test_missing_artifact_fails_by_default(self):
        self.assertFalse(self.verify(artifact_bytes={}).valid)

    def test_nonce_replay_fails(self):
        self.assertFalse(self.verify(expected_nonce="nonce-b").valid)

    def test_policy_and_parent_binding_fail(self):
        self.assertFalse(self.verify(expected_policy_digest="other").valid)
        self.assertFalse(self.verify(expected_parent_digest="other").valid)

    def test_expired_attestation_fails(self):
        self.assertFalse(self.verify(now=self.now + timedelta(hours=1)).valid)

    def test_duplicate_artifact_names_rejected(self):
        with self.assertRaises(ValueError):
            replace(self.manifest, artifacts=(self.artifact, self.artifact))


if __name__ == "__main__":
    unittest.main()
