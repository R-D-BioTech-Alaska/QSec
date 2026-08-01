import unittest
from dataclasses import replace

from qsec.qec import QECPolicy, StabilizerCode, SyndromeEvidence, syndrome_for_error, verify_syndrome_evidence


class QECTests(unittest.TestCase):
    def setUp(self):
        self.code = StabilizerCode("bit-flip", ("ZZI", "IZZ"))
        self.syndrome = syndrome_for_error(self.code.stabilizers, "XII")
        self.evidence = SyndromeEvidence(
            code_digest=self.code.digest, round_index=2, nonce="challenge", measured_syndrome=self.syndrome,
            error_witness="XII", correction_witness="XII", ancilla_syndrome=self.syndrome,
            decoder_votes=(("a", "XII"), ("b", "XII")), previous_round_digest="previous",
        )
        self.policy = QECPolicy(minimum_decoder_votes=2)

    def verify(self, evidence=None, **kwargs):
        defaults = dict(expected_nonce="challenge", minimum_round=2, expected_previous_digest="previous", policy=self.policy)
        defaults.update(kwargs)
        return verify_syndrome_evidence(self.code, evidence or self.evidence, **defaults)

    def test_syndrome_math(self):
        self.assertEqual(self.syndrome, (1, 0))

    def test_noncommuting_stabilizers_rejected(self):
        with self.assertRaises(ValueError):
            StabilizerCode("bad", ("X", "Z"))

    def test_valid_evidence(self):
        self.assertTrue(self.verify().valid)

    def test_injected_syndrome(self):
        self.assertFalse(self.verify(replace(self.evidence, measured_syndrome=(0, 0))).valid)

    def test_ancilla_disagreement(self):
        self.assertFalse(self.verify(replace(self.evidence, ancilla_syndrome=(0, 0))).valid)

    def test_decoder_disagreement(self):
        changed = replace(self.evidence, decoder_votes=(("a", "XII"), ("b", "IIX")))
        self.assertFalse(self.verify(changed).valid)

    def test_replay_links(self):
        self.assertFalse(self.verify(expected_nonce="other").valid)
        self.assertFalse(self.verify(expected_previous_digest="other").valid)


if __name__ == "__main__":
    unittest.main()
