import hashlib
import unittest

from qsec.entropy import EntropyPolicy, approximate_monobit_z_score, assess_entropy


def deterministic_entropy(blocks=256):
    return b"".join(hashlib.sha256(index.to_bytes(8, "big")).digest() for index in range(blocks))


class EntropyTests(unittest.TestCase):
    def test_healthy_deterministic_sample(self):
        report = assess_entropy(deterministic_entropy())
        self.assertTrue(report.healthy, report.violations)
        self.assertGreater(report.min_entropy_per_byte, 6.0)

    def test_rejects_repeated_sample(self):
        report = assess_entropy(b"\x00" * 4096)
        self.assertFalse(report.healthy)
        self.assertIn("estimated min-entropy is below policy", report.violations)
        self.assertIn("repeated-byte run is outside policy", report.violations)

    def test_rejects_short_sample(self):
        report = assess_entropy(deterministic_entropy(2))
        self.assertFalse(report.healthy)
        self.assertTrue(any("fewer than" in item for item in report.violations))

    def test_monobit_score_is_finite(self):
        score = approximate_monobit_z_score(deterministic_entropy())
        self.assertLess(abs(score), 8.0)

    def test_policy_can_be_tightened(self):
        report = assess_entropy(deterministic_entropy(), EntropyPolicy(maximum_bit_bias=0.0))
        self.assertFalse(report.healthy)


if __name__ == "__main__":
    unittest.main()
