import tempfile
import unittest
from pathlib import Path

from qsec.crypto import scan_path, scan_text, summarize_findings


class CryptoTests(unittest.TestCase):
    def test_detects_vulnerable_and_standardized_algorithms(self):
        findings = scan_text("TLS uses ECDHE with ECDSA. New mode uses ML-KEM-768 and ML-DSA-65.")
        names = {item.algorithm for item in findings}
        self.assertIn("ECDH", names)
        self.assertIn("ECDSA", names)
        self.assertIn("ML-KEM", names)
        self.assertIn("ML-DSA", names)

    def test_harvest_vault_summary(self):
        findings = scan_text("ssh-rsa AAAA and X25519")
        summary = summarize_findings(findings)
        self.assertTrue(summary["harvest_vault_exposure"])
        self.assertEqual(summary["quantum_vulnerable_matches"], 2)

    def test_selected_algorithm_is_not_marked_standardized(self):
        findings = scan_text("HQC-256")
        self.assertEqual(findings[0].status, "selected")
        self.assertEqual(findings[0].standard, "future NIST standard")

    def test_prestandard_alias_is_not_marked_as_fips(self):
        findings = scan_text("Kyber768 and Dilithium3")
        self.assertEqual({item.status for item in findings}, {"pre-standard"})
        self.assertTrue(all("not automatically" in item.standard for item in findings))

    def test_scans_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.txt").write_text("algorithm=RSA-3072\nnext=SLH-DSA", encoding="utf-8")
            findings = scan_path(root)
            self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
