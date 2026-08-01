import json
import tempfile
import unittest
from pathlib import Path

from qsec.errors import EvidenceError
from qsec.evidence import EvidenceLedger


class EvidenceTests(unittest.TestCase):
    def test_unkeyed_chain_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            ledger = EvidenceLedger(path)
            first = ledger.append({"event": "baseline"}, timestamp="2026-08-01T00:00:00+00:00")
            second = ledger.append({"event": "inspection"}, timestamp="2026-08-01T00:01:00+00:00")
            report = ledger.verify()
            self.assertTrue(report.valid)
            self.assertEqual(report.records, 2)
            self.assertEqual(second["previous_hash"], first["record_hash"])

    def test_hmac_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            ledger = EvidenceLedger(path, key=b"test-key")
            ledger.append({"event": "baseline"})
            record = json.loads(path.read_text(encoding="utf-8"))
            record["event"]["event"] = "changed"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            report = ledger.verify()
            self.assertFalse(report.valid)
            self.assertIn("record hash mismatch", report.error)

    def test_refuses_append_to_invalid_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            path.write_text("not json\n", encoding="utf-8")
            ledger = EvidenceLedger(path)
            with self.assertRaises(EvidenceError):
                ledger.append({"event": "new"})


if __name__ == "__main__":
    unittest.main()
