import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from qsec.cli import main


class CliTests(unittest.TestCase):
    def test_verify_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps({"kind": "bloch", "values": [0.0, 0.0, 1.0]}), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["verify-state", str(path)])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(output.getvalue())["valid"])

    def test_crypto_audit_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.txt"
            path.write_text("key_exchange=X25519", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["audit-crypto", directory])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.getvalue())["summary"]["quantum_vulnerable_matches"], 1)

    def test_threats_command(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["threats"])
        self.assertEqual(code, 0)
        names = {item["name"] for item in json.loads(output.getvalue())}
        self.assertIn("Phaseworm", names)
        self.assertIn("Shadow Circuit", names)


if __name__ == "__main__":
    unittest.main()
