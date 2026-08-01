import argparse
import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from qsec.attestation import AttestationManifest
from qsec.trust_cli import register_trust_subcommands


class TrustCLITests(unittest.TestCase):
    def parser(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command", required=True)
        register_trust_subcommands(sub)
        return parser

    def test_scenarios_command(self):
        args = self.parser().parse_args(["scenarios"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = args.function(args)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["scenario_count"], 17)

    def test_attestation_sign_command(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = AttestationManifest.issue("subject", "backend", "issuer", "nonce", 1, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
            manifest_path = Path(temp) / "manifest.json"
            output_path = Path(temp) / "signed.json"
            manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
            args = self.parser().parse_args([
                "attest", "sign", str(manifest_path), "--key-id", "root",
                "--key-hex", (b"0123456789abcdef0123456789abcdef").hex(), "--output", str(output_path),
            ])
            self.assertEqual(args.function(args), 0)
            data = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(data["key_id"], "root")
            self.assertEqual(len(data["signature"]), 64)

    def test_invalid_short_key(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = AttestationManifest.issue("subject", "backend", "issuer", "nonce", 1, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
            manifest_path = Path(temp) / "manifest.json"
            manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
            args = self.parser().parse_args(["attest", "sign", str(manifest_path), "--key-id", "root", "--key-hex", "00"])
            with self.assertRaises(ValueError):
                args.function(args)


if __name__ == "__main__":
    unittest.main()
