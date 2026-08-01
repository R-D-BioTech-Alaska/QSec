from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from qsec.quantum_cli import command_quantum_verify
from qsec.quantum_core import QuantumGate, QuantumRequest


ROOT = Path(__file__).resolve().parents[1]


class QuantumCliTests(unittest.TestCase):
    def test_cli_cross_code_verification(self) -> None:
        compiler = next((item for item in ("c++", "g++", "clang++") if shutil.which(item)), None)
        if compiler is None:
            self.skipTest("no C++ compiler is available")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / "qsec-law-core"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "build_native_core.py"),
                    "--compiler",
                    compiler,
                    "--output",
                    str(native),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            request = QuantumRequest(
                request_id="a" * 64,
                nonce="b" * 64,
                policy_digest="c" * 64,
                parent_digest="d" * 64,
                qubits=2,
                initial_basis=0,
                gates=(QuantumGate("H", 0), QuantumGate("CNOT", 0, 1)),
            )
            path = root / "request.json"
            path.write_text(json.dumps(request.to_dict()), encoding="utf-8")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import argparse; from qsec.quantum_cli import command_quantum_verify; "
                        f"raise SystemExit(command_quantum_verify(argparse.Namespace(request={str(path)!r}, "
                        f"native={str(native)!r}, qsa=False, replay_db={str(root / 'replay.sqlite3')!r}, "
                        "no_replay_guard=False, minimum_agreement=None, allow_disagreement=False)))"
                    ),
                ],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertTrue(payload["accepted"])
            self.assertEqual(set(payload["route"]), {"python-isolated", "native-cpp"})
