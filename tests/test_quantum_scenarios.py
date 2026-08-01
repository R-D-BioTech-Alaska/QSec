from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from qsec.quantum_scenarios import run_quantum_scenarios, summarize_quantum_scenarios


ROOT = Path(__file__).resolve().parents[1]


class QuantumScenarioTests(unittest.TestCase):
    def test_controlled_quantum_matrix(self) -> None:
        configured = os.environ.get("QSEC_NATIVE_CORE")
        if configured and Path(configured).is_file():
            native = Path(configured)
            context = None
        else:
            compiler = next((item for item in ("c++", "g++", "clang++") if shutil.which(item)), None)
            if compiler is None:
                self.skipTest("no C++ compiler is available")
            context = tempfile.TemporaryDirectory()
            native = Path(context.name) / "qsec-law-core"
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
        try:
            summary = summarize_quantum_scenarios(run_quantum_scenarios(native))
            self.assertTrue(summary["passed"])
            self.assertEqual(summary["true_positive"], 7)
            self.assertEqual(summary["true_negative"], 3)
            self.assertEqual(summary["false_positive"], 0)
            self.assertEqual(summary["false_negative"], 0)
        finally:
            if context is not None:
                context.cleanup()
