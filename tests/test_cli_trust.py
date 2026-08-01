import contextlib
import io
import json
import unittest

from qsec.cli import build_parser


class IntegratedTrustCLITests(unittest.TestCase):
    def test_scenarios_are_registered(self):
        args = build_parser().parse_args(["scenarios"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = args.function(args)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["scenario_count"], 17)


if __name__ == "__main__":
    unittest.main()
