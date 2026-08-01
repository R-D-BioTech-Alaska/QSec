import unittest

from qsec.scenarios import run_controlled_scenarios


class ScenarioTests(unittest.TestCase):
    def test_controlled_matrix(self):
        report = run_controlled_scenarios()
        self.assertEqual(report["scenario_count"], 17)
        self.assertEqual(report["true_positive"], 12)
        self.assertEqual(report["true_negative"], 5)
        self.assertEqual(report["false_positive"], 0)
        self.assertEqual(report["false_negative"], 0)


if __name__ == "__main__":
    unittest.main()
