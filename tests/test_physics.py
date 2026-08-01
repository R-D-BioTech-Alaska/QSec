import unittest

from qsec.physics import (
    pure_state_fidelity,
    total_variation_distance,
    validate_bloch_vector,
    validate_density_matrix,
    validate_probabilities,
    validate_readout_matrix,
    validate_relaxation_times,
    validate_statevector,
)


class PhysicsTests(unittest.TestCase):
    def test_valid_statevector(self):
        report = validate_statevector([[2 ** -0.5, 0.0], [2 ** -0.5, 0.0]])
        self.assertTrue(report.valid)
        self.assertAlmostEqual(report.metrics["norm_squared"], 1.0)

    def test_rejects_non_normalized_statevector(self):
        report = validate_statevector([[1.0, 0.0], [1.0, 0.0]])
        self.assertFalse(report.valid)
        self.assertIn("statevector norm is not one", report.violations)

    def test_valid_mixed_density_matrix(self):
        report = validate_density_matrix([[[0.5, 0.0], [0.0, 0.0]], [[0.0, 0.0], [0.5, 0.0]]])
        self.assertTrue(report.valid)
        self.assertAlmostEqual(report.metrics["purity"], 0.5)

    def test_rejects_non_positive_density_matrix(self):
        report = validate_density_matrix([[[1.2, 0.0], [0.0, 0.0]], [[0.0, 0.0], [-0.2, 0.0]]])
        self.assertFalse(report.valid)
        self.assertIn("density matrix is not positive semidefinite", report.violations)

    def test_bloch_vector_must_be_inside_unit_ball(self):
        self.assertTrue(validate_bloch_vector([0.0, 0.0, 1.0]).valid)
        self.assertFalse(validate_bloch_vector([1.0, 1.0, 1.0]).valid)

    def test_relaxation_bound(self):
        self.assertTrue(validate_relaxation_times([100.0], [150.0]).valid)
        self.assertFalse(validate_relaxation_times([100.0], [250.0]).valid)

    def test_readout_matrix_columns_sum_to_one(self):
        self.assertTrue(validate_readout_matrix([[0.98, 0.03], [0.02, 0.97]]).valid)
        self.assertFalse(validate_readout_matrix([[0.98, 0.03], [0.04, 0.97]]).valid)

    def test_probability_vector(self):
        self.assertTrue(validate_probabilities([0.25, 0.75]).valid)
        self.assertFalse(validate_probabilities([0.25, 0.70]).valid)

    def test_state_fidelity_is_global_phase_invariant(self):
        first = [[2 ** -0.5, 0.0], [2 ** -0.5, 0.0]]
        second = [[0.0, 2 ** -0.5], [0.0, 2 ** -0.5]]
        self.assertAlmostEqual(pure_state_fidelity(first, second), 1.0)

    def test_total_variation_distance(self):
        self.assertAlmostEqual(total_variation_distance({"0": 75, "1": 25}, {"0": 25, "1": 75}), 0.5)


if __name__ == "__main__":
    unittest.main()
