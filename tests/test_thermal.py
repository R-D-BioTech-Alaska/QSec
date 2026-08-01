import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from qsec.thermal import ThermalPolicy, ThermalSample, inspect_thermal_telemetry


class ThermalTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 1, tzinfo=timezone.utc)
        self.policy = ThermalPolicy(
            minimum_temperature=3.0, maximum_temperature=6.0, maximum_temperature_rate=0.5,
            maximum_sensor_step=0.5, heat_capacity=10.0, ambient_temperature=4.0,
            maximum_first_law_residual=0.25, maximum_input_power=10.0, maximum_cooling_power=10.0,
        )
        self.samples = (
            ThermalSample(self.now.isoformat(), 4.0, 2.0, 1.0),
            ThermalSample((self.now + timedelta(seconds=1)).isoformat(), 4.1, 2.0, 1.0),
        )

    def test_clean_energy_balance(self):
        report = inspect_thermal_telemetry(self.samples, self.policy)
        self.assertTrue(report.valid)
        self.assertAlmostEqual(report.checks["maximum_absolute_first_law_residual"], 0.0, places=8)

    def test_first_law_mismatch(self):
        changed = (self.samples[0], replace(self.samples[1], temperature=4.5))
        self.assertFalse(inspect_thermal_telemetry(changed, self.policy).valid)

    def test_temperature_envelope(self):
        changed = (self.samples[0], replace(self.samples[1], temperature=7.0))
        self.assertFalse(inspect_thermal_telemetry(changed, self.policy).valid)

    def test_reversed_time(self):
        changed = (self.samples[0], replace(self.samples[1], timestamp=(self.now - timedelta(seconds=1)).isoformat()))
        self.assertFalse(inspect_thermal_telemetry(changed, self.policy).valid)

    def test_power_envelope(self):
        changed = (replace(self.samples[0], input_power=20.0), self.samples[1])
        self.assertFalse(inspect_thermal_telemetry(changed, self.policy).valid)


if __name__ == "__main__":
    unittest.main()
