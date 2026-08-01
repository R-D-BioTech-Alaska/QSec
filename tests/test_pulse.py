import unittest
from dataclasses import replace
from math import pi

from qsec.pulse import PulsePolicy, PulseSchedule, PulseSegment, circular_phase_delta, inspect_pulse_schedule


class PulseTests(unittest.TestCase):
    def setUp(self):
        self.base = PulseSchedule("backend-a", 1e-9, (
            PulseSegment("d0", 0.0, 0.1, 0.2, phase=pi - 1e-7, shape="sampled", samples=(0.0, 0.1, 0.0)),
            PulseSegment("d0", 0.12, 0.1, -0.1, phase=0.0, shape="gaussian"),
        ))
        self.policy = PulsePolicy(
            allowed_channels=("d0",), maximum_absolute_amplitude=0.5, maximum_duration=0.2,
            maximum_schedule_duration=1.0, maximum_duty_cycle=0.95, maximum_slew_rate=10.0,
            maximum_control_energy=1.0, amplitude_tolerance=1e-5, phase_tolerance=1e-5,
        )

    def report(self, segments):
        return inspect_pulse_schedule(PulseSchedule("backend-a", 1e-9, tuple(segments)), self.base, self.policy)

    def test_clean_schedule(self):
        self.assertTrue(inspect_pulse_schedule(self.base, self.base, self.policy).valid)

    def test_amplitude_change(self):
        segments = list(self.base.segments)
        segments[0] = replace(segments[0], amplitude=0.3)
        self.assertFalse(self.report(segments).valid)

    def test_phase_wrap_is_circular(self):
        self.assertLess(circular_phase_delta(pi - 1e-7, -pi + 1e-7), 1e-5)
        segments = list(self.base.segments)
        segments[0] = replace(segments[0], phase=-pi + 1e-7)
        self.assertTrue(self.report(segments).valid)

    def test_extra_segment(self):
        self.assertFalse(self.report(self.base.segments + (PulseSegment("d0", 0.24, 0.05, 0.1),)).valid)

    def test_overlap(self):
        segments = (self.base.segments[0], replace(self.base.segments[1], start=0.05))
        self.assertFalse(self.report(segments).valid)

    def test_slew_limit(self):
        segment = replace(self.base.segments[0], samples=(0.0, 1.0, 0.0))
        report = inspect_pulse_schedule(PulseSchedule("backend-a", 1e-9, (segment,)), None, replace(self.policy, maximum_slew_rate=5.0))
        self.assertFalse(report.valid)

    def test_energy_budget(self):
        report = inspect_pulse_schedule(self.base, None, replace(self.policy, maximum_control_energy=0.0001))
        self.assertFalse(report.valid)


if __name__ == "__main__":
    unittest.main()
