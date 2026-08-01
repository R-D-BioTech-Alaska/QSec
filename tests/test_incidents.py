import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from qsec.incidents import IncidentEvent, IncidentPolicy, build_incidents, verify_incident
from qsec.model import FindingStatus, Severity


class IncidentTests(unittest.TestCase):
    def setUp(self):
        now = datetime(2026, 8, 1, tzinfo=timezone.utc)
        self.events = (
            IncidentEvent("e1", "backend-a", now.isoformat(), "pulse-monitor", "Pulse Parasite", "Pulse Tampering", Severity.CRITICAL, FindingStatus.BREACH, "Pulse digest failed.", {"digest": "a"}),
            IncidentEvent("e2", "backend-a", (now + timedelta(seconds=1)).isoformat(), "thermal-monitor", "Coherence Eater", "Thermal Loading", Severity.HIGH, FindingStatus.DISTURBANCE, "Energy balance failed.", {"residual": 2.0}),
        )

    def test_build_and_verify_incident(self):
        records = build_incidents(self.events)
        self.assertEqual(len(records), 1)
        self.assertTrue(verify_incident(records[0]))

    def test_independent_sources_promote_compromise(self):
        record = build_incidents(self.events)[0]
        self.assertEqual(record.status, FindingStatus.COMPROMISE)

    def test_tampered_incident_fails(self):
        record = build_incidents(self.events)[0]
        row = dict(record.timeline[0])
        row["summary"] = "changed"
        tampered = replace(record, timeline=(row,) + record.timeline[1:])
        self.assertFalse(verify_incident(tampered))

    def test_large_gap_splits_incident(self):
        late = replace(self.events[1], timestamp=(datetime.fromisoformat(self.events[0].timestamp) + timedelta(hours=1)).isoformat())
        records = build_incidents((self.events[0], late), IncidentPolicy(maximum_event_gap_seconds=60))
        self.assertEqual(len(records), 2)

    def test_duplicate_event_ids_are_deduplicated(self):
        records = build_incidents((self.events[0], self.events[0]))
        self.assertEqual(len(records[0].event_digests), 1)


if __name__ == "__main__":
    unittest.main()
