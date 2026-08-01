from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .model import FindingStatus, Severity
from .trust import canonical_json, parse_time, sha256_bytes


_STATUS_RANK = {
    FindingStatus.OBSERVATION: 0,
    FindingStatus.DISTURBANCE: 1,
    FindingStatus.BREACH: 2,
    FindingStatus.COMPROMISE: 3,
    FindingStatus.COLLAPSE: 4,
}


@dataclass(frozen=True)
class IncidentEvent:
    event_id: str
    incident_key: str
    timestamp: str
    source: str
    threat: str
    technique: str
    severity: Severity
    status: FindingStatus
    summary: str
    evidence: Dict[str, Any]

    def __post_init__(self):
        if not self.event_id or not self.incident_key or not self.source:
            raise ValueError("event_id, incident_key, and source are required")
        parse_time(self.timestamp)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IncidentEvent":
        severity_raw = data["severity"]
        severity = Severity[severity_raw.upper()] if isinstance(severity_raw, str) else Severity(int(severity_raw))
        status_raw = data["status"]
        status = FindingStatus(status_raw)
        return cls(
            event_id=str(data["event_id"]), incident_key=str(data["incident_key"]), timestamp=str(data["timestamp"]),
            source=str(data["source"]), threat=str(data["threat"]), technique=str(data["technique"]),
            severity=severity, status=status, summary=str(data["summary"]), evidence=dict(data.get("evidence", {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id, "incident_key": self.incident_key, "timestamp": self.timestamp,
            "source": self.source, "threat": self.threat, "technique": self.technique,
            "severity": self.severity.name.lower(), "severity_value": int(self.severity),
            "status": self.status.value, "summary": self.summary, "evidence": self.evidence,
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict()))


@dataclass(frozen=True)
class IncidentPolicy:
    compromise_source_quorum: int = 2
    compromise_minimum_severity: Severity = Severity.HIGH
    maximum_event_gap_seconds: float = 900.0


@dataclass(frozen=True)
class IncidentRecord:
    incident_id: str
    incident_key: str
    status: FindingStatus
    highest_severity: Severity
    sources: Tuple[str, ...]
    threats: Tuple[str, ...]
    first_seen: str
    last_seen: str
    event_digests: Tuple[str, ...]
    timeline: Tuple[Dict[str, Any], ...]
    evidence_root: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id, "incident_key": self.incident_key, "status": self.status.value,
            "highest_severity": self.highest_severity.name.lower(), "highest_severity_value": int(self.highest_severity),
            "sources": list(self.sources), "threats": list(self.threats), "first_seen": self.first_seen,
            "last_seen": self.last_seen, "event_digests": list(self.event_digests),
            "timeline": list(self.timeline), "evidence_root": self.evidence_root,
        }


def _promote_status(events: Tuple[IncidentEvent, ...], policy: IncidentPolicy) -> FindingStatus:
    highest = max((event.status for event in events), key=lambda item: _STATUS_RANK[item])
    if highest == FindingStatus.COLLAPSE:
        return highest
    independent_sources = {event.source for event in events if event.severity >= policy.compromise_minimum_severity}
    confirmed_breach = any(_STATUS_RANK[event.status] >= _STATUS_RANK[FindingStatus.BREACH] for event in events)
    if confirmed_breach and len(independent_sources) >= policy.compromise_source_quorum:
        return FindingStatus.COMPROMISE
    if confirmed_breach:
        return FindingStatus.BREACH
    if any(event.severity >= Severity.HIGH for event in events):
        return FindingStatus.DISTURBANCE
    return highest


def build_incidents(events: Iterable[IncidentEvent], policy: IncidentPolicy = IncidentPolicy()) -> Tuple[IncidentRecord, ...]:
    groups: Dict[str, list[IncidentEvent]] = {}
    seen_event_ids = set()
    for event in events:
        if event.event_id in seen_event_ids:
            continue
        seen_event_ids.add(event.event_id)
        groups.setdefault(event.incident_key, []).append(event)

    records = []
    for incident_key, items in sorted(groups.items()):
        ordered = tuple(sorted(items, key=lambda item: (parse_time(item.timestamp), item.event_id)))
        clusters = []
        current = []
        for event in ordered:
            if current:
                gap = (parse_time(event.timestamp) - parse_time(current[-1].timestamp)).total_seconds()
                if gap > policy.maximum_event_gap_seconds:
                    clusters.append(tuple(current))
                    current = []
            current.append(event)
        if current:
            clusters.append(tuple(current))

        for cluster_index, cluster in enumerate(clusters):
            digests = tuple(event.digest for event in cluster)
            root = "0" * 64
            timeline = []
            for event, digest in zip(cluster, digests):
                root = sha256_bytes(canonical_json({"previous": root, "event": digest}))
                timeline.append({**event.to_dict(), "event_digest": digest, "chain_root": root})
            seed = {"incident_key": incident_key, "cluster": cluster_index, "first_event": digests[0], "last_event": digests[-1]}
            records.append(IncidentRecord(
                incident_id=sha256_bytes(canonical_json(seed))[:32], incident_key=incident_key,
                status=_promote_status(cluster, policy), highest_severity=max(event.severity for event in cluster),
                sources=tuple(sorted({event.source for event in cluster})), threats=tuple(sorted({event.threat for event in cluster})),
                first_seen=cluster[0].timestamp, last_seen=cluster[-1].timestamp, event_digests=digests,
                timeline=tuple(timeline), evidence_root=root,
            ))
    return tuple(records)


def verify_incident(record: IncidentRecord) -> bool:
    root = "0" * 64
    if len(record.timeline) != len(record.event_digests):
        return False
    for row, expected_digest in zip(record.timeline, record.event_digests):
        data = dict(row)
        recorded_digest = data.pop("event_digest", None)
        recorded_root = data.pop("chain_root", None)
        computed_digest = sha256_bytes(canonical_json(data))
        if computed_digest != expected_digest or recorded_digest != expected_digest:
            return False
        root = sha256_bytes(canonical_json({"previous": root, "event": expected_digest}))
        if root != recorded_root:
            return False
    return root == record.evidence_root
