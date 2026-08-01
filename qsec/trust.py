from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict

from .model import Finding, FindingStatus, Severity
from .threat_catalog import get_threat


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def make_finding(
    threat_name: str,
    technique: str,
    severity: Severity,
    confidence: float,
    summary: str,
    evidence: Dict[str, Any],
    status: FindingStatus = FindingStatus.DISTURBANCE,
) -> Finding:
    threat = get_threat(threat_name)
    return Finding(
        code=threat.code,
        threat=threat.name,
        technique=technique,
        severity=severity,
        confidence=confidence,
        status=status,
        summary=summary,
        evidence=evidence,
    )
