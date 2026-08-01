from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional, Tuple

from .errors import EvidenceError


ZERO_HASH = "0" * 64


@dataclass(frozen=True)
class LedgerVerification:
    valid: bool
    records: int
    last_hash: str
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "records": self.records,
            "last_hash": self.last_hash,
            "error": self.error,
        }


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class EvidenceLedger:
    def __init__(self, path: str | Path, key: Optional[bytes] = None):
        self.path = Path(path)
        self.key = key

    @property
    def algorithm(self) -> str:
        return "hmac-sha256" if self.key is not None else "sha256"

    def _digest(self, payload: bytes) -> str:
        if self.key is None:
            return hashlib.sha256(payload).hexdigest()
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()


    @contextmanager
    def _writer_lock(self):
        lock_path = Path(str(self.path) + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise EvidenceError(f"evidence ledger is already locked: {lock_path}") from exc
        try:
            os.write(descriptor, str(os.getpid()).encode("ascii"))
            os.fsync(descriptor)
            yield
        finally:
            os.close(descriptor)
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass

    def _records(self) -> Iterator[Tuple[int, Dict[str, Any]]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise EvidenceError(f"ledger line {line_number} is not valid JSON") from exc
                if not isinstance(record, dict):
                    raise EvidenceError(f"ledger line {line_number} is not an object")
                yield line_number, record

    def verify(self) -> LedgerVerification:
        previous_hash = ZERO_HASH
        records = 0
        try:
            for line_number, record in self._records():
                records += 1
                claimed_hash = str(record.get("record_hash", ""))
                if record.get("sequence") != records:
                    return LedgerVerification(False, records - 1, previous_hash, f"sequence mismatch at line {line_number}")
                if record.get("previous_hash") != previous_hash:
                    return LedgerVerification(False, records - 1, previous_hash, f"previous hash mismatch at line {line_number}")
                if record.get("algorithm") != self.algorithm:
                    return LedgerVerification(False, records - 1, previous_hash, f"algorithm mismatch at line {line_number}")
                unsigned = dict(record)
                unsigned.pop("record_hash", None)
                expected_hash = self._digest(canonical_json(unsigned))
                if not hmac.compare_digest(claimed_hash, expected_hash):
                    return LedgerVerification(False, records - 1, previous_hash, f"record hash mismatch at line {line_number}")
                previous_hash = claimed_hash
        except EvidenceError as exc:
            return LedgerVerification(False, records, previous_hash, str(exc))
        return LedgerVerification(True, records, previous_hash)

    def append(self, event: Dict[str, Any], timestamp: Optional[str] = None) -> Dict[str, Any]:
        with self._writer_lock():
            verification = self.verify()
            if not verification.valid:
                raise EvidenceError(f"refusing to append to an invalid ledger: {verification.error}")
            record: Dict[str, Any] = {
                "schema": "qsec.evidence.v1",
                "sequence": verification.records + 1,
                "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
                "algorithm": self.algorithm,
                "previous_hash": verification.last_hash,
                "event": event,
            }
            record["record_hash"] = self._digest(canonical_json(record))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            encoded = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
            descriptor = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            try:
                written = os.write(descriptor, encoded)
                if written != len(encoded):
                    raise EvidenceError("evidence record was not written completely")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return record
