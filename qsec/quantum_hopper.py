from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol, Sequence

from .quantum_core import (
    NORM_TOLERANCE_SCALED,
    QUANTUM_SCALE,
    QuantumProtocolError,
    QuantumRequest,
    QuantumWitness,
    consensus_digest_for,
)


class QuantumWorker(Protocol):
    @property
    def name(self) -> str:
        ...

    def verify(self, request: QuantumRequest) -> QuantumWitness:
        ...


def _validate_witness(request: QuantumRequest, witness: QuantumWitness) -> None:
    if witness.request_digest != request.digest:
        raise QuantumProtocolError("worker returned a witness for a different request")
    expected = consensus_digest_for(
        witness.request_digest,
        witness.state_digest,
        witness.probability_digest,
        witness.norm_scaled,
        request.qubits,
    )
    if witness.consensus_digest != expected:
        raise QuantumProtocolError("worker returned an internally inconsistent witness")
    if abs(witness.norm_scaled - QUANTUM_SCALE) > NORM_TOLERANCE_SCALED:
        raise QuantumProtocolError("worker returned a non-normalized quantum state")


@dataclass(frozen=True)
class ProcessWorker:
    worker_name: str
    command: tuple[str, ...]
    timeout_seconds: float = 10.0

    @property
    def name(self) -> str:
        return self.worker_name

    def verify(self, request: QuantumRequest) -> QuantumWitness:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        }
        for key in (
            "SYSTEMROOT",
            "WINDIR",
            "PATHEXT",
            "QSA_NATIVE_LIB",
            "QUBIT_NATIVE_LIB",
            "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
        ):
            if key in os.environ:
                environment[key] = os.environ[key]
        completed = subprocess.run(
            self.command,
            input=request.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=self.timeout_seconds,
            env=environment,
            cwd=str(Path.cwd()),
        )
        if completed.returncode != 0:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise QuantumProtocolError(f"{self.name} rejected the request: {error or completed.returncode}")
        witness = QuantumWitness.decode(completed.stdout)
        if witness.backend_id != self.name:
            raise QuantumProtocolError(f"{self.name} returned the wrong backend identity")
        _validate_witness(request, witness)
        return witness


def python_worker() -> ProcessWorker:
    script = Path(__file__).with_name("quantum_worker.py").resolve()
    return ProcessWorker(
        worker_name="python-isolated",
        command=(sys.executable, "-I", "-S", "-B", str(script)),
    )


def native_worker(executable: str | os.PathLike[str]) -> ProcessWorker:
    path = Path(executable).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    return ProcessWorker(worker_name="native-cpp", command=(str(path),))


def qsa_worker() -> ProcessWorker:
    script = Path(__file__).with_name("qsa_worker.py").resolve()
    return ProcessWorker(
        worker_name="qsa-native",
        command=(sys.executable, "-I", "-B", str(script)),
    )


@dataclass(frozen=True)
class MeshReceipt:
    accepted: bool
    request_digest: str
    consensus_digest: str | None
    route: tuple[str, ...]
    witness_digests: tuple[str, ...]
    disagreements: tuple[str, ...]
    failures: tuple[str, ...]
    receipt_digest: str

    @classmethod
    def create(
        cls,
        *,
        accepted: bool,
        request_digest: str,
        consensus_digest: str | None,
        route: Sequence[str],
        witnesses: Sequence[QuantumWitness],
        disagreements: Sequence[str],
        failures: Sequence[str],
    ) -> "MeshReceipt":
        witness_digests = tuple(witness.witness_digest for witness in witnesses)
        fields = [
            "1" if accepted else "0",
            request_digest,
            consensus_digest or "-",
            ",".join(route),
            ",".join(witness_digests),
            ",".join(sorted(disagreements)),
            ",".join(sorted(failures)),
        ]
        receipt_digest = hashlib.sha256("|".join(fields).encode("utf-8")).hexdigest()
        return cls(
            accepted=accepted,
            request_digest=request_digest,
            consensus_digest=consensus_digest,
            route=tuple(route),
            witness_digests=witness_digests,
            disagreements=tuple(disagreements),
            failures=tuple(failures),
            receipt_digest=receipt_digest,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "request_digest": self.request_digest,
            "consensus_digest": self.consensus_digest,
            "route": list(self.route),
            "witness_digests": list(self.witness_digests),
            "disagreements": list(self.disagreements),
            "failures": list(self.failures),
            "receipt_digest": self.receipt_digest,
        }


class QuantumReplayGuard:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS quantum_nonce (
                    nonce TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    consumed_at_ns INTEGER NOT NULL
                )
                """
            )
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def consume(self, request: QuantumRequest) -> None:
        now = time.time_ns()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO quantum_nonce(nonce, request_digest, consumed_at_ns) VALUES (?, ?, ?)",
                    (request.nonce, request.digest, now),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise QuantumProtocolError("quantum request nonce has already been consumed") from exc
            else:
                connection.execute("COMMIT")
        finally:
            connection.close()


class HopperMesh:
    def __init__(
        self,
        workers: Iterable[QuantumWorker],
        *,
        minimum_agreement: int | None = None,
        require_unanimous: bool = True,
        replay_guard: QuantumReplayGuard | None = None,
    ) -> None:
        values = tuple(workers)
        if len(values) < 2:
            raise ValueError("a hopper mesh requires at least two independent workers")
        names = tuple(worker.name for worker in values)
        if len(set(names)) != len(names):
            raise ValueError("worker names must be unique")
        if minimum_agreement is None:
            minimum_agreement = len(values) if require_unanimous else 2
        if minimum_agreement < 2 or minimum_agreement > len(values):
            raise ValueError("minimum_agreement is outside the worker set")
        self.workers = values
        self.minimum_agreement = int(minimum_agreement)
        self.require_unanimous = bool(require_unanimous)
        self.replay_guard = replay_guard

    def verify(self, request: QuantumRequest) -> MeshReceipt:
        if self.replay_guard is not None:
            self.replay_guard.consume(request)
        route = list(self.workers)
        secrets.SystemRandom().shuffle(route)
        witnesses: list[QuantumWitness] = []
        failures: list[str] = []
        for worker in route:
            try:
                witness = worker.verify(request)
                if witness.backend_id != worker.name:
                    raise QuantumProtocolError("worker returned the wrong backend identity")
                _validate_witness(request, witness)
                witnesses.append(witness)
            except (OSError, subprocess.SubprocessError, QuantumProtocolError, ValueError) as exc:
                failures.append(f"{worker.name}:{type(exc).__name__}:{exc}")

        groups: dict[str, list[QuantumWitness]] = {}
        for witness in witnesses:
            groups.setdefault(witness.consensus_digest, []).append(witness)
        ordered = sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
        consensus_digest = ordered[0][0] if ordered else None
        agreement = len(ordered[0][1]) if ordered else 0
        disagreements = [
            f"{witness.backend_id}:{witness.consensus_digest}"
            for witness in witnesses
            if witness.consensus_digest != consensus_digest
        ]
        accepted = agreement >= self.minimum_agreement
        if self.require_unanimous:
            accepted = accepted and not failures and not disagreements and len(witnesses) == len(route)
        return MeshReceipt.create(
            accepted=accepted,
            request_digest=request.digest,
            consensus_digest=consensus_digest if accepted else None,
            route=[worker.name for worker in route],
            witnesses=witnesses,
            disagreements=disagreements,
            failures=failures,
        )
