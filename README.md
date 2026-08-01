<p align="center">
  <a href="https://discord.gg/sr9QBj3k36">
    <img src="https://img.shields.io/badge/Discord-Join%20the%20Server-blue?style=for-the-badge" alt="Join our Discord" />
  </a>
</p>

<div align="center">

# QSec

[![QSec Validation](https://github.com/R-D-BioTech-Alaska/QSec/actions/workflows/qsec.yml/badge.svg)](https://github.com/R-D-BioTech-Alaska/QSec/actions/workflows/qsec.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

### Physics-grounded security for classical, quantum, and AI systems

**QSec treats identity, entropy, circuit structure, calibration, measurement, authorization, and state validity as security boundaries that can be measured and verified.**

</div>

---

## Why QSec Exists

Quantum capability creates new security problems and accelerates old ones. Public-key systems must be migrated before stored information becomes vulnerable to future decryption. Quantum workloads also introduce attack surfaces that normal antivirus software does not understand: state preparation, control pulses, calibration, transpilation, reset, ancilla, measurement, error correction, entropy, and remote backends.

A physical law does not protect a system if the program interpreting it can be replaced. QSec therefore separates the protected application, the security policy, and the quantum verification core. The system must prove what code ran, what state transition occurred, what evidence was produced, and whether independent implementations agree.

QSec keeps its own authority, protocol, replay controls, and release gates. QSA can be used as an isolated quantum worker, but QSec does not hand its security authority to QSA, Brain, QELM, QZip, Decoder, or another project.

## QSec 0.1 Foundation

The first layer established the inspection and evidence core:

- quantum-state validation for statevectors, density matrices, probability vectors, and Bloch vectors;
- exact circuit manifests and SHA-256 circuit identities;
- T1/T2, detuning, readout, reset, gate-error, and measurement drift checks;
- entropy-source health checks;
- post-quantum migration inventory;
- SHA-256 or HMAC-SHA-256 chained evidence records;
- the initial QSec threat taxonomy.

## QSec 0.2 Trust Mesh

The second layer added independently verifiable controls around systems ordinary malware scanners cannot inspect:

- authenticated software, model, compiler, backend, policy, and pulse artifacts;
- exact pulse-schedule identity and physical envelope checks;
- binary-symplectic stabilizer syndrome verification;
- governed AI and automated actions using authenticated approvals and exact-bound capability leases;
- calibrated first-law thermal telemetry;
- deterministic incident reconstruction and chained evidence roots;
- a 17-case controlled trust-mesh matrix.

QSec does not execute the protected action. It decides whether a narrowly bound capability lease may be issued.

## QSec 0.3 Cross-Code Quantum Core

QSec 0.3 prevents one codebase from declaring its own quantum result valid.

The default verification route uses:

- an isolated Python dense-state worker;
- an independent C++17 dense-state worker;
- randomized worker order;
- unanimous phase-sensitive witness comparison;
- a durable SQLite replay guard;
- an optional isolated QSA worker.

The workers communicate through `QSEC-QH/1`, a strict ASCII protocol containing values only. It does not accept pickles, callbacks, shared-memory objects, code strings, shell commands, or plugin loading.

Each worker independently calculates:

- the authenticated request digest;
- a phase-sensitive state commitment;
- a probability commitment;
- probability normalization;
- a backend-independent consensus digest.

The workers never return the internal statevector. A relative-phase change is detected even when computational-basis probabilities remain unchanged.

The default mesh fails closed on a timeout, malformed witness, worker failure, request mismatch, or disagreement. QSA can be added as a third worker, but it receives no replay database, policy authority, route information, or other worker result.

## Installation

```bash
python -m pip install -e .
```

Build the independent native law worker:

```bash
python tools/build_native_core.py --output build/qsec-law-core
```

The native worker requires a C++17 compiler. It has no external runtime dependency.

## Command Line

Inspect a current snapshot against a trusted baseline:

```bash
qsec inspect examples/current_snapshot.json \
  --baseline examples/baseline_snapshot.json \
  --ledger qsec-ledger.jsonl
```

Verify a state:

```bash
qsec verify-state examples/statevector.json
```

Compare two circuit manifests:

```bash
qsec compare-circuit trusted-circuit.json current-circuit.json
```

Audit a repository or configuration tree for cryptographic migration work:

```bash
qsec audit-crypto path/to/project
```

Assess a captured raw entropy sample:

```bash
qsec entropy entropy-sample.bin
```

Verify an evidence ledger:

```bash
qsec ledger verify qsec-ledger.jsonl
```

Print the machine-readable threat taxonomy:

```bash
qsec threats
```

Trust-mesh commands:

```bash
qsec attest sign manifest.json --key-id root --key-hex <hex-key> --output signed.json
qsec attest verify signed.json --key-id root --key-hex <hex-key> --artifact runtime.bin=runtime.bin
qsec pulse inspect examples/pulse_current.json --baseline examples/pulse_baseline.json --policy examples/pulse_policy.json
qsec qec verify examples/qec_code.json examples/qec_evidence.json --expected-nonce qec-challenge --minimum-round 3 --expected-previous-digest previous
qsec thermal inspect examples/thermal_telemetry.json --policy examples/thermal_policy.json
qsec scenarios
```

Cross-code quantum verification:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core
```

Add QSA as a third isolated worker:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core \
  --qsa
```

Run the controlled cross-code matrix:

```bash
qsec quantum scenarios --native build/qsec-law-core
```

Exit code `0` means the command passed its active policy. Exit code `2` means it failed closed or produced a high-severity finding.

## Cross-Code Contract

A quantum request binds:

- request identity;
- one-time nonce;
- policy digest;
- parent evidence digest;
- register width;
- initial basis state;
- ordered gate sequence;
- integer nanoradian rotation values.

Supported gates are `X`, `Y`, `Z`, `H`, `S`, `T`, `RX`, `RY`, `RZ`, `CNOT`, `CZ`, and `SWAP`. Qubit 0 is the least-significant basis bit, matching QSA.

No application receives a law-core object or reusable internal handle. The only accepted operation is a bounded verification request. The only returned state information is a cryptographic commitment.

## Security Model

QSec uses separate trust planes because each failure needs different evidence:

1. **Identity:** Is this the backend, compiler, channel, model, worker, or device that was approved?
2. **Entropy:** Is the randomness source behaving inside its measured health envelope?
3. **Execution:** Is the actual circuit or control sequence the one that was authorized?
4. **Physics:** Is the reported state mathematically and physically valid?
5. **Cross-code agreement:** Do independent implementations produce the same phase-sensitive result?
6. **Calibration:** Did coherence, detuning, reset, readout, pulse, or gate behavior move outside baseline?
7. **Cryptography:** Which assets remain exposed to quantum-vulnerable key exchange or signatures?
8. **Authorization:** Is the requested action exactly the action that was approved?
9. **Evidence:** Can the observation history be verified without silently accepting altered records?

An anomaly is first recorded as a disturbance. Promotion to breach, compromise, or collapse requires stronger evidence and an explicit response policy.

## Important Boundaries

- QSec does not invent replacement cryptographic primitives. Standard algorithms still provide signatures, key establishment, and hardware identity.
- The cross-code core prevents one worker from approving itself, but two implementations can still share the same conceptual defect.
- Process isolation blocks ordinary imports and object access. It does not stop a fully compromised host kernel, malicious compiler, debugger with equal privilege, or hardware memory observer.
- High-risk deployments should place the law core in a measured VM, separate machine, TPM-backed appliance, enclave, or other independently controlled boundary.
- QSA is optional. It expands structured-state capacity and provides a third implementation path, but it does not receive QSec policy or security authority.
- Entropy checks are online health indicators, not a substitute for a full entropy-source validation program.
- The `T2 <= 2*T1` check is a model-consistency test for the usual Markovian relaxation model, not a universal law for every non-Markovian experiment.
- A local hash chain or replay database can be replaced by an attacker who controls the entire host. Important roots must be signed, hardware sealed, or anchored outside that host.
- Controlled matrices are acceptance tests, not production detection-rate estimates.

## Validation

Run the suite:

```bash
python tools/build_native_core.py --output build/qsec-law-core
QSEC_NATIVE_CORE=build/qsec-law-core python -m compileall -q qsec tests tools
QSEC_NATIVE_CORE=build/qsec-law-core python -m unittest discover -s tests -v
```

Run all bounded benchmarks:

```bash
python tools/benchmark_qsec.py
python tools/benchmark_trust_mesh.py
python tools/benchmark_quantum_core.py --native build/qsec-law-core
```

The QSec 0.3 matrix contains seven malicious mutations and three clean controls. It covers gate insertion, relative-phase injection, target substitution, initial-state substitution, worker disagreement, nonce replay, malformed protocol input, and clean Bell, GHZ, and rotation circuits.

The benchmark reports Python-worker, native-worker, and unanimous-mesh throughput. Results are workload-specific and are not universal security multipliers.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [QSec 0.2 trust mesh](docs/TRUST_MESH.md)
- [QSec 0.3 cross-code quantum core](docs/QUANTUM_CORE.md)
- [Threat taxonomy](docs/THREAT_TAXONOMY.md)
- [Security boundaries](docs/SECURITY_BOUNDARIES.md)
- [Post-quantum transition](docs/CRYPTOGRAPHIC_TRANSITION.md)

## Project Direction

The next evidence-bearing layers are:

1. hardware-rooted signing and measured-boot receipts;
2. host filesystem, process, memory, network, and persistence containment;
3. captured hardware pulse traces and independently sealed calibration evidence;
4. persistent law-core services with hidden challenge state and one-way capability channels;
5. remote Bell-pair and correlation challenge protocols;
6. fault-injection and error-correction datasets beyond deterministic witnesses;
7. AI memory, training-data, tool-output, and action-result receipts with rollback;
8. adversarial datasets with matched benign variation and sealed false-positive evaluation.

Every layer must report what it detects, what it does not detect, runtime cost, false-positive cost, and the evidence required before a disturbance is promoted.
