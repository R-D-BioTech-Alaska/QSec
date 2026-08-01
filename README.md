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

**QSec treats identity, entropy, circuit structure, calibration, measurement, and state validity as security boundaries that can be measured and verified.**

</div>

---

## Why QSec Exists

Quantum capability creates new security problems and accelerates old ones. Public-key systems must be migrated before stored information becomes vulnerable to future decryption. Quantum workloads also introduce attack surfaces that normal antivirus software does not understand: state preparation, control pulses, calibration, transpilation, reset, ancilla, measurement, error correction, entropy, and remote backends.

A quantum system cannot be secured by telling it not to cross a boundary. The boundary has to be enforced through physical constraints, authenticated execution contracts, measured baselines, cryptographic controls, and evidence that survives inspection.

QSec is a standalone security project. It does not depend on Brain, QELM, QSA, QZip, Decoder, or any other R&D BioTech Alaska project. Adapters may be added later, but QSec keeps its own authority, data contracts, and release gates.

## Current Foundation

QSec 0.1.0 establishes the first working security core:

- **Quantum-state validation**
  - statevector normalization;
  - density-matrix Hermiticity, trace, positivity, and purity bounds;
  - probability conservation;
  - Bloch-vector physical bounds;
  - pure-state fidelity checks.
- **Circuit integrity**
  - canonical circuit manifests;
  - SHA-256 circuit identities;
  - exact gate, qubit, parameter, depth, and topology comparison;
  - gate and resource allow-lists.
- **Calibration and readout monitoring**
  - T1/T2 validation;
  - the Markovian `T2 <= 2*T1` consistency bound;
  - detuning, gate-error, readout-matrix, and reset-residue drift;
  - measurement-distribution comparison with a shot-dependent noise floor.
- **Entropy health**
  - byte Shannon entropy;
  - conservative sample min-entropy estimate;
  - bit bias;
  - serial correlation;
  - repeated-value detection.
- **Post-quantum migration inventory**
  - detection of quantum-vulnerable RSA, finite-field, and elliptic-curve use;
  - recognition of ML-KEM, ML-DSA, and SLH-DSA;
  - separate status for algorithms selected or still under standardization.
- **Tamper-evident evidence**
  - SHA-256 or HMAC-SHA-256 chained JSON records;
  - full-chain verification before every append;
  - deterministic canonical encoding.
- **Professional threat vocabulary**
  - Phaseworm, Shadow Circuit, State Leech, Collapseware, Driftroot, Noisecloak,
    Pulse Parasite, Syndrome Forger, Entanglement Siphon, Oracle Mimic,
    Coherence Eater, State Doppelgänger, Basis Trap, Readout Phantom,
    Reset Ghost, Ancilla Parasite, Channel Splice, Correlation Forge,
    Entropy Leech, and Harvest Vault.

## QSec 0.2 Trust Mesh

The second layer moves QSec from observation into independently verifiable trust controls:

- authenticated software, model, compiler, backend, policy, and pulse artifacts;
- exact pulse-schedule identity plus physical envelope, overlap, duty-cycle, slew, energy, waveform, and spectral checks;
- binary-symplectic stabilizer syndrome verification with error, correction, ancilla, round, and decoder evidence;
- governed AI and automated actions using authenticated approvals, separation of duties, and exact-bound capability leases;
- calibrated first-law thermal telemetry with temperature, power, rate, continuity, and energy-balance checks;
- deterministic incident reconstruction and evidence roots;
- a 17-case controlled attack matrix with 12 malicious mutations and five clean controls.

QSec does not execute model or tool actions. It only decides whether a narrowly bound capability lease may be issued. The current attestation and approval authenticators use HMAC-SHA-256, which provides symmetric integrity and authenticity between parties that already share protected keys; it is not a public signature system.

## Installation

```bash
python -m pip install -e .
```

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

Exit code `0` means the command passed its current policy. Exit code `2` means a policy failure or high-severity finding was produced.

Additional 0.2 commands:

```bash
qsec attest sign manifest.json --key-id root --key-hex <hex-key> --output signed.json
qsec attest verify signed.json --key-id root --key-hex <hex-key> --artifact runtime.bin=runtime.bin
qsec pulse inspect examples/pulse_current.json --baseline examples/pulse_baseline.json --policy examples/pulse_policy.json
qsec qec verify examples/qec_code.json examples/qec_evidence.json --expected-nonce qec-challenge --minimum-round 3 --expected-previous-digest previous
qsec thermal inspect examples/thermal_telemetry.json --policy examples/thermal_policy.json
qsec scenarios
```

The controlled scenario matrix is an acceptance test, not a production detection-rate estimate.

## Security Model

QSec uses separate trust planes because the evidence is different for each failure:

1. **Identity:** Is this the backend, compiler, channel, model, or device that was approved?
2. **Entropy:** Is the randomness source behaving inside its measured health envelope?
3. **Execution:** Is the actual circuit or control sequence the one that was authorized?
4. **Physics:** Is the reported state mathematically and physically valid?
5. **Calibration:** Did coherence, detuning, reset, readout, or gate behavior move outside baseline?
6. **Cryptography:** Which assets remain exposed to quantum-vulnerable key exchange or signatures?
7. **Evidence:** Can the observation history be verified without silently accepting altered records?

An anomaly is initially recorded as a **disturbance**. QSec does not call every deviation an attack. Promotion to breach, compromise, or collapse requires stronger evidence and an explicit response policy.

## Important Boundaries

- QSec does not create new cryptographic primitives. It inventories and controls the use of standardized algorithms.
- Entropy checks are online health indicators, not a substitute for a full entropy-source validation program.
- The `T2 <= 2*T1` check is a model-consistency test for the usual Markovian relaxation model, not a universal law for every non-Markovian experiment.
- Exact circuit comparison can detect benign compiler changes. Production deployments should approve known compiled manifests rather than weakening the comparison.
- A local unkeyed hash chain detects edits relative to its retained root, but an attacker who can rewrite the entire ledger can replace that root. Important roots must be HMAC-protected, signed, or anchored outside the protected host.
- QSec 0.1.0 detects and records. Automated containment, host antivirus, pulse attestation, QEC syndrome verification, remote-channel proofs, and AI action governance are the next implementation layers.

## Validation

Run the focused suite:

```bash
python -m compileall -q qsec tests tools
python -m unittest discover -s tests -v
```

Run the bounded benchmark:

```bash
python tools/benchmark_qsec.py
```

The benchmark reports entropy-analysis throughput, exact circuit-comparison throughput, and evidence-ledger append/verification throughput. Results are workload-specific and are not universal security multipliers.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [QSec 0.2 trust mesh](docs/TRUST_MESH.md)
- [Threat taxonomy](docs/THREAT_TAXONOMY.md)
- [Security boundaries](docs/SECURITY_BOUNDARIES.md)
- [Post-quantum transition](docs/CRYPTOGRAPHIC_TRANSITION.md)

## Project Direction

The next evidence-bearing layers are:

1. asymmetric and hardware-rooted attestation adapters without replacing the HMAC trust domain;
2. host filesystem, process, memory, network, and conventional malware containment;
3. captured hardware pulse traces and independently sealed calibration evidence;
4. fault-injection and error-correction datasets beyond deterministic stabilizer witnesses;
5. remote-channel, temporary-node, Bell-pair, and correlation challenge protocols;
6. AI memory, training-data, tool-output, and action-result receipts with rollback;
7. independent hardware entropy and multi-sensor thermodynamic telemetry;
8. adversarial datasets with matched benign variation and sealed false-positive evaluation.

Every layer must report what it detects, what it does not detect, runtime cost, false-positive cost, and the evidence needed before a disturbance is promoted.
