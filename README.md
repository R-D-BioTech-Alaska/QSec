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

**QSec turns execution identity, quantum state, physical validity, authorization, calibration, entropy, and evidence history into security controls that can be independently checked.**

</div>

---

## What QSec Does

QSec is a security and evidence layer for systems where ordinary endpoint security is not enough.

It can currently:

- authenticate software, model, compiler, backend, policy, pulse, and other named artifacts;
- bind an approved quantum request to an exact gate sequence, nonce, policy digest, and parent evidence root;
- verify bounded quantum calculations across independent Python and C++ implementations;
- detect phase changes that leave computational-basis probabilities unchanged;
- prevent replay of accepted quantum requests through a durable nonce database;
- validate statevectors, density matrices, probability vectors, and Bloch vectors;
- inspect calibration drift, reset behavior, readout, detuning, gate error, pulse envelopes, and thermal telemetry;
- verify stabilizer error-correction evidence;
- assess raw entropy-source behavior;
- inventory source trees for post-quantum migration work;
- govern automated actions through narrowly bound capability leases;
- produce chained, deterministic evidence that can be replayed and inspected later;
- use QSA 0.2 as an isolated structured quantum evidence source without giving QSA security authority.

QSec does not replace cryptography, a TPM, an EDR platform, or a quantum runtime. It provides a control plane around them.

## Why QSec Exists

Quantum systems create security surfaces that normal malware scanners do not understand: state preparation, circuit substitution, transpilation, pulse control, calibration, reset, ancilla behavior, measurement, entropy, error correction, remote backends, and the quantum runtime itself.

The software interpreting a physical law can still be replaced. A simulator can lie. A backend can be substituted. A valid-looking state can be the wrong state. A correct calculation can be replayed under the wrong authorization.

QSec therefore separates three things that should not share authority:

1. the application requesting work;
2. the runtime performing the work;
3. the security layer deciding whether the evidence is acceptable.

QSA, Brain, QELM, QZip, Decoder, a cloud backend, or a hardware controller may provide evidence to QSec. They do not inherit QSec policy authority.

## QSec 0.4: Structured Quantum Evidence

QSec 0.3 could use QSA as a third dense-state worker. That was useful for bounded cross-code verification, but it left most of QSA's newer state engine invisible to QSec.

QSec 0.4 changes that relationship.

When QSA evidence is enabled, QSec launches an isolated QSA worker and records a content-addressed receipt of what QSA actually used and what state survived execution. The default policy requires QSA 0.2.0 or newer and ABI 1.5.0 or newer.

The receipt binds:

- the exact QSA evidence request digest;
- QSA package version, native version, and ABI version;
- logical qubit width and gate count;
- operation-plan step count after native compilation;
- QSA native state validation;
- component count and component representation kinds;
- peak component size and nonzero count;
- a deterministic structure digest;
- QSA's estimated state memory;
- the equivalent dense-statevector storage requirement;
- the measured dense-to-QSA storage reduction;
- QSC serialized-state size and SHA-256 commitment;
- QSC decode, native validation, and exact round-trip checks;
- deterministic exact amplitude probes;
- a digest of every single-qubit `P(1)` marginal;
- the full phase-sensitive state and probability commitments when the request is within the 12-qubit cross-code bound;
- the final receipt digest and any fail-closed policy failures.

The QSA worker cannot silently return evidence for another request. QSec validates the receipt framing, hashes the complete receipt body, and verifies that its request digest matches the evidence request that was sent.

### Two verification ranges

QSec deliberately separates two different guarantees.

**Cross-code range, up to 12 qubits:** Python, native C++, and optionally QSA independently produce full phase-sensitive state commitments. QSec can require unanimous agreement.

**Structured QSA evidence range, up to 64 qubits:** QSec does not enumerate `2^n` amplitudes. It records QSA's exact adaptive state structure, QSC state commitment, round-trip equivalence, all single-qubit marginals, deterministic amplitude probes, native validation, and resource use under QSec policy.

Those are different evidence strengths and are reported as such. The wider route is not presented as independent full-state reconstruction.

### Measured 50-qubit result

The repository includes a 50-qubit GHZ request:

```bash
qsec quantum qsa-evidence examples/qsa50_ghz_request.json
```

The QSec validation workflow installed the pinned QSA 0.2.0 release and executed that command on August 10, 2026. The run passed with this receipt data:

| Evidence | Recorded result |
| --- | ---: |
| QSA package / native / ABI | `0.2.0` / `0.2.0` / `1.5.0` |
| Logical qubits | 50 |
| Gates / compiled steps | 50 / 50 |
| Native QSA validation | passed |
| QSA components | 1 sparse component |
| Peak nonzero amplitudes | 2 |
| Estimated QSA state memory | **5,568 bytes** |
| QSC state packet | **333 bytes** |
| Dense complex128 equivalent | **18,014,398,509,481,984 bytes (16 PiB)** |
| Dense-to-QSA state-memory reduction | **3,235,344,559,892x** |
| Single-qubit marginals | `P(1) = 0.5` for all 50 qubits |
| QSC round trip | exact and byte-stable |
| Receipt accepted | yes |

The two GHZ support amplitudes were recorded as approximately `0.7071067812 + 0j`; the other deterministic probe locations were zero. The QSC commitment before and after reconstruction was identical.

The receipt digest for that run is:

```text
af5e0c39d14ef70b64d4b55c40bace31da5dee4d82e493e7d52a176e3414c6f1
```

This is a structured GHZ result, not a claim that arbitrary 50-qubit circuits remain sparse or obtain the same reduction. QSec reports the actual representation and resource evidence for each run.

The workflow uploads the full JSON receipt as the `qsa-0.2-evidence` artifact.

## QSec 0.3: Cross-Code Quantum Core

QSec 0.3 established the independent law-core path that remains part of 0.4.

The default route uses:

- an isolated Python dense-state worker;
- an independent C++17 dense-state worker;
- randomized worker order;
- unanimous phase-sensitive witness comparison;
- a durable SQLite replay guard.

QSA can be added as a third isolated implementation. With QSec 0.4, the same `--qsa` option also requires the QSA structural evidence receipt to pass.

The workers communicate through `QSEC-QH/1`, a strict ASCII values-only protocol. It does not accept pickles, callbacks, shared-memory objects, code strings, shell commands, or plugin loading.

Each cross-code worker independently calculates:

- the authenticated request digest;
- a phase-sensitive state commitment;
- a probability commitment;
- probability normalization;
- a backend-independent consensus digest.

Workers never return the full statevector to the application. A relative-phase mutation is detectable even when computational-basis probabilities are unchanged.

The mesh fails closed on timeout, malformed witness, worker failure, request mismatch, replay, or required-consensus failure.

## Earlier Layers

### QSec 0.1 Foundation

The first layer established:

- quantum-state physical validation;
- exact circuit manifests and SHA-256 circuit identities;
- T1/T2, detuning, readout, reset, gate-error, and measurement-drift checks;
- entropy-source health checks;
- post-quantum migration inventory;
- SHA-256 or HMAC-SHA-256 chained evidence records;
- the initial QSec threat taxonomy.

### QSec 0.2 Trust Mesh

The second layer added:

- authenticated software, model, compiler, backend, policy, and pulse artifacts;
- exact pulse-schedule identity and physical-envelope checks;
- binary-symplectic stabilizer-syndrome verification;
- authenticated approval and exact-bound capability leases for automated actions;
- calibrated first-law thermal telemetry;
- deterministic incident reconstruction and chained evidence roots;
- a 17-case controlled trust-mesh matrix.

QSec does not execute the protected action. It determines whether the requested capability may be issued.

## Installation

Install QSec:

```bash
python -m pip install -e .
```

Build the independent C++ law worker:

```bash
python tools/build_native_core.py --output build/qsec-law-core
```

Install QSA 0.2.0 when QSA evidence is required:

```bash
python -m pip install "qubit-state-algebra @ git+https://github.com/R-D-BioTech-Alaska/QSA.git@v0.2.0"
```

QSA remains an optional dependency. QSec's non-QSA controls do not require it.

## Quantum Verification

Run the independent Python/C++ mesh:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core
```

Add QSA cross-code verification and the QSA 0.2 evidence receipt:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core \
  --qsa
```

Run only the wider QSA evidence path:

```bash
qsec quantum qsa-evidence examples/qsa50_ghz_request.json
```

A custom QSA evidence policy can set minimum versions, ABI, state-memory and QSC limits, full-state threshold, and probe count:

```bash
qsec quantum qsa-evidence request.json --policy qsa-policy.json
```

Run the controlled cross-code matrix:

```bash
qsec quantum scenarios --native build/qsec-law-core
```

Exit code `0` means the active policy passed. Exit code `2` means the command failed closed or produced a high-severity result.

## Other Commands

Inspect a system snapshot:

```bash
qsec inspect examples/current_snapshot.json \
  --baseline examples/baseline_snapshot.json \
  --ledger qsec-ledger.jsonl
```

Verify physical state constraints:

```bash
qsec verify-state examples/statevector.json
```

Compare circuit identity and policy:

```bash
qsec compare-circuit trusted-circuit.json current-circuit.json
```

Audit a source or configuration tree for cryptographic migration:

```bash
qsec audit-crypto path/to/project
```

Assess captured raw entropy:

```bash
qsec entropy entropy-sample.bin
```

Verify an evidence ledger:

```bash
qsec ledger verify qsec-ledger.jsonl
```

Trust-mesh controls:

```bash
qsec attest sign manifest.json --key-id root --key-hex <hex-key> --output signed.json
qsec attest verify signed.json --key-id root --key-hex <hex-key> --artifact runtime.bin=runtime.bin
qsec pulse inspect examples/pulse_current.json --baseline examples/pulse_baseline.json --policy examples/pulse_policy.json
qsec qec verify examples/qec_code.json examples/qec_evidence.json --expected-nonce qec-challenge --minimum-round 3 --expected-previous-digest previous
qsec thermal inspect examples/thermal_telemetry.json --policy examples/thermal_policy.json
qsec scenarios
```

Print the machine-readable threat taxonomy:

```bash
qsec threats
```

## Security Model

QSec separates evidence by trust plane because different failures require different proof.

1. **Identity:** Is this the backend, compiler, runtime, model, worker, or device that was approved?
2. **Authorization:** Is this exact request allowed under this exact policy and parent evidence state?
3. **Execution:** Did the approved circuit, operation sequence, or control schedule execute?
4. **Quantum state:** Is the result physically valid, structurally consistent, and bound to the requested calculation?
5. **Cross-code agreement:** Do independent implementations produce the same phase-sensitive result where independent reconstruction is feasible?
6. **Runtime structure:** Did QSA remain within the representation and resource envelope QSec expected?
7. **Calibration:** Did coherence, detuning, reset, readout, pulse, or gate behavior move outside baseline?
8. **Entropy:** Is a randomness source behaving inside its measured health envelope?
9. **Cryptography:** Which assets still depend on quantum-vulnerable key exchange or signatures?
10. **Evidence:** Can the complete observation history be replayed without silently accepting altered records?

An anomaly is first recorded as a disturbance. Promotion to breach, compromise, or collapse requires stronger evidence and explicit response policy.

## Important Boundaries

- QSec does not invent replacement cryptographic primitives. Standard algorithms still provide signatures, key establishment, and hardware identity.
- QSA provides quantum execution evidence; it does not receive QSec policy authority, replay state, or authorization authority.
- The 12-qubit cross-code path independently reconstructs the bounded state. The wider QSA evidence path does not claim independent reconstruction of an arbitrary 64-qubit state.
- Deterministic amplitude probes are exact checks of selected amplitudes and QSC round-trip behavior. They are not a proof of every unobserved amplitude.
- QSA 0.2 includes broader exact structural systems such as tensor, stabilizer, phase, Pauli, and exact execution-broker routes. QSec 0.4 does not yet claim security receipts for every one of those specialized routes.
- Process isolation blocks ordinary imports and object access. It does not stop a compromised host kernel, malicious compiler, equal-privilege debugger, or hardware memory observer.
- High-risk deployments should place the law core and evidence roots in measured or independently controlled hardware boundaries.
- Entropy checks are online health indicators, not substitutes for a full entropy-source validation program.
- The `T2 <= 2*T1` check is a consistency test for the stated Markovian relaxation model, not a universal law for every experiment.
- A local hash chain or replay database can be replaced by an attacker who controls the host. Important roots must be signed, hardware-sealed, or anchored outside that host.
- Controlled matrices are acceptance tests, not production detection-rate estimates.

## Validation

Run the complete local suite:

```bash
python tools/build_native_core.py --output build/qsec-law-core
QSEC_NATIVE_CORE=build/qsec-law-core python -m compileall -q qsec tests tools
QSEC_NATIVE_CORE=build/qsec-law-core python -m unittest discover -s tests -v
```

Run bounded benchmarks:

```bash
python tools/benchmark_qsec.py
python tools/benchmark_trust_mesh.py
python tools/benchmark_quantum_core.py --native build/qsec-law-core
```

The QSec 0.3 cross-code matrix remains a regression gate for gate insertion, relative-phase injection, target substitution, initial-state substitution, worker disagreement, nonce replay, malformed protocol input, and clean Bell, GHZ, and rotation circuits.

QSec 0.4 adds fail-closed tests for QSA version requirements, ABI requirements, memory policy, structured-width request bounds, QSC round-trip evidence, and preservation of the bounded cross-code state commitments.

## Current QSA Integration Boundary

QSA 0.2 is substantially broader than the old QSec adapter. Its exact runtime can preserve structure through adaptive registers, stabilizer states, phase graphs, sparse Pauli propagation, tensor contractions, reusable estimators, and exact gradients.

QSec 0.4 takes the first security-focused step into that runtime: it records adaptive `QRegister`/`OperationPlan` execution and QSC evidence without forcing a dense statevector.

The next QSA integration should expose QSA's exact execution-route receipt directly to QSec: selected route, structural eligibility, fallback reason, contraction or Pauli bounds, and exact query result. That will allow QSec policy to distinguish "QSA returned a valid answer" from "QSA returned this exact answer through this certified exact route under these resource bounds."

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [QSec 0.2 Trust Mesh](docs/TRUST_MESH.md)
- [QSec 0.3 Cross-Code Quantum Core](docs/QUANTUM_CORE.md)
- [Threat Taxonomy](docs/THREAT_TAXONOMY.md)
- [Security Boundaries](docs/SECURITY_BOUNDARIES.md)
- [Post-Quantum Transition](docs/CRYPTOGRAPHIC_TRANSITION.md)

## Project Direction

The next evidence-bearing layers are:

1. direct QSA exact-route, fallback, tensor-width, and Pauli-growth receipts;
2. hardware-rooted signing and measured-boot receipts;
3. host filesystem, process, memory, network, and persistence containment;
4. captured hardware pulse traces and independently sealed calibration evidence;
5. persistent law-core services with hidden challenge state and one-way capability channels;
6. remote Bell-pair and correlation challenge protocols;
7. fault-injection and error-correction datasets beyond deterministic witnesses;
8. AI memory, training-data, tool-output, and action-result receipts with rollback;
9. adversarial datasets with matched benign variation and sealed false-positive evaluation.

Every layer must report what it detects, what it cannot detect, runtime cost, false-positive cost, and the evidence required before a disturbance is promoted.
