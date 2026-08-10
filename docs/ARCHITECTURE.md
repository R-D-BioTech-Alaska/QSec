# QSec Architecture

## Design Rule

QSec separates security authority from the system it observes. A backend, model, compiler, simulator, quantum runtime, or node may provide evidence, but it does not decide whether its own evidence satisfies QSec policy.

This applies to QSA as well. QSA may perform exact quantum work and expose state structure. QSec owns the request binding, policy, replay controls, acceptance decision, and evidence history.

## Trust Planes

### 1. Identity Plane

The identity plane binds an approved object to a fingerprint:

- backend or simulator;
- compiler and transpiler;
- quantum runtime and ABI;
- circuit manifest;
- pulse schedule;
- calibration set;
- model or checkpoint;
- node and channel endpoint.

A mismatch is classified as a disturbance until attestation or operator evidence confirms a stronger event.

### 2. Entropy Plane

The entropy plane observes raw source behavior before a source is trusted for keys, nonces, sampling, randomized compilation, or security challenges.

Current checks include:

- byte distribution;
- sample min-entropy estimate;
- bit balance;
- serial correlation;
- repeated values.

Source-specific startup tests, adaptive-proportion tests, repetition-count tests, conditioning records, and independent-source comparison remain future work.

### 3. Execution Plane

A circuit manifest contains the ordered gate, qubits, parameters, and optional label for every operation. Mutable metadata does not change execution identity.

The exact manifest is checked before broader policy limits. This prevents an allowed gate set from being used to substitute a different approved calculation.

The cross-code protocol adds request identity, a one-time nonce, policy digest, parent evidence digest, register width, initial basis state, and integer-nanoradian rotations.

### 4. Quantum Evidence Plane

QSec uses two verification ranges because the evidence available at small and large widths is different.

#### Bounded cross-code range

For requests up to 12 qubits, independent Python and C++ workers reconstruct the complete state and generate the same phase-sensitive commitment. QSA can be a third isolated worker.

The default mesh requires unanimity and records worker order, witness digests, failures, disagreements, consensus, and a final receipt digest.

#### Structured QSA range

QSec 0.4 adds an isolated QSA 0.2 evidence path for requests up to 64 qubits without enumerating the full statevector.

The QSA evidence request is bound to the same security fields as a normal quantum request but has its own canonical JSON digest. The isolated worker returns:

- QSA package, native, and ABI versions;
- logical width and gate count;
- compiled operation-plan step count;
- native state validation result;
- component count, kinds, sizes, and nonzero counts;
- deterministic structure digest;
- estimated native state memory;
- equivalent dense complex128 storage and reduction ratio;
- QSC serialized-state size and SHA-256 digest;
- QSC decode, revalidation, and round-trip evidence;
- deterministic exact amplitude probes;
- a digest over all single-qubit `P(1)` marginals;
- full state and probability commitments when the request also fits the 12-qubit cross-code range;
- policy failures and a final receipt digest.

The parent process verifies the receipt digest and rejects a receipt whose request digest does not match the request it sent.

The wider receipt is evidence about exact QSA execution and persistence under QSec policy. It is not described as an independent reconstruction of every amplitude.

### 5. Physical State Plane

QSec rejects states that violate basic physical constraints:

- statevectors must have power-of-two dimension and unit norm;
- density matrices must be square, Hermitian, trace one, positive semidefinite, and physically bounded in purity;
- probability vectors must be nonnegative and sum to one;
- Bloch vectors must remain inside the unit ball.

A physically valid state can still be the wrong state. Physical validity, request identity, preparation identity, and cross-code agreement remain separate checks.

### 6. Calibration Plane

Calibration is both operational data and a security surface. QSec compares:

- T1 and T2;
- detuning;
- readout matrices;
- reset excitation;
- gate error rates;
- measurement distributions.

The engine uses both physical validity and baseline drift. A valid calibration can still be poisoned if it moves persistently in a targeted direction.

### 7. Cryptographic Transition Plane

QSec inventories algorithm use rather than inventing replacements. Discovery separates quantum-vulnerable public-key systems, standardized post-quantum algorithms, selected non-final algorithms, and algorithms still in development.

Production migration additionally requires data-lifetime analysis, protocol ownership, dependency mapping, interoperability testing, rollback, and crypto agility.

### 8. Evidence Plane

Evidence records form a canonical chain:

```text
record[n].previous_hash = record[n-1].record_hash
record[n].record_hash = SHA-256(canonical record[n])
```

An optional HMAC key changes the record function to HMAC-SHA-256. QSec verifies the complete chain before appending.

The chain is tamper-evident, not immutable. Strong deployments protect or externally anchor the latest accepted root.

### 9. Response Plane

QSec uses a progression rather than one alarm bit:

```text
observation -> disturbance -> breach -> compromise -> collapse
```

Automated response requires signed policy, bounded authority, reversible actions, and rollback evidence. A detector does not automatically receive destructive authority.

## QSA Authority Boundary

QSA 0.2 contains exact structural execution systems that are substantially broader than the original QSec 0.3 adapter. QSA can preserve work in adaptive registers, stabilizer form, phase structure, sparse Pauli form, bounded tensor contractions, and other exact routes rather than forcing a global dense state.

QSec 0.4 intentionally integrates only the evidence surfaces it can bind cleanly today:

- `QubitRegister` execution;
- `OperationPlan` compilation and execution;
- native register validation;
- component structure and resource measurements;
- exact amplitude and marginal queries;
- QSC persistence and reconstruction.

QSA's exact execution broker already reports route identity and fallback information for its C++ query routes. QSec does not yet claim those broker receipts. A later QSec layer should authenticate and consume selected route, structural eligibility, fallback reason, Pauli growth, tensor contraction limits, and exact query result without weakening QSA's fail-closed exactness rules.

This boundary is deliberate. QSec should not describe an internal QSA capability as security evidence until that capability is actually exported, bound to the request, and checked by QSec policy.

## QSA Evidence Policy

The default QSA evidence policy requires:

```text
QSA package >= 0.2.0
QSA native  >= 0.2.0
QSA ABI     >= 1.5.0
state memory <= 256 MiB
QSC bytes    <= 256 MiB
full-state cross-code commitment <= 12 qubits
amplitude probes = 12
```

Version downgrade, ABI downgrade, native validation failure, state-memory excess, QSC-size excess, or failed QSC round trip fails the evidence receipt closed.

The policy is separate from QSA. A QSA runtime may execute a state successfully while QSec rejects its evidence because the runtime identity or resource envelope is not authorized.

## QSC as Evidence

QSC is treated as a state artifact, not as proof by itself.

QSec hashes the serialized QSC bytes, decodes them through QSA, reruns native validation, repeats the exact probe and marginal checks, and for bounded states repeats the full phase-sensitive commitment. The receipt records both the original and reconstructed QSC digests and whether the byte representation was stable.

Byte-for-byte stability is informative but not required for state equivalence. The round-trip gate is based on reconstructed quantum evidence.

## Physics and Thermodynamics

Physical law is useful when it creates a measurable invariant or budget. It is not a naming convention.

Current invariants include probability conservation, density-matrix positivity, state normalization, Bloch bounds, a T1/T2 consistency check under a stated relaxation model, pulse-control envelopes, stabilizer syndrome consistency, and a calibrated first-law energy balance.

Future thermodynamic controls should consume real telemetry such as device temperature, control-system power, cooling load, reset energy and timing, entropy-source operating conditions, and unexplained heat or power changes correlated with computation.

QSec does not claim that thermodynamics blocks an attack unless the measured boundary supports that conclusion.

## QSec 0.2 Trust Mesh

### Authenticated Identity and Artifact Plane

Attestations bind an issuer, subject, nonce, sequence, lifetime, policy, parent trust state, and named artifact hashes. Required artifacts fail closed when absent. HMAC-SHA-256 is used as a symmetric authenticator; deployments needing public verification should add an approved asymmetric or hardware-rooted signer without weakening the existing binding.

### Pulse-Control Plane

Pulse schedules are compared as ordered physical controls rather than generic files. QSec verifies backend, clock, channel, timing, duration, amplitude, circular phase, frequency, shape, sampled waveform, spectral residual, overlap, duty cycle, slew rate, and a calibrated control-energy proxy.

### Error-Correction Evidence Plane

Stabilizer evidence is verified with binary symplectic algebra. The verifier checks code identity, challenge and round continuity, error-to-syndrome consistency, correction residuals, ancilla agreement, and independent decoder votes.

### Governed Action Plane

Models and automated systems receive no direct execution authority from QSec. Authenticated approvals can issue short-lived, exactly bound, use-limited capability leases. Forged, stale, duplicated, denied, or mismatched approvals block the request even when another subset appears to satisfy quorum.

### Thermodynamic Plane

QSec supports a calibrated lumped first-law model using temperature, input power, cooling power, passive heat flow, and heat capacity. This creates an energy-consistency residual inside a declared sensor model. It does not convert every heat anomaly into an attack finding.

### Incident Plane

Evidence events can be deterministically grouped, ordered, content-digested, and chained into an incident evidence root. Independent sources may promote a confirmed breach to a compromise; collapse remains an explicit state.

## AI Security Boundary

AI protection follows the same architecture:

- immutable signed parent or approved checkpoint;
- exact no-op attachment for new control paths;
- restricted tool and action authority;
- signed input, output, and policy receipts;
- independent execution verification;
- capability changes compared against a frozen baseline;
- rollback that does not depend on the candidate being evaluated.

A model must not be the sole verifier of its own identity, memory, tools, or permitted actions.
