# QSec Architecture

## Design Rule

QSec separates security authority from the system it observes. A protected backend, model, compiler, simulator, or node may provide telemetry, but it does not decide whether its own telemetry is trustworthy.

The first release is deliberately standalone. Other projects may export QSec-compatible snapshots later, but QSec does not import their authority or persistent state.

## Trust Planes

### 1. Identity Plane

The identity plane binds an approved object to a fingerprint:

- backend or simulator;
- compiler and transpiler;
- circuit manifest;
- pulse schedule;
- calibration set;
- model or checkpoint;
- node and channel endpoint.

A mismatch is classified as an Oracle Mimic or Channel Splice disturbance until attestation or operator evidence confirms a breach.

### 2. Entropy Plane

The entropy plane observes raw source behavior before a source is trusted for keys, nonces, sampling, randomized compilation, or security challenges.

QSec 0.1.0 measures:

- byte distribution;
- sample min-entropy estimate;
- bit balance;
- serial correlation;
- repeated values.

Later versions will add source-specific startup tests, adaptive-proportion tests, repetition-count tests, conditioning-component records, and independent-source comparison.

### 3. Execution Plane

A circuit is encoded as an ordered manifest containing the gate, qubits, parameters, and optional label for every operation. Metadata is not included in the circuit digest because mutable notes must not change execution identity.

The exact manifest is checked before policy limits. This prevents a circuit that stays inside an allow-list from silently replacing the approved computation.

Known compiler outputs should be separately approved by digest. QSec should not make circuit comparison vague merely to suppress benign differences.

### 4. Physical State Plane

QSec rejects states that violate basic physical constraints:

- statevectors must have power-of-two dimension and unit norm;
- density matrices must be square, Hermitian, trace one, positive semidefinite, and physically bounded in purity;
- probability vectors must be nonnegative and sum to one;
- Bloch vectors must remain inside the unit ball.

A physically valid state can still be malicious. Fidelity and preparation identity are separate checks.

### 5. Calibration Plane

Calibration data is both operational data and a security surface. QSec compares:

- T1 and T2;
- detuning;
- readout matrices;
- reset excitation;
- gate error rates;
- measurement distributions.

The engine uses both physical validity and baseline drift. A valid calibration can still be poisoned if it moves persistently in a targeted direction.

### 6. Cryptographic Transition Plane

QSec inventories algorithm use rather than inventing replacements. The inventory separates:

- quantum-vulnerable public-key systems;
- finalized NIST post-quantum standards;
- selected algorithms not yet standardized;
- algorithms still in development.

Discovery is the first step. Production migration also needs data-lifetime analysis, protocol ownership, dependency mapping, interoperability testing, rollback, and crypto agility.

### 7. Evidence Plane

Evidence records form a canonical chain:

```text
record[n].previous_hash = record[n-1].record_hash
record[n].record_hash = SHA-256(canonical record[n])
```

An optional HMAC key changes the record function to HMAC-SHA-256. QSec verifies the complete chain before appending.

The chain is tamper-evident, not magically immutable. Strong deployments protect or externally anchor the latest accepted root.

### 8. Response Plane

QSec uses a progression rather than one alarm bit:

```text
observation -> disturbance -> breach -> compromise -> collapse
```

The 0.1.0 engine emits observations and disturbances. It does not automatically destroy states, revoke infrastructure, or quarantine hosts. Automated response will require signed policy, bounded authority, reversible actions, and rollback evidence.

## Physics and Thermodynamics

Physical law is useful when it creates a measurable invariant or budget. It is not a naming convention.

Current invariants include probability conservation, density-matrix positivity, state normalization, Bloch bounds, and a T1/T2 consistency check under a stated relaxation model.

Future thermodynamic controls should consume real telemetry:

- device temperature;
- control-system power;
- cooling load;
- reset energy and timing;
- entropy-source operating conditions;
- unexplained heat or power changes correlated with computation.

QSec will not claim that thermodynamics blocks an attack unless the measured energy or entropy boundary actually supports that conclusion.

## AI Security Boundary

Future AI protection follows the same architecture:

- immutable signed parent or approved checkpoint;
- exact no-op attachment for new control paths;
- restricted tool and action authority;
- signed input, output, and policy receipts;
- independent execution verification;
- capability changes compared against a frozen baseline;
- rollback that does not depend on the candidate being evaluated.

A model must not be the sole verifier of its own identity, memory, tools, or permitted actions.
