# QSec Quantum Core

QSec separates quantum verification authority from the application and runtime being inspected. The application does not receive a law-core statevector or a reusable internal handle. It submits a bounded request and receives evidence.

QSec 0.4 has two quantum evidence paths:

- independent full-state cross-code verification for bounded requests;
- structured QSA 0.2 evidence for wider requests where dense reconstruction is not appropriate.

## Cross-Code Operating Rule

No single implementation is allowed to approve its own bounded quantum result.

The default route uses:

- an isolated Python dense-state worker;
- a standalone C++17 dense-state worker with its own parser, gate engine, quantization, and SHA-256 implementation.

Both workers receive the same canonical byte request. QSec accepts only when the required workers independently produce the same phase-sensitive consensus digest. Worker order is randomized for every request. The default policy is unanimous and fails closed on timeout, malformed response, backend failure, replay, or disagreement.

QSA can be added as a third isolated worker. QSA is an execution engine, not QSec's security authority. QSec keeps its own protocol, replay store, routing, comparison, and receipt.

## QSEC-QH/1 Request

The cross-code protocol is ASCII, line ordered, length bounded, and values only. It does not accept Python pickles, classes, callbacks, shared-memory handles, dynamic imports, shell commands, or plugin names.

```text
QSEC-QH/1
request_id=<64 lowercase hex>
nonce=<64 lowercase hex>
policy_digest=<64 lowercase hex or ->
parent_digest=<64 lowercase hex or ->
qubits=<1 through 12>
initial_basis=<basis index>
gate_count=<0 through 4096>
gate=<name>,<first>,<second>,<angle in nanoradians>
END
```

Supported operations are `X`, `Y`, `Z`, `H`, `S`, `T`, `RX`, `RY`, `RZ`, `CNOT`, `CZ`, and `SWAP`. Qubit 0 is the least-significant basis bit, matching QSA.

Angles use signed integer nanoradians and are bounded to plus or minus eight pi radians. This avoids language-specific floating-point text formats in the authenticated request.

## QSEC-QW/1 Witness

Cross-code workers return commitments:

- request digest;
- backend identity;
- phase-sensitive state digest;
- probability digest;
- normalized probability total;
- backend-independent consensus digest.

The witness does not return amplitudes, an internal state object, memory addresses, file handles, or a reusable execution session.

The state commitment includes quantized real and imaginary amplitudes. A relative-phase change therefore changes the witness even when computational-basis probabilities remain identical.

## Hopper Mesh

`HopperMesh` records:

- randomized route order;
- worker witness digests;
- accepted consensus digest;
- worker failures;
- disagreements;
- final mesh receipt digest.

The default route requires every selected worker to agree. A lower quorum can be configured, but disagreement remains in the receipt.

## Replay Control

`QuantumReplayGuard` uses SQLite WAL mode and an atomic unique nonce constraint. A nonce is consumed before verification. Reusing it fails closed even after the original process exits.

The replay database remains a host resource. A deployment that assumes host compromise must move it to a separately measured or hardware-protected boundary.

## QSA 0.2 Evidence

The old QSA adapter enumerated every amplitude and reduced QSA to another dense witness generator. QSec 0.4 preserves that behavior only for requests small enough to participate in the cross-code mesh.

The wider evidence path uses `QSAEvidenceRequest` and `QSAEvidencePolicy`. It allows up to 64 logical qubits while keeping the same identity, nonce, policy, parent, initial-basis, and gate semantics.

The worker executes the request through QSA `OperationPlan` and `QubitRegister`, then records:

- QSA package version;
- native runtime version;
- ABI version;
- compiled operation count;
- native validation result;
- adaptive component structure;
- estimated memory;
- dense complex128 storage equivalent;
- QSC state size and commitment;
- QSC reconstruction evidence;
- exact selected amplitudes;
- all single-qubit `P(1)` marginals.

For requests at or below the 12-qubit full-state threshold, the evidence path also computes the existing phase-sensitive state and probability commitments. This keeps the QSA evidence receipt tied to the same bounded witness semantics used by the mesh.

## Isolated Evidence Worker

`qsa_worker.py` has two modes rather than two separate worker implementations.

Normal mode consumes `QSEC-QH/1` and returns `QSEC-QW/1` for the bounded mesh.

Evidence mode consumes canonical JSON containing a QSA evidence request and policy. The parent process starts it with isolated Python mode and a constrained environment. The result is a self-hashed JSON receipt. The parent verifies the receipt hash and verifies that `request_digest` matches the request it sent.

The worker receives no replay database, hopper route, other worker result, or QSec authorization authority.

## QSA Evidence Policy

The default policy requires QSA package and native versions at least 0.2.0 and ABI at least 1.5.0. It also enforces state-memory and QSC-size limits.

The following conditions fail closed:

- QSA package downgrade;
- QSA native-runtime downgrade;
- ABI downgrade;
- failed native state validation;
- state-memory policy excess;
- QSC-size policy excess;
- failed QSC round-trip equivalence.

A QSA calculation can therefore succeed while QSec rejects the evidence.

## QSC Round Trip

QSec treats QSC as a committed state artifact.

The worker:

1. serializes the executed QSA register;
2. hashes the QSC bytes;
3. reconstructs a new register from those bytes;
4. reruns QSA native validation;
5. repeats exact amplitude probes;
6. repeats all single-qubit marginals;
7. for bounded requests, repeats the full phase-sensitive witness;
8. records the reconstructed QSC digest and whether the bytes were stable.

Byte-for-byte QSC stability is reported but state equivalence is the acceptance gate.

## 50-Qubit Demonstration

The repository contains `examples/qsa50_ghz_request.json`.

```bash
qsec quantum qsa-evidence examples/qsa50_ghz_request.json
```

The dense complex128 equivalent for 50 qubits is 16 PiB. QSec calculates that reference size but reports QSA's actual `estimated_bytes`, QSC size, component structure, and reduction from the live run rather than embedding a presumed value.

The GitHub workflow runs the same command against the pinned QSA 0.2.0 release and preserves the JSON receipt as a build artifact.

## QSA 0.2 Capabilities Not Yet Claimed by QSec

QSA 0.2 also contains exact execution machinery for bounded tensor contraction, causal Pauli propagation, stabilizer execution, phase structure, estimators, gradients, and an exact execution broker that reports selected route and fallback information.

Those capabilities are relevant to QSec, but QSec 0.4 does not claim security evidence for them until their route and resource receipts are explicitly exported and authenticated into QSec.

The next integration target is an exact-query receipt containing:

- selected QSA route;
- structural eligibility proof or certificate;
- fallback reason;
- tensor contraction limits or Pauli-growth statistics;
- exact query result;
- QSA runtime identity;
- QSec request and policy binding.

## Native Law Worker

Build the independent C++ worker:

```bash
python tools/build_native_core.py --output build/qsec-law-core
```

It is built from `native/qsec_law_core.cpp` with a C++17 compiler and no external runtime dependency.

## Commands

Cross-code verification:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core
```

Cross-code verification plus QSA evidence:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core \
  --qsa
```

Structured QSA evidence:

```bash
qsec quantum qsa-evidence examples/qsa50_ghz_request.json
```

Controlled cross-code matrix:

```bash
qsec quantum scenarios --native build/qsec-law-core
```

## Current Boundary

Process isolation prevents ordinary application imports and direct object access. It does not defeat a fully compromised host kernel, equal-privilege debugger, malicious compiler, or hardware-level memory observer. Strong deployments must move the law core, replay state, and evidence roots to independently controlled boundaries when that threat model applies.

The deterministic scenario matrices and QSA evidence run are acceptance evidence. They are not production detection-rate estimates and do not replace real quantum-hardware captures.
