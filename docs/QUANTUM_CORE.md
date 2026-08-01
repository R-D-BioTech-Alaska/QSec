# QSec Cross-Code Quantum Core

QSec 0.3 separates quantum verification authority from the application being inspected. The application does not import the law core, receive its statevector, or provide executable objects. It submits one canonical request and receives a bounded witness.

## Operating Rule

No single codebase is allowed to approve its own quantum result.

The default route uses two independent implementations:

- an isolated Python dense-state worker;
- a standalone C++17 dense-state worker with its own parser, gate engine, quantization, and SHA-256 implementation.

Both workers receive the same canonical byte request. QSec accepts the result only when the workers independently produce the same phase-sensitive consensus digest. Worker order is randomized for every request. The default policy is unanimous and fails closed on a timeout, malformed response, backend failure, or disagreement.

QSA can be added as a third isolated worker. It is an execution engine, not QSec's security authority. QSec keeps its own protocol, replay store, routing, comparison, and evidence receipt.

## QSEC-QH/1 Request

The cross-code protocol is ASCII, line ordered, length bounded, and contains values only. It does not accept Python pickles, classes, callbacks, shared-memory handles, dynamic imports, shell commands, or plugin names.

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

Angles use signed integer nanoradians and are bounded to plus or minus eight pi radians. This avoids language-specific floating-point text formats and unstable argument reduction in the authenticated request.

## QSEC-QW/1 Witness

Workers return only commitments:

- request digest;
- backend identity;
- phase-sensitive state digest;
- probability digest;
- normalized probability total;
- backend-independent consensus digest.

The witness does not return amplitudes, an internal state object, memory addresses, file handles, or a reusable execution session.

The state commitment includes quantized real and imaginary amplitudes. A relative-phase change therefore changes the witness even when computational-basis probabilities remain identical.

## Hopper Mesh

`HopperMesh` randomizes the worker route and records:

- route order;
- each worker witness digest;
- the accepted consensus digest;
- worker failures;
- disagreements;
- a final mesh receipt digest.

The default route requires every selected worker to agree. A lower quorum can be configured, but disagreement is retained in the receipt and should not be ignored for high-risk decisions.

## Replay Control

`QuantumReplayGuard` uses SQLite WAL mode and an atomic unique nonce constraint. A nonce is consumed before verification. Reusing it fails closed even after the original process exits.

The replay database is still a host resource. A deployment that assumes host compromise must place it on a separately measured or hardware-protected system.

## QSA Adapter

The optional QSA adapter uses the stable `QubitRegister` contract:

- chainable gates;
- least-significant-bit qubit ordering;
- exact amplitude queries;
- explicit register ownership and close.

QSA runs in its own process. QSec reconstructs the same witness format from QSA amplitudes and compares it with the other implementations. QSA does not receive the replay database, policy authority, hopper route, or another worker's result.

## Native Build

```bash
python tools/build_native_core.py --output build/qsec-law-core
```

The worker is built from `native/qsec_law_core.cpp` with a C++17 compiler and no external runtime library.

## Verification

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core
```

Add QSA as a third worker when its native library is installed:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core \
  --qsa
```

Run the controlled matrix:

```bash
qsec quantum scenarios --native build/qsec-law-core
```

## Current Boundary

Process isolation prevents ordinary application imports and direct object access. It does not defeat a fully compromised host kernel, debugger with equivalent privilege, malicious compiler, or hardware-level memory observer. Strong deployments must move the law core to a measured VM, separate machine, TPM-backed appliance, enclave, or other independently controlled boundary.

The included matrix is deterministic acceptance evidence. It is not a production detection-rate estimate and does not replace real quantum-hardware captures.
