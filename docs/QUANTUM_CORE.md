# QSec Quantum Core

QSec separates quantum verification authority from the application and runtime being inspected. The application does not receive a law-core statevector, QSA internals, or a reusable privileged handle. It submits a bounded request and receives evidence.

QSec 0.5 has four quantum evidence routes:

1. full-state cross-code verification for bounded requests;
2. adaptive QSA structured-state evidence for wider requests;
3. nonce-bound exact Grover capability challenges;
4. nonce-bound exact Hamming-weight symmetry challenges.

The routes deliberately make different claims. QSec does not turn a structured receipt into a full-state proof or a classical exact simulation into a physical-QPU claim.

## Cross-Code Operating Rule

No single implementation is allowed to approve its own bounded quantum result.

The default route uses:

- an isolated Python dense-state worker;
- a standalone C++17 dense-state worker with its own parser, gate engine, quantization, and SHA-256 implementation.

Both workers receive the same canonical request. QSec accepts only when the required workers independently produce the same phase-sensitive consensus digest. Worker order is randomized. The default policy is unanimous and fails closed on timeout, malformed response, backend failure, replay, or disagreement.

QSA can be added as a third isolated worker. QSA is an execution engine, not QSec's security authority. QSec keeps the protocol, replay store, routing, comparison, policies, and final receipt.

## QSEC-QH/1

The bounded cross-code protocol is ASCII, line ordered, length bounded, and values only.

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

Workers return commitments to the request, backend identity, phase-sensitive state, probabilities, normalization, and backend-independent consensus. They do not return internal state objects or reusable execution sessions.

A relative-phase mutation changes the witness even when computational-basis probabilities are unchanged.

## Hopper Mesh and Replay

`HopperMesh` records randomized worker order, worker witness digests, accepted consensus, failures, disagreements, and the final receipt digest.

`QuantumReplayGuard` uses SQLite WAL mode and an atomic unique nonce constraint. The nonce is consumed before verification. Reuse fails closed even after the original process exits.

The replay database remains a host resource. A deployment that assumes host compromise must move replay state and evidence roots to a separately controlled boundary.

## QSA Structured Evidence

The original QSA adapter enumerated every amplitude and therefore reduced QSA to another small dense witness generator. QSec 0.4 added an explicit wider evidence route instead.

`QSAEvidenceRequest` permits up to 64 logical qubits while retaining identity, nonce, policy, parent, initial basis, and gate semantics.

The isolated worker records:

- QSA package, native runtime, and ABI versions;
- compiled operation count;
- QSA native validation;
- adaptive component structure and nonzero counts;
- estimated state memory and dense complex128 equivalent;
- QSC serialized state size and SHA-256 commitment;
- QSC reconstruction and byte-stability evidence;
- deterministic exact amplitude probes;
- every single-qubit `P(1)` marginal.

At or below 12 qubits it also computes the existing full phase-sensitive state and probability commitments.

### QSC round trip

The worker serializes the executed state, hashes the QSC bytes, reconstructs a new QSA register, reruns native validation, repeats exact probes and marginals, and repeats the full witness when the state is inside the bounded cross-code range.

A QSA calculation may therefore succeed while QSec rejects the evidence because of version, validation, resource, QSC, or reconstruction policy.

## QSEC-QSA-GROVER/1

The Grover challenge is a request-bound exact capability receipt around QSA's symmetry-compressed Grover engine.

A request binds:

- `QSEC-QSA-GROVER/1` protocol domain;
- request identity;
- one-time nonce;
- domain-separated policy digest;
- parent evidence digest;
- logical qubit count;
- marked-state count;
- explicit or optimal iteration count.

QSec derives the explicit marked basis states from `SHA-256(request_id || nonce || counter)`. A fixed repository example therefore does not imply a permanently fixed marked target.

The worker runs QSA `GroverSearch` and records:

- QSA package/native/ABI identity;
- logical search size and marked count;
- marked-set commitment;
- marked and unmarked membership probes;
- QSA optimal and executed iteration counts;
- QSA validation;
- estimated engine memory and dense-state equivalent;
- success probability;
- marked and unmarked amplitudes;
- receipt digest and fail-closed result.

The parent does not trust the worker's acceptance bit. It independently re-derives the marked set, chooses the analytic optimum around

```text
pi / (4 theta) - 1/2
```

where

```text
theta = asin(sqrt(M / N))
```

and recomputes

```text
P(success) = sin^2((2k + 1) theta)
```

plus the expected marked and unmarked amplitudes. Request digest, policy, membership probes, memory accounting, receipt digest, and process exit status are also checked.

The request domain is limited to the exact QSA Grover engine boundary of 1 through 62 qubits.

## QSEC-QSA-SYMMETRY/1

The symmetry challenge exercises QSA's exact permutation-invariant Hamming-weight representation.

For `n` qubits, QSA represents the complete logical basis using `n + 1` amplitude classes. Class `k` contains every basis state with exactly `k` set bits.

QSec derives one phase challenge per class from the request identity, nonce, and class index. The worker creates `SymmetryState.hamming_weight(n)`, applies those phases, and returns all class evidence.

QSec independently verifies:

- protocol and policy domains;
- QSA package/native/ABI identity;
- logical state count `2^n`;
- membership mode `hamming_weight`;
- class count `n + 1`;
- every class size `C(n, k)`;
- every expected class amplitude;
- every expected class probability `C(n, k) / 2^n`;
- selected basis-membership probes;
- QSA validation and memory policy;
- phase, request, and receipt digests.

A class mismatch or membership mismatch fails closed even when QSA itself reports a valid state.

The exact Hamming-weight route is limited to the QSA engine boundary of 1 through 62 qubits.

## Measured 0.5 Gate

The GitHub workflow installs the pinned QSA 0.2.0 release and executes three live evidence commands.

### 50-qubit structured state

`examples/qsa50_ghz_request.json`

- QSA estimated state memory: 5,568 bytes
- QSC: 333 bytes
- dense complex128 equivalent: 16 PiB
- measured storage reduction: 3,235,344,559,892x
- QSC reconstruction digest identical to the original digest
- accepted receipt: `af5e0c39d14ef70b64d4b55c40bace31da5dee4d82e493e7d52a176e3414c6f1`

### 60-qubit Grover challenge

`examples/qsa60_grover_request.json`

- logical search space: `2^60 = 1,152,921,504,606,846,976`
- QSA estimated engine memory: 96 bytes
- dense complex128 equivalent: 16 EiB
- measured storage reduction: 192,153,584,101,141,162x
- QSA optimal iterations: 843,314,856
- QSec independent optimal iterations: 843,314,856
- probability error at the `10^-15` receipt scale: 0
- accepted receipt: `3ca12a7f06307b0c15b247aaa0473cfeb4f513c034da6f2cd46c749e17c9b3b5`

### 60-qubit Hamming-weight challenge

`examples/qsa60_symmetry_request.json`

- logical basis space: `2^60`
- exact amplitude classes: 61
- QSA estimated state memory: 1,592 bytes
- dense complex128 equivalent: 16 EiB
- measured storage reduction: 11,587,150,800,068,813x
- maximum class-amplitude error at the `10^-15` receipt scale: 0
- maximum class-probability error at the `10^-15` receipt scale: 0
- accepted receipt: `8576ec4e7d88d31fca0c71cdf2d665ea2ccf381ba1ca91370657c54ff16dfbbd`

The full JSON receipts are preserved by CI as the `qsa-0.2-evidence` artifact.

These are exact classical structural-execution results under the stated QSA contracts. They are not physical-QPU measurements or claims of physical quantum query advantage.

## Isolated QSA Worker

`qsa_worker.py` provides four bounded execution modes through one worker entry point:

- `QSEC-QH/1` cross-code witness mode;
- adaptive structured-evidence mode;
- Grover challenge mode;
- Hamming-weight symmetry challenge mode.

Evidence and challenge modes receive canonical JSON request/policy values. The parent starts the worker using isolated Python mode and a constrained environment.

The worker receives no replay database, hopper route, other worker result, or QSec authorization authority.

## Commands

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core

qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core \
  --qsa

qsec quantum qsa-evidence examples/qsa50_ghz_request.json
qsec quantum qsa-grover examples/qsa60_grover_request.json
qsec quantum qsa-symmetry examples/qsa60_symmetry_request.json
qsec quantum scenarios --native build/qsec-law-core
```

## QSA Capabilities Not Yet Claimed by QSec

QSA 0.2 also contains exact execution machinery for bounded tensor contraction, causal Pauli propagation, stabilizer execution, phase structure, estimators, gradients, and an exact execution broker that reports selected route and fallback information.

QSec does not currently claim authenticated security receipts for those routes. The broker is implemented in QSA's native layer, but QSec should not claim broker-route evidence until the selected route, eligibility proof, fallback reason, resource bound, and exact result are exposed through a callable interface that QSec can bind.

That remains the next major QSA integration target.

## Current Boundary

Process isolation prevents ordinary application imports and direct object access. It does not defeat a fully compromised host kernel, equal-privilege debugger, malicious compiler, or hardware-level memory observer. Strong deployments must move the law core, replay state, and evidence roots to independently controlled boundaries when that threat model applies.

The structured routes also depend on their mathematical representation contracts. Grover two-class symmetry and Hamming-weight symmetry can represent enormous logical spaces exactly because many basis states are known to evolve identically. They are not general compression of arbitrary quantum states.

The deterministic matrices and challenge receipts are acceptance evidence. They are not production detection-rate estimates and do not replace real quantum-hardware captures.
