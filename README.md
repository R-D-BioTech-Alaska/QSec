<p align="center">
  <a href="https://discord.gg/sr9QBj3k36">
    <img src="https://img.shields.io/badge/Discord-Join%20the%20Server-blue?style=for-the-badge" alt="Join the QSec Discord server" />
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

## What QSec Can Prove Today

QSec is a security and evidence layer for systems where ordinary endpoint security is not enough. It separates the application requesting work, the runtime performing it, and the security layer deciding whether the resulting evidence is acceptable.

Current acceptance paths include:

| Capability | Current evidence |
| --- | --- |
| Independent quantum-law verification | Isolated Python and standalone C++17 workers independently reconstruct bounded states and must agree on a phase-sensitive commitment. |
| Replay-resistant quantum requests | One-time nonces are consumed through a durable SQLite replay guard before verification. |
| Structured QSA state evidence | QSA 0.2 execution is isolated and bound to package/native/ABI identity, adaptive state structure, memory, QSC state commitment, exact probes, marginals, and validation. |
| Nonce-bound Grover challenge | QSec derives the marked state, QSA executes the exact symmetry-compressed search, and QSec independently recomputes the analytic result and optimal iteration count. |
| Nonce-bound symmetry challenge | QSec derives an independent phase challenge across every Hamming-weight class and verifies QSA class sizes, amplitudes, probabilities, and selected basis membership. |
| Artifact and runtime trust | Software, model, compiler, backend, policy, pulse, and other named artifacts can be authenticated and bound to policy. |
| Physical telemetry | Calibration, reset, readout, detuning, gate error, pulse envelopes, thermal telemetry, entropy, and stabilizer evidence can be checked against explicit policy. |
| Governed automation | Approved automated actions can be restricted through narrowly bound capability leases and deterministic evidence chains. |
| Post-quantum migration | Source and configuration trees can be inventoried for quantum-vulnerable cryptographic dependencies. |

QSec does not replace cryptography, a TPM, an EDR platform, a QPU, or a quantum runtime. It provides an independently checkable control plane around them.

## Measured QSA 0.2 Evidence

These are live GitHub Actions results from the pinned QSA 0.2.0 release, not estimated capability claims.

| Demonstration | Logical space | QSA evidence/state memory | Dense complex128 equivalent | Measured reduction | Independent QSec check |
| --- | ---: | ---: | ---: | ---: | --- |
| 50-qubit GHZ structured state | `2^50` | **5,568 B** | **16 PiB** | **3,235,344,559,892x** | QSC round trip, all marginals, exact probes, native validation |
| 60-qubit Grover challenge | `2^60` | **96 B** | **16 EiB** | **192,153,584,101,141,162x** | optimal iterations, success probability, class amplitudes, membership probes |
| 60-qubit Hamming-weight challenge | `2^60` | **1,592 B** | **16 EiB** | **11,587,150,800,068,813x** | all 61 class sizes, amplitudes, probabilities, and selected basis membership |

The 60-qubit Grover challenge independently produced **843,314,856 optimal iterations** in both QSA and QSec. The success probability and marked/unmarked amplitudes agreed at QSec's `10^-15` receipt scale with zero recorded probability error.

The 60-qubit Hamming-weight challenge retained **61 exact amplitude classes**. QSec independently checked every class against `C(60, k)`, regenerated every nonce-derived phase, recomputed every expected class amplitude and probability, and recorded zero maximum amplitude or probability error at the `10^-15` receipt scale.

The corresponding accepted receipt digests are:

```text
50-qubit structured state:  af5e0c39d14ef70b64d4b55c40bace31da5dee4d82e493e7d52a176e3414c6f1
60-qubit Grover challenge:  3ca12a7f06307b0c15b247aaa0473cfeb4f513c034da6f2cd46c749e17c9b3b5
60-qubit symmetry challenge:8576ec4e7d88d31fca0c71cdf2d665ea2ccf381ba1ca91370657c54ff16dfbbd
```

The workflow uploads the complete JSON receipts as the `qsa-0.2-evidence` artifact.

These results demonstrate exact classical structural execution under the stated QSA representation contracts. They are **not** claims of physical quantum hardware, quantum supremacy, or physical Grover query advantage.

## QSec 0.5: Quantum Capability Challenges

QSec 0.5 adds challenge-response evidence around QSA's stronger exact structured engines. The important change is not that QSec trusts QSA more. It is that QSec now asks QSA questions whose answers can be independently derived and checked.

### Grover challenge

A `QSEC-QSA-GROVER/1` request binds:

- request identity;
- one-time nonce;
- QSec policy digest;
- parent evidence digest;
- logical qubit count;
- marked-state count;
- explicit or optimal iteration count.

The marked basis states are derived from the request identity and nonce. QSA therefore does not receive a permanently fixed benchmark target.

The isolated QSA worker returns a self-hashed receipt containing QSA package/native/ABI identity, logical search size, marked-state commitment, iteration count, memory use, success probability, marked/unmarked amplitudes, and membership probes.

QSec then independently:

1. re-derives the nonce-bound marked states;
2. recomputes the optimal Grover iteration count;
3. recomputes the expected success probability;
4. recomputes marked and unmarked amplitudes;
5. verifies membership probes and memory accounting;
6. verifies the receipt digest, request digest, policy, version gates, and worker exit status.

A self-reported `accepted=true` from the worker is not sufficient.

### Hamming-weight symmetry challenge

A `QSEC-QSA-SYMMETRY/1` request creates a different phase challenge for every Hamming-weight class from the request identity and nonce.

For 60 qubits that means 61 independently challenged classes spanning the complete `2^60` logical basis space. QSec verifies:

- membership mode is exactly `hamming_weight`;
- class count is exactly `n + 1`;
- every class size equals the independent binomial coefficient `C(n, k)`;
- every challenged class amplitude matches QSec's independent complex reference;
- every class probability matches `C(n, k) / 2^n`;
- selected basis states resolve to the expected Hamming-weight amplitude;
- QSA validation and memory policy pass;
- request, policy, phase, and receipt digests remain bound.

Grover and symmetry requests use distinct protocol and policy hash domains. Both consume their nonces through QSec's existing durable replay control.

## QSec 0.4: Structured Quantum Evidence

QSec 0.4 expanded the QSA integration beyond a small dense-state adapter.

For structured QSA evidence, the worker records:

- exact QSA evidence request digest;
- package, native runtime, and ABI versions;
- logical width, gate count, and compiled operation count;
- QSA native state validation;
- adaptive component representation and nonzero counts;
- deterministic structure digest;
- estimated state memory and dense-state equivalent;
- QSC serialized-state size and SHA-256 commitment;
- QSC reconstruction, validation, equivalence, and byte-stability evidence;
- deterministic exact amplitude probes;
- every single-qubit `P(1)` marginal commitment;
- full phase-sensitive state and probability commitments when the request is inside the 12-qubit cross-code bound;
- final receipt digest and fail-closed policy results.

### Two evidence ranges

**Cross-code range, up to 12 qubits:** Python, standalone C++, and optionally QSA independently reconstruct the full bounded state. QSec can require unanimous phase-sensitive agreement.

**Structured QSA evidence range, up to 64 qubits:** QSec does not enumerate `2^n` amplitudes. It records QSA's exact adaptive representation, QSC commitment and round trip, all single-qubit marginals, deterministic probes, validation, and resource use.

The guarantees are different and QSec reports them separately.

## QSec 0.3: Independent Cross-Code Law Core

No single implementation is allowed to approve its own bounded quantum result.

The default cross-code path uses:

- an isolated Python dense-state worker;
- an independent C++17 law worker with its own parser, gate engine, quantization, and SHA-256 implementation;
- randomized worker order;
- unanimous phase-sensitive witness comparison;
- a durable SQLite replay guard.

QSA can be added as a third isolated implementation. It receives no replay database, route information, other worker results, or QSec policy authority.

Workers communicate through `QSEC-QH/1`, a strict ASCII values-only protocol. It does not accept pickles, callbacks, shared-memory objects, code strings, shell commands, or plugin loading.

A relative-phase mutation changes the state witness even when computational-basis probabilities remain unchanged.

## Earlier Security Layers

QSec 0.1 and 0.2 established controls that remain active in 0.5:

- physical validation for statevectors, density matrices, probability vectors, and Bloch vectors;
- exact circuit manifests and SHA-256 identities;
- T1/T2, detuning, readout, reset, gate-error, and measurement-drift checks;
- entropy-source health checks;
- post-quantum migration inventory;
- chained SHA-256 or HMAC-SHA-256 evidence;
- authenticated software, model, compiler, backend, policy, and pulse artifacts;
- exact pulse-schedule identity and physical-envelope checks;
- binary-symplectic stabilizer-syndrome verification;
- authenticated approval and exactly bound capability leases;
- calibrated first-law thermal telemetry;
- deterministic incident reconstruction and chained evidence roots.

QSec does not execute the protected action. It decides whether the evidence is sufficient for a narrowly bound capability to be issued.

## Installation

Install QSec:

```bash
python -m pip install -e .
```

Build the independent native law worker:

```bash
python tools/build_native_core.py --output build/qsec-law-core
```

Install QSA 0.2.0 when QSA evidence is required:

```bash
python -m pip install "qubit-state-algebra @ git+https://github.com/R-D-BioTech-Alaska/QSA.git@v0.2.0"
```

QSA remains optional. QSec's non-QSA controls do not require it.

## Quantum Commands

Independent Python/C++ verification:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core
```

Add QSA cross-code and structured evidence:

```bash
qsec quantum verify examples/quantum_request.json \
  --native build/qsec-law-core \
  --qsa
```

Run the 50-qubit structured-state evidence path:

```bash
qsec quantum qsa-evidence examples/qsa50_ghz_request.json
```

Run the 60-qubit nonce-bound Grover challenge:

```bash
qsec quantum qsa-grover examples/qsa60_grover_request.json
```

Run the 60-qubit nonce-bound Hamming-weight challenge:

```bash
qsec quantum qsa-symmetry examples/qsa60_symmetry_request.json
```

Run the controlled cross-code matrix:

```bash
qsec quantum scenarios --native build/qsec-law-core
```

Exit code `0` means the active policy passed. Exit code `2` means the command failed closed or produced a high-severity result.

## Other Commands

```bash
qsec inspect examples/current_snapshot.json --baseline examples/baseline_snapshot.json --ledger qsec-ledger.jsonl
qsec verify-state examples/statevector.json
qsec compare-circuit trusted-circuit.json current-circuit.json
qsec audit-crypto path/to/project
qsec entropy entropy-sample.bin
qsec ledger verify qsec-ledger.jsonl
qsec threats
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

## Security Model

QSec separates evidence by trust plane because different failures require different proof.

1. **Identity:** Is this the runtime, backend, compiler, model, worker, or device that was approved?
2. **Authorization:** Is this exact request allowed under this policy and parent evidence state?
3. **Execution:** Did the approved circuit, operation sequence, or control schedule execute?
4. **Quantum state:** Is the result physically valid and bound to the requested calculation?
5. **Independent agreement:** Do separate implementations produce the same phase-sensitive result where full reconstruction is feasible?
6. **Structured execution:** Did the runtime remain inside an exact representation contract whose result QSec can independently challenge?
7. **Calibration:** Did coherence, detuning, reset, readout, pulse, or gate behavior move outside baseline?
8. **Entropy:** Is the randomness source behaving inside its measured health envelope?
9. **Cryptography:** Which assets still depend on quantum-vulnerable key exchange or signatures?
10. **Evidence:** Can the observation history be verified without silently accepting altered records?

An anomaly is first recorded as a disturbance. Promotion to breach, compromise, or collapse requires stronger evidence and explicit response policy.

## Important Boundaries

- QSec does not invent replacement cryptographic primitives. Standard algorithms still provide signatures, key establishment, and hardware identity.
- QSA provides execution evidence. It does not receive QSec policy, replay, or authorization authority.
- The 12-qubit cross-code path independently reconstructs bounded states. The wider structured route does not claim independent reconstruction of arbitrary 64-qubit states.
- The Grover and Hamming-weight challenge routes are exact only inside their stated structural contracts. They do not compress arbitrary quantum states.
- The 60-qubit demonstrations are exact classical simulations. They are not physical-QPU results or claims of hardware quantum advantage.
- Process isolation blocks ordinary imports and object access. It does not defeat a compromised host kernel, equal-privilege debugger, malicious compiler, or hardware memory observer.
- A local replay database or hash chain can be replaced by an attacker who controls the host. Strong deployments must anchor important state outside that host.
- Entropy checks are online health indicators, not substitutes for a full entropy-source validation program.
- The `T2 <= 2*T1` check is a consistency test for the stated Markovian relaxation model, not a universal law for every experiment.
- Controlled matrices are acceptance tests, not production detection-rate estimates.

## Validation

Run the local suite:

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

GitHub Actions validates Python 3.10, 3.11, and 3.12, rebuilds the standalone C++ law core, runs the regression and benchmark gates, installs the pinned QSA 0.2.0 release, and executes all three QSA evidence demonstrations.

QSec 0.5 includes fail-closed tests for nonce variation, policy mismatch, package/native/ABI downgrade, resource limits, incorrect Grover probability, incorrect class amplitudes, challenge shape, membership, and QSA's documented structured-engine width boundaries.

## QSA Integration Frontier

QSA 0.2 is broader than the surfaces QSec currently authenticates. It includes adaptive registers, exact symmetry algebra, stabilizer execution, phase structure, bounded tensor contraction, causal Pauli propagation, estimators, gradients, and an exact execution broker.

QSec 0.5 now has explicit security receipts for adaptive structured-state evidence, exact two-class Grover search, and exact Hamming-weight symmetry.

The next high-value integration is QSA's exact execution broker once its route receipt is exposed through a callable interface. QSec should then bind selected route, structural eligibility, fallback reason, contraction or Pauli bounds, exact query result, runtime identity, request, and policy into the same evidence model.

## Development Direction

The next evidence-bearing layers are:

1. hardware-rooted signing, measured boot, and externally anchored replay/evidence roots;
2. host filesystem, process, memory, network, and persistence containment;
3. captured hardware pulse traces and independently sealed calibration evidence;
4. authenticated QSA exact-route receipts and fallback evidence;
5. remote Bell-pair and correlation challenge protocols;
6. fault-injection and error-correction datasets beyond deterministic witnesses;
7. AI memory, training-data, tool-output, and action-result receipts with rollback;
8. adversarial datasets with matched benign variation and sealed false-positive evaluation.

Every layer must report what it detects, what it does not detect, runtime cost, false-positive cost, and the evidence required before a disturbance is promoted.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Quantum Core](docs/QUANTUM_CORE.md)
- [QSec 0.2 Trust Mesh](docs/TRUST_MESH.md)
- [Threat Taxonomy](docs/THREAT_TAXONOMY.md)
- [Security Boundaries](docs/SECURITY_BOUNDARIES.md)
- [Post-Quantum Transition](docs/CRYPTOGRAPHIC_TRANSITION.md)

QSec is open source under the MIT License.
