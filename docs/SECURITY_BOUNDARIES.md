# Security Boundaries

## What QSec 0.1.0 Proves

A passing QSec inspection proves only that the supplied evidence passed the configured checks:

- identity matched the supplied baseline;
- circuit structure matched or satisfied policy;
- supplied states obeyed the implemented physical constraints;
- supplied calibration remained inside the configured envelope;
- supplied entropy passed the implemented health checks;
- supplied evidence records formed a valid chain.

It does not prove that omitted telemetry was safe or that the source providing telemetry was honest.

## Disturbance Is Not Automatically an Attack

Hardware drift, finite-shot noise, compiler updates, thermal changes, maintenance, and measurement error can all create real deviations. QSec records the mechanism that best describes the evidence while retaining the status `disturbance` until stronger evidence confirms an unauthorized cause.

## Entropy Boundary

The entropy module is a bounded online health check. Its min-entropy value is a sample estimate based on the most frequent byte. It is not a complete entropy-source model and is not a certification under NIST SP 800-90B.

Use source-specific validation, conditioning analysis, independent health tests, startup tests, and operational monitoring before trusting a source for production keys.

## Physical Boundary

Mathematical validity is necessary but not sufficient.

A substituted state can be normalized, positive, and physically valid. QSec therefore separates physical validity from fidelity, preparation identity, and execution identity.

The `T2 <= 2*T1` rule is valid for the standard Markovian relaxation relationship used by the current check. Non-Markovian systems can require a different model. The policy must state the model being enforced.

## Circuit Boundary

Exact manifest comparison intentionally detects any ordered operation change. A compiler or transpiler may produce a semantically equivalent circuit with a different manifest.

The safe response is to approve and bind known compiled outputs, not to ignore circuit changes. Future semantic-equivalence adapters must produce independent evidence and preserve the original logical circuit contract.

## Evidence Boundary

An unkeyed chain detects changes relative to a retained trusted root. It cannot stop an attacker with full storage control from replacing every record and the root.

Stronger deployments should use one or more of:

- an HMAC key outside the monitored filesystem;
- a digital signature held by a separate authority;
- append-only hardware or service storage;
- periodic root publication to an independent system;
- redundant independent observers.

## Cryptographic Boundary

String discovery is inventory evidence, not proof of actual protocol negotiation. QSec can find algorithm names, keys, configuration, and source references, but runtime protocol capture and certificate/key inspection are separate tasks.

QSec does not implement ML-KEM, ML-DSA, SLH-DSA, or any replacement cryptographic primitive. Use validated implementations and follow the applicable standards and protocol profiles.

## Automated Response Boundary

No 0.1.0 detector has unilateral authority to erase data, destroy a state, revoke a production key, quarantine a host, or disable an AI system.

Future automated response must be:

- policy-bound;
- signed;
- reversible where possible;
- independently logged;
- rate limited;
- isolated from the system being judged;
- tested against false positives and attacker-induced denial of service.
