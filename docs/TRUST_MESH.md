# QSec Trust Mesh

QSec 0.2 adds authenticated and physics-bound controls around objects that ordinary malware scanners cannot verify: quantum pulse schedules, error-correction evidence, model or backend identity, AI action authority, and thermodynamic telemetry.

The trust mesh is not a claim that one mechanism can secure every quantum system. Each control produces independent evidence with its own failure meaning.

## Authenticated Artifact Manifests

An attestation binds a subject to:

- issuer identity;
- issue and expiration times;
- a challenge nonce;
- a monotonic sequence;
- policy and parent digests;
- named artifact hashes and sizes;
- bounded claims.

The current authenticator is HMAC-SHA-256. HMAC provides symmetric authenticity and integrity between parties that already share a protected key. It is not a public signature and does not provide third-party nonrepudiation.

Artifact verification fails closed by default. A manifest is not accepted merely because its HMAC is valid; every required artifact must also be supplied and match its authenticated digest and size.

## Pulse-Control Integrity

A pulse schedule has a canonical identity derived from its ordered physical controls:

- backend identity;
- clock period;
- channel;
- start and duration;
- amplitude;
- phase;
- frequency;
- waveform shape;
- optional sampled waveform.

QSec checks exact schedule identity and calibrated physical envelopes. It detects segment insertion, removal, reordering, channel substitution, overlap, excessive duty cycle, amplitude or duration violations, slew-rate violations, control-energy growth, and waveform or spectral residuals.

Phase comparison is circular. Values near `+pi` and `-pi` are compared by their shortest angular distance rather than by a naive subtraction.

## Stabilizer Syndrome Verification

The QEC verifier uses binary symplectic Pauli algebra. It checks:

- stabilizer-generator commutation;
- code identity;
- round, nonce, and previous-round binding;
- syndrome consistency with an error witness;
- whether the proposed correction clears the syndrome;
- ancilla agreement;
- independent decoder quorum and agreement.

This verifies evidence for a supplied stabilizer code. It does not prove that physical syndrome extraction hardware is honest without independent measurement or attestation.

## Governed AI and Automated Actions

QSec does not execute model or tool actions. It can issue a capability lease only after a request passes all policy and evidence gates.

A request binds:

- request and actor identity;
- exact action and resource;
- scopes;
- risk class;
- nonce and lifetime;
- context;
- attestation and policy digests.

Approvals are individually authenticated and request-bound. High-risk actions can require multiple independent roles. A forged, stale, duplicated, denied, or mismatched approval blocks authorization even when the remaining approvals would otherwise satisfy quorum.

A capability lease is short-lived, exact-bound, and use-limited. It cannot be rebound to a different actor, action, resource, scope set, or request digest.

## Thermodynamic Telemetry

QSec uses a calibrated lumped first-law model:

```text
observed stored-energy change = heat capacity * temperature change
expected energy change = integral(input power - cooling power - passive heat flow)
```

The monitor also checks temperature, power, temperature-rate, sensor continuity, and energy-balance residuals.

This is only valid inside the declared sensor model, heat-capacity estimate, time resolution, and operating envelope. A residual is evidence of inconsistency, not automatic proof of an attack. Benign explanations include sensor delay, omitted heat paths, incorrect calibration, and non-lumped thermal behavior.

## Incident Replay

Trust-mesh evidence can be grouped into deterministic incidents. Events are ordered by timestamp and identifier, content-digested, and chained into an evidence root. Independent high-severity sources can promote a confirmed breach to a compromise. A collapse status remains explicit rather than being inferred from a generic score.

## Controlled Scenario Matrix

The bundled matrix contains 17 deterministic cases:

- 12 malicious mutations across attestation, pulse control, QEC, authorization, and thermal telemetry;
- five clean controls covering the same trust planes.

The matrix is an acceptance test, not a real-world detection-rate estimate. Production claims require hardware captures, realistic benign variation, adversarial datasets, and independently sealed evaluation.
