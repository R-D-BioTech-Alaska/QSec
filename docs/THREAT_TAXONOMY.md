# QSec Threat Taxonomy

QSec names a threat by the mechanism it uses, not by placing a letter in front of an ordinary security term.

## Report Vocabulary

| Term | Meaning |
|---|---|
| Threat | The hostile entity, mechanism, or operation |
| Lineage | Related threats descended from the same design |
| Strain | A specific implementation or variant |
| Payload | The executable or physical malicious component |
| Vector | The entry path |
| Footprint | Observable evidence of execution |
| Residue | Computational or physical change left behind |
| Disturbance | Suspicious deviation not yet confirmed as hostile |
| Breach | Confirmed unauthorized interaction |
| Compromise | Loss of trusted operation |
| Collapse | Destructive loss of a protected state or service |
| Propagation | Movement into additional nodes, channels, or devices |

## Threat Classes

| Code | Name | Primary layer | Mechanism |
|---|---|---|---|
| QSEC-PHASE-001 | Phaseworm | State and circuit | Propagates while changing or exploiting relative phase |
| QSEC-CIRCUIT-001 | Shadow Circuit | Circuit | Hides unauthorized gates or branches inside approved execution |
| QSEC-STATE-002 | State Leech | State and side channel | Extracts information through repeated preparation, leakage, or sampling |
| QSEC-MEASURE-001 | Collapseware | Measurement | Forces premature measurement or destructive state loss |
| QSEC-CAL-001 | Driftroot | Calibration | Persistently moves trusted calibration toward attacker-selected behavior |
| QSEC-NOISE-001 | Noisecloak | Noise | Conceals targeted manipulation inside apparently ordinary noise |
| QSEC-PULSE-001 | Pulse Parasite | Control pulse | Alters waveforms, timing, phase, amplitude, or pulse order |
| QSEC-QEC-001 | Syndrome Forger | Error correction | Injects, suppresses, or rewrites syndrome results |
| QSEC-ENT-001 | Entanglement Siphon | Entanglement and channel | Redirects or leaks trust through unauthorized correlations |
| QSEC-BACKEND-001 | Oracle Mimic | Backend and service | Impersonates an oracle, backend, simulator, compiler, or service |
| QSEC-COHERENCE-001 | Coherence Eater | Coherence | Deliberately accelerates decoherence |
| QSEC-STATE-001 | State Doppelgänger | State | Substitutes an attacker-controlled but plausible state |
| QSEC-BASIS-001 | Basis Trap | Measurement | Changes or biases basis selection |
| QSEC-READOUT-001 | Readout Phantom | Readout | Forges output without necessarily changing the computation |
| QSEC-RESET-001 | Reset Ghost | Reset | Survives or influences a supposedly clean reset |
| QSEC-ANCILLA-001 | Ancilla Parasite | Ancilla | Compromises helper qubits used for verification or correction |
| QSEC-CHANNEL-001 | Channel Splice | Channel | Inserts an unauthorized endpoint into a trusted channel |
| QSEC-CORR-001 | Correlation Forge | Correlation | Manufactures false but plausible correlations |
| QSEC-POLICY-001 | Policy Parasite | Policy | Substitutes, weakens, or bypasses the active security policy |
| QSEC-CAP-001 | Capability Escalator | Authorization | Expands a bounded permission into broader scope, duration, reuse, or action |
| QSEC-INTENT-001 | Intent Forger | Request and context | Rebinds approval to a different actor, request, resource, nonce, or context |
| QSEC-CONSENSUS-001 | Consensus Forge | Approval and verification | Manufactures or corrupts independent approvals so a false quorum appears valid |
| QSEC-ENTROPY-001 | Entropy Leech | Randomness | Predicts, reuses, reduces, or biases an entropy source |
| QSEC-CRYPTO-001 | Harvest Vault | Cryptography and storage | Stores protected data for later quantum decryption |

## Technique Names

- Phase Injection
- Amplitude Steering
- Basis Substitution
- Measurement Injection
- State Replacement
- Gate Grafting
- Circuit Splicing
- Calibration Poisoning
- Pulse Tampering
- Readout Forgery
- Syndrome Suppression
- Noise Camouflage
- Entropy Biasing
- Entanglement Hijacking
- Correlation Spoofing
- Reset Contamination
- Backend Impersonation
- Compiler Poisoning
- Transpiler Grafting
- Coherence Starvation
- Policy Substitution
- Rule Downgrade
- Scope Escalation
- Action Rebinding
- Request Rebinding
- Context Replay
- Approval Forgery
- Quorum Replay

## Classification Rule

A threat name is not evidence. A report should state:

1. the observed disturbance;
2. the invariant, identity, or baseline that failed;
3. the strength and source of the evidence;
4. competing benign explanations;
5. the response authority that promoted or rejected the finding.

Example:

> QSec detected a Phaseworm disturbance from the Helix lineage. The strain entered through a pulse-control vector, added a Shadow Circuit, and used Noise Camouflage to conceal phase steering. Circuit, pulse, and calibration residue were preserved in the evidence ledger.
