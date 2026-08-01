# Post-Quantum Cryptographic Transition

## Current Standards Used by QSec

QSec recognizes the three NIST post-quantum standards finalized in August 2024:

| Standard | Algorithm | Purpose |
|---|---|---|
| FIPS 203 | ML-KEM | Key encapsulation |
| FIPS 204 | ML-DSA | Digital signatures |
| FIPS 205 | SLH-DSA | Stateless hash-based digital signatures |

HQC was selected by NIST in March 2025 for future standardization as an additional code-based KEM. QSec labels it `selected`, not `standardized`.

FN-DSA remains an algorithm under standards development. QSec does not label it as a finalized FIPS standard.

Pre-standard names such as CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+, and Falcon are recorded separately. Their presence does not prove that an implementation conforms to ML-KEM, ML-DSA, SLH-DSA, or a future FN-DSA standard.

## Why Inventory Comes First

Migration fails when an organization does not know where cryptography is used. Discovery must include:

- source code and configuration;
- libraries and package dependencies;
- TLS, SSH, VPN, messaging, storage, backups, and firmware;
- certificates and public keys;
- hardware security modules and secure elements;
- long-lived encrypted data;
- third-party services and protocols;
- update and code-signing paths;
- offline recovery material.

QSec 0.1.0 begins with source and configuration discovery. Runtime protocol and certificate inventory are later layers.

## Harvest Vault Exposure

RSA, finite-field Diffie-Hellman/DSA, and elliptic-curve key agreement/signatures are vulnerable to sufficiently capable fault-tolerant quantum algorithms. An attacker does not need that capability today to create risk. Long-lived ciphertext can be collected now and decrypted later.

QSec therefore marks discovery of quantum-vulnerable public-key algorithms as Harvest Vault exposure. That finding means migration work exists. It does not claim that a quantum attacker has already decrypted the data.

## Crypto Agility

Replacing one algorithm is not enough. Systems need the ability to change algorithms, parameters, keys, protocols, libraries, and hardware without losing security or operations.

A QSec migration record should bind:

1. asset and data owner;
2. current algorithm and implementation;
3. confidentiality or signature lifetime;
4. protocol and dependency chain;
5. target algorithm and validated implementation;
6. interoperability test evidence;
7. rollback path;
8. removal date for the vulnerable algorithm;
9. evidence that the old path is no longer negotiated or accepted.

## No Homegrown Cryptography

QSec may test, inventory, route, attest, and enforce cryptographic policy. It must not replace standardized cryptographic primitives with an unreviewed "quantum" cipher.

Experimental physics-derived protocols belong in isolated research lanes until their security model, implementation, side channels, failure behavior, and interoperability have independent evidence.

## Primary References

- NIST FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205: https://csrc.nist.gov/pubs/fips/205/final
- NIST SP 800-227: https://csrc.nist.gov/pubs/sp/800/227/final
- NIST Considerations for Achieving Crypto Agility: https://csrc.nist.gov/pubs/cswp/39/considerations-for-achieving-cryptographic-agility/final
- NIST NCCoE Migration to Post-Quantum Cryptography: https://www.nccoe.nist.gov/projects/building-blocks/post-quantum-cryptography
