# ERC-WWWW: Post-Quantum Key Registry

**Fourth ERC of the [STYX Protocol](https://github.com/Valisthea) suite by Valisthea.**

On-chain registration, rotation, and migration of post-quantum cryptographic keys.
NIST FIPS 203 (ML-KEM/Kyber), FIPS 204 (ML-DSA/Dilithium), FIPS 205 (SLH-DSA/SPHINCS+).

---

## Overview

Quantum computers running Shor's algorithm will break secp256k1, ECDH, and BN254 — every cryptographic primitive Ethereum currently relies on. This ERC provides a **parallel post-quantum identity layer**: accounts register PQ keys on-chain, protocols opt in to quantum-resistant verification without waiting for a consensus-level hard fork.

```
Account → registerPQKeyWithProof() → REGISTERED
       → activateKey()             → ACTIVE (usable for new ops)
       → rotateKey()               → ROTATED (historical verification only)
       → revokeKey()               → REVOKED (permanently invalid)
```

---

## Interfaces

| File | Purpose |
|------|---------|
| `IERCWWWW.sol` | Core interface — key lifecycle, pagination, expiration |
| `IERCWWWW_DualSign.sol` | Optional — classical + PQ dual-signature verification (EIP-712) |
| `IERCWWWW_OnChainVerify.sol` | Optional — on-chain PQ signature verification (expensive) |
| `IERCWWWW_Attestation.sol` | Optional — third-party key quality attestations (HSM, FIPS 140-3) |

---

## OMEGA Audit Fixes Applied

Seven security fixes from the Kairos Lab OMEGA V4 audit:

1. **Proof of possession** — `registerPQKeyWithProof()` verifies the caller holds the private key before registration
2. **Paginated key queries** — `keysOfPaginated()` + `keyCountOf()` + `maxKeysPerOwner()` prevent gas DoS
3. **Key expiration** — `expiresAt` field + `validityPeriod` param; `isKeyUsable()` checks expiry
4. **Structured revocation** — `RevocationReason` enum replaces unbounded string
5. **On-chain verify as extension** — `verifyPQSignature()` moved to optional `IERCWWWW_OnChainVerify` (ML-DSA-65: ~1.5M gas)
6. **Canonical dual-sign format** — Both signatures sign the same EIP-712 digest
7. **REGISTERED→ACTIVE documentation** — Two-step lifecycle rationale for key ceremony pre-staging

---

## Algorithms

| Identifier | Constant | NIST Level | Purpose | Pub Key |
|------------|----------|-----------|---------|---------|
| `0x4B454D31` | `ALG_ML_KEM_512` | 1 | Encapsulation | 800 B |
| `0x4B454D33` | `ALG_ML_KEM_768` | 3 | Encapsulation | 1,184 B |
| `0x4B454D35` | `ALG_ML_KEM_1024` | 5 | Encapsulation | 1,568 B |
| `0x44534132` | `ALG_ML_DSA_44` | 2 | Signature | 1,312 B |
| `0x44534133` | `ALG_ML_DSA_65` | 3 | Signature | 1,952 B |
| `0x44534135` | `ALG_ML_DSA_87` | 5 | Signature | 2,592 B |
| `0x534C4831` | `ALG_SLH_DSA_128` | 1 | Signature | 32 B |
| `0x534C4833` | `ALG_SLH_DSA_192` | 3 | Signature | 48 B |
| `0x534C4835` | `ALG_SLH_DSA_256` | 5 | Signature | 64 B |

---

## STYX Protocol ERC Suite

| ERC | Name | Status |
|-----|------|--------|
| ERC-1680 | Encrypted Token Interface | Draft — PR open |
| ERC-1681 | Cryptographic Amnesia Interface | Draft — PR open |
| ERC-1682 | FHE Computation Verification Interface | Draft — PR open |
| ERC-WWWW | Post-Quantum Key Registry | This repo |

---

## License

[CC0-1.0](./LICENSE) — No rights reserved.
