// SPDX-License-Identifier: CC0-1.0
pragma solidity >=0.8.0;

import "./IERCWWWW.sol";

/// @title  ERC-WWWW On-Chain Verification Extension
/// @author Valisthea (@Valisthea)
/// @notice Optional extension for on-chain post-quantum signature verification.
///
/// @dev    GAS COST ADVISORY:
///
///         On-chain PQ signature verification is prohibitively expensive for
///         most use cases:
///           ML-DSA-65 (Dilithium-3): ~1,500,000 gas
///           SLH-DSA-256f:            ~10,000,000+ gas (thousands of SHAKE calls)
///
///         This is intentionally NOT part of the core IERCWWWW interface.
///         The recommended flow for the vast majority of protocols is:
///
///           OFF-CHAIN:
///             1. Call publicKeyOf(keyId) to fetch the PQ public key.
///             2. Verify the PQ signature locally (fast, free).
///             3. Submit only the outcome (e.g., a ZK proof of verification)
///                on-chain.
///
///           ON-CHAIN (this extension):
///             Use verifyPQSignature() ONLY when the contract itself must
///             decide based on a PQ signature and a ZK proof of verification
///             is unavailable or undesired. Example: a multisig contract where
///             each custodian provides a PQ signature and the contract verifies
///             all of them before releasing funds.
///
///         SLH-DSA IMPLEMENTORS:
///           Consider using SHA3/SHAKE precompiles (EIP-5988, when available)
///           to reduce the hash computation cost significantly.

interface IERCWWWW_OnChainVerify is IERCWWWW {

    /// @notice Verify a post-quantum signature on-chain.
    /// @dev    The key MUST be in ACTIVE or ROTATED state.
    ///         REVOKED keys MUST return false without reverting.
    ///         Expired keys (expiresAt > 0 && block.timestamp >= expiresAt)
    ///         MUST revert with KeyExpired — expiry invalidates new use.
    ///
    ///         Historical verification of old signatures under a ROTATED key
    ///         is permitted (ROTATED state preserved exactly for this purpose).
    ///
    /// @param keyId      Key used to produce the signature.
    /// @param message    The signed message bytes (raw, not pre-hashed).
    /// @param signature  The PQ signature bytes.
    /// @return True if the signature is valid under the public key for keyId.
    function verifyPQSignature(
        bytes32 keyId,
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool);

    /// @notice Returns the approximate gas cost to verify a signature for a given algorithm.
    /// @dev    Informational only. Actual cost varies by EVM version, available precompiles,
    ///         and signature/message length. These are order-of-magnitude estimates.
    ///         Use eth_estimateGas for accurate per-call estimates.
    ///
    ///         Reference values (no precompiles):
    ///           ALG_ML_DSA_44:   ~900,000 gas
    ///           ALG_ML_DSA_65:   ~1,500,000 gas
    ///           ALG_ML_DSA_87:   ~2,000,000 gas
    ///           ALG_SLH_DSA_128: ~4,000,000 gas
    ///           ALG_SLH_DSA_192: ~7,000,000 gas
    ///           ALG_SLH_DSA_256: ~10,000,000 gas
    ///           ALG_ML_KEM_*:    N/A (key encapsulation has no signature)
    ///
    /// @param algorithm  Algorithm identifier (e.g. ALG_ML_DSA_87).
    /// @return Estimated gas in gas units. Returns 0 for KEM algorithms.
    function estimatedVerificationGas(bytes4 algorithm)
        external pure returns (uint256);
}
