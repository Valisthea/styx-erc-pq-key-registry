// SPDX-License-Identifier: CC0-1.0
pragma solidity >=0.8.0;

import "./IERCWWWW.sol";

/// @title  ERC-WWWW Dual-Signing Extension
/// @author Valisthea (@Valisthea)
/// @notice Optional extension for verifying dual classical + post-quantum signatures.
///
/// @dev    PURPOSE:
///         During the quantum transition period, protocols may require BOTH a
///         classical secp256k1 ECDSA signature AND a PQ signature (ML-DSA or
///         SLH-DSA) on the same message. This provides defense-in-depth:
///         even if one cryptographic scheme is broken, the other still protects.
///
///         CANONICAL DUAL-SIGN MESSAGE FORMAT (Fix 6 — interoperability):
///
///         Both the classical and PQ signatures MUST sign the SAME digest.
///         Signing different representations of the same message is forbidden
///         as it enables signature confusion attacks.
///
///         The canonical digest is:
///           digest = keccak256(abi.encode(
///               "\x19\x01",         // EIP-191 prefix byte + version byte
///               DOMAIN_SEPARATOR,   // EIP-712 domain separator (see below)
///               keccak256(message)  // Hash of the raw message payload
///           ))
///
///         Where DOMAIN_SEPARATOR is:
///           keccak256(abi.encode(
///               keccak256(
///                   "EIP712Domain(string name,string version,"
///                   "uint256 chainId,address verifyingContract)"
///               ),
///               keccak256("ERC-WWWW"),
///               keccak256("1"),
///               block.chainid,
///               address(this)
///           ))
///
///         The secp256k1 ECDSA signature signs `digest` as per EIP-712.
///         The PQ signature (ML-DSA or SLH-DSA) also signs `digest` as per
///         the respective FIPS algorithm specification.
///
///         Implementations MUST NOT allow one scheme to sign the raw message
///         while the other signs the hash — both MUST operate on `digest`.

interface IERCWWWW_DualSign is IERCWWWW {

    /// @notice Verify a dual signature (secp256k1 ECDSA + post-quantum).
    /// @dev    Returns true if and only if BOTH signatures are valid over
    ///         the canonical EIP-712 digest (see interface NatSpec above).
    ///
    ///         The PQ key (keyId) MUST be in ACTIVE or ROTATED state.
    ///         REVOKED or expired keys cause the function to return false.
    ///
    ///         `message` is the raw payload bytes. The implementation
    ///         hashes it as keccak256(message) and constructs the digest
    ///         internally — callers do NOT pre-hash the message.
    ///
    /// @param keyId            PQ key ID used for the PQ signature.
    /// @param message          Raw message payload (pre-hashing).
    /// @param classicalSig     65-byte secp256k1 ECDSA signature (r ‖ s ‖ v).
    /// @param pqSig            Post-quantum signature bytes.
    /// @param classicalSigner  Expected secp256k1 signer address.
    /// @return True if both signatures are valid over the canonical digest.
    function verifyDualSignature(
        bytes32 keyId,
        bytes calldata message,
        bytes calldata classicalSig,
        bytes calldata pqSig,
        address classicalSigner
    ) external view returns (bool);

    /// @notice Returns the EIP-712 domain separator used by this registry.
    /// @dev    Clients that construct the digest off-chain MUST use this value
    ///         as DOMAIN_SEPARATOR. It changes if the contract is redeployed
    ///         (different address) or migrated to a new chain.
    function domainSeparator() external view returns (bytes32);

    /// @notice Returns whether an address has both a classical Ethereum key
    ///         and an active PQ signing key (ML-DSA or SLH-DSA) registered.
    /// @dev    "Classical key" is inferred from the existence of a non-zero
    ///         Ethereum address (every EOA implicitly has a secp256k1 key).
    ///         This function checks the PQ side only.
    /// @param account  Address to check.
    /// @return True if account has at least one ACTIVE PQ key with SIGNATURE
    ///         or DUAL purpose and the key is not expired.
    function isDualSignReady(address account) external view returns (bool);
}
