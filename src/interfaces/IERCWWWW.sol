// SPDX-License-Identifier: CC0-1.0
pragma solidity >=0.8.0;

/// @title  ERC-WWWW Post-Quantum Key Registry
/// @author Valisthea (@Valisthea)
/// @notice Standard interface for on-chain registration, rotation,
///         and migration of post-quantum cryptographic keys.
///
/// Supported NIST-standardized algorithms:
///   - ML-KEM  (FIPS 203) — lattice-based key encapsulation (Kyber)
///   - ML-DSA  (FIPS 204) — lattice-based digital signatures (Dilithium)
///   - SLH-DSA (FIPS 205) — hash-based digital signatures (SPHINCS+)
///
/// Algorithm identifiers (bytes4):
///   ALG_ML_KEM_512  = 0x4B454D31  "KEM1" — NIST Level 1
///   ALG_ML_KEM_768  = 0x4B454D33  "KEM3" — NIST Level 3
///   ALG_ML_KEM_1024 = 0x4B454D35  "KEM5" — NIST Level 5
///   ALG_ML_DSA_44   = 0x44534132  "DSA2" — NIST Level 2
///   ALG_ML_DSA_65   = 0x44534133  "DSA3" — NIST Level 3
///   ALG_ML_DSA_87   = 0x44534135  "DSA5" — NIST Level 5
///   ALG_SLH_DSA_128 = 0x534C4831  "SLH1" — NIST Level 1
///   ALG_SLH_DSA_192 = 0x534C4833  "SLH3" — NIST Level 3
///   ALG_SLH_DSA_256 = 0x534C4835  "SLH5" — NIST Level 5

interface IERCWWWW {

    // ─── Types ───────────────────────────────────────────────────────────────

    enum KeyState {
        REGISTERED, // Key staged, pending activation. NOT usable for new ops.
        ACTIVE,     // Current active key for this algorithm+purpose+owner.
        ROTATED,    // Replaced by a newer key. Valid for HISTORICAL verification only.
        REVOKED     // Permanently invalidated. MUST NOT be used for any operation.
    }

    enum KeyPurpose {
        SIGNATURE,      // Digital signature (ML-DSA, SLH-DSA)
        ENCAPSULATION,  // Key encapsulation / key exchange (ML-KEM)
        DUAL            // Both signature and encapsulation (algorithm permitting)
    }

    /// @notice Revocation reason codes.
    /// @dev    Enum instead of string: gas efficient, indexable, and unambiguous.
    ///         Filtering for KEY_COMPROMISED vs OWNER_REQUEST has different
    ///         security implications — a string would require off-chain parsing.
    enum RevocationReason {
        KEY_COMPROMISED,      // Private key known or suspected compromised
        ALGORITHM_DEPRECATED, // Algorithm deprecated by NIST or governance action
        OWNER_REQUEST,        // Voluntary revocation by the key owner
        GOVERNANCE_ACTION,    // Registry governance forced revocation
        SUPERSEDED            // Replaced by a stronger parameter set or newer key
    }

    struct PQKeyInfo {
        bytes32 keyId;       // Unique key identifier (computed on-chain)
        address owner;       // Key owner address
        bytes4 algorithm;    // Algorithm identifier (e.g. ALG_ML_DSA_87)
        KeyPurpose purpose;  // What this key is used for
        KeyState state;      // Current lifecycle state
        uint256 registeredAt; // Block timestamp of registration
        uint256 activatedAt;  // Block timestamp of activation (0 if not yet active)
        uint256 rotatedAt;    // Block timestamp of rotation (0 if still active/registered)
        uint256 revokedAt;    // Block timestamp of revocation (0 if not revoked)
        bytes32 rotatedTo;    // keyId of the replacement key (bytes32(0) if none)
        uint256 nistLevel;    // NIST security level (1, 2, 3, or 5)
        uint256 expiresAt;    // Expiry UNIX timestamp. 0 = no expiration.
    }

    // ─── Custom Errors ───────────────────────────────────────────────────────

    error KeyAlreadyRegistered(bytes32 keyId);
    error KeyNotFound(bytes32 keyId);
    error KeyNotActive(bytes32 keyId, KeyState currentState);
    error KeyAlreadyRevoked(bytes32 keyId);
    error UnauthorizedKeyOwner(address caller, address owner);
    error UnsupportedAlgorithm(bytes4 algorithm);
    error InvalidPublicKeyFormat(bytes4 algorithm, uint256 expectedSize, uint256 actualSize);
    error AlgorithmPurposeMismatch(bytes4 algorithm, KeyPurpose purpose);
    error NistLevelTooLow(uint256 provided, uint256 minimum);
    error RotationTargetNotActive(bytes32 newKeyId);
    error InvalidProofOfPossession(bytes32 keyId);

    /// @notice Reverts when an owner tries to register more keys than maxKeysPerOwner().
    error MaxKeysReached(address owner, uint256 max);

    /// @notice Reverts when interacting with an expired key for a new operation.
    error KeyExpired(bytes32 keyId, uint256 expiresAt);

    // ─── Events ──────────────────────────────────────────────────────────────

    /// @notice Emitted when a new PQ key is registered.
    event PQKeyRegistered(
        bytes32 indexed keyId,
        address indexed owner,
        bytes4 indexed algorithm,
        KeyPurpose purpose,
        uint256 nistLevel
    );

    /// @notice Emitted when a registered key is activated.
    event PQKeyActivated(
        bytes32 indexed keyId,
        address indexed owner
    );

    /// @notice Emitted when an active key is rotated to a new key.
    event PQKeyRotated(
        bytes32 indexed oldKeyId,
        bytes32 indexed newKeyId,
        address indexed owner
    );

    /// @notice Emitted when a key is permanently revoked.
    event PQKeyRevoked(
        bytes32 indexed keyId,
        address indexed owner,
        RevocationReason indexed reason
    );

    // ─── Key Registration ────────────────────────────────────────────────────

    /// @notice Register a new post-quantum public key.
    /// @dev    Key ID is computed deterministically on-chain:
    ///           keyId = keccak256(abi.encode(
    ///               block.chainid,        // cross-chain collision prevention
    ///               address(this),        // cross-registry collision prevention
    ///               owner,                // key owner
    ///               algorithm,            // algorithm identifier
    ///               keccak256(publicKey)  // public key hash (saves gas vs full key)
    ///           ))
    ///
    ///         The publicKey MUST pass size validation per algorithm:
    ///           ML-KEM-512:  800 bytes   ML-KEM-768:  1,184 bytes
    ///           ML-KEM-1024: 1,568 bytes ML-DSA-44:   1,312 bytes
    ///           ML-DSA-65:   1,952 bytes ML-DSA-87:   2,592 bytes
    ///           SLH-DSA-128: 32 bytes    SLH-DSA-192: 48 bytes
    ///           SLH-DSA-256: 64 bytes
    ///
    ///         Implementations MUST also validate that the public key bytes
    ///         decode to a well-formed key per FIPS 203 §7.2 (ML-KEM),
    ///         FIPS 204 §7.2 (ML-DSA), or FIPS 205 §10.1 (SLH-DSA).
    ///         If full on-chain validation is too expensive, use
    ///         registerPQKeyWithProof() instead.
    ///
    ///         TWO-STEP LIFECYCLE — Rationale for REGISTERED → ACTIVE:
    ///           Pre-staging a backup key BEFORE the current active key
    ///           is needed for rotation has several use cases:
    ///           (1) Key ceremony: register replacement key, governance votes,
    ///               then activateKey() atomically rotates the old key.
    ///           (2) Scheduled rotation: register N days ahead, activate on date.
    ///           (3) Disaster recovery: pre-register a cold-storage backup key
    ///               that can be activated immediately if the active key is lost.
    ///           The REGISTERED state is NOT usable for new cryptographic operations.
    ///           Call activateKey(keyId) to transition REGISTERED → ACTIVE.
    ///
    ///         Reverts with MaxKeysReached if the owner has reached maxKeysPerOwner().
    ///
    /// @param owner          Address that will own this key.
    /// @param algorithm      Algorithm identifier (e.g. ALG_ML_DSA_87).
    /// @param purpose        Key purpose (SIGNATURE, ENCAPSULATION, or DUAL).
    /// @param publicKey      The PQ public key bytes.
    /// @param validityPeriod Duration in seconds before the key expires.
    ///                       Pass 0 for no expiration. When nonzero,
    ///                       expiresAt = block.timestamp + validityPeriod.
    /// @return keyId         The computed key identifier.
    function registerPQKey(
        address owner,
        bytes4 algorithm,
        KeyPurpose purpose,
        bytes calldata publicKey,
        uint256 validityPeriod
    ) external returns (bytes32 keyId);

    /// @notice Register a new PQ key with cryptographic proof of possession.
    /// @dev    Identical to registerPQKey() but additionally verifies that the
    ///         caller possesses the private key corresponding to publicKey.
    ///         This prevents registry pollution with invalid or rogue keys.
    ///
    ///         PROOF OF POSSESSION FORMAT:
    ///           For ML-DSA and SLH-DSA (signature algorithms):
    ///             message = keccak256(abi.encode(
    ///                 "PQ_KEY_REGISTRATION",
    ///                 owner,
    ///                 algorithm,
    ///                 publicKey
    ///             ))
    ///             proofOfPossession = Sign(privateKey, message)
    ///             (per the PQ algorithm's signing procedure)
    ///
    ///           For ML-KEM (key encapsulation, no signing):
    ///             The proof is a decapsulation response. The implementation
    ///             generates a deterministic test ciphertext from publicKey and
    ///             a canonical nonce. The caller provides the decapsulated shared
    ///             secret as proofOfPossession. The implementation re-encapsulates
    ///             and verifies the shared secret matches.
    ///
    ///         Reverts with InvalidProofOfPossession if verification fails.
    ///         Reverts with MaxKeysReached if the owner has reached maxKeysPerOwner().
    ///
    /// @param owner              Address that will own this key.
    /// @param algorithm          Algorithm identifier.
    /// @param purpose            Key purpose.
    /// @param publicKey          The PQ public key bytes.
    /// @param validityPeriod     Duration in seconds, 0 = no expiration.
    /// @param proofOfPossession  Self-signature or decapsulation proof.
    /// @return keyId             The computed key identifier.
    function registerPQKeyWithProof(
        address owner,
        bytes4 algorithm,
        KeyPurpose purpose,
        bytes calldata publicKey,
        uint256 validityPeriod,
        bytes calldata proofOfPossession
    ) external returns (bytes32 keyId);

    /// @notice Activate a registered key, making it the current active key.
    /// @dev    Transitions REGISTERED → ACTIVE.
    ///         If another ACTIVE key of the same (algorithm, purpose, owner)
    ///         combination exists, it is automatically transitioned to ROTATED.
    ///         Emits PQKeyRotated for the displaced key, then PQKeyActivated.
    /// @param keyId  Key to activate. Must be in REGISTERED state.
    function activateKey(bytes32 keyId) external;

    /// @notice Rotate the active key to a pre-registered replacement.
    /// @dev    oldKey: ACTIVE → ROTATED.
    ///         newKey: REGISTERED → ACTIVE (auto-activated).
    ///         Historical signatures under the old key remain verifiable
    ///         (ROTATED state preserves public key for lookups).
    ///         Emits PQKeyRotated then PQKeyActivated.
    /// @param oldKeyId  Currently ACTIVE key to retire.
    /// @param newKeyId  Replacement key, must be in REGISTERED state.
    function rotateKey(bytes32 oldKeyId, bytes32 newKeyId) external;

    /// @notice Permanently revoke a key.
    /// @dev    Transitions any non-REVOKED state → REVOKED. Irreversible.
    ///         A REVOKED key MUST NOT be used for any new operation.
    ///         Historical signatures under a REVOKED key SHOULD be treated as
    ///         suspect — the private key may have been compromised.
    ///         Implementations MUST prevent isKeyUsable() from returning
    ///         true for any REVOKED key.
    /// @param keyId   Key to revoke.
    /// @param reason  Structured revocation reason (replaces string for gas efficiency).
    function revokeKey(bytes32 keyId, RevocationReason reason) external;

    // ─── Key Queries ─────────────────────────────────────────────────────────

    /// @notice Returns full key metadata for a given key ID.
    function keyInfo(bytes32 keyId) external view returns (PQKeyInfo memory);

    /// @notice Returns the raw public key bytes for a given key ID.
    function publicKeyOf(bytes32 keyId) external view returns (bytes memory);

    /// @notice Returns the active key ID for an (owner, algorithm, purpose) tuple.
    /// @dev    Returns bytes32(0) if no active key exists for this combination.
    function activeKeyFor(
        address owner,
        bytes4 algorithm,
        KeyPurpose purpose
    ) external view returns (bytes32 keyId);

    /// @notice Returns a paginated slice of all key IDs registered by an owner.
    /// @dev    Includes keys in ALL states (REGISTERED, ACTIVE, ROTATED, REVOKED).
    ///         Caller SHOULD first call keyCountOf(owner) to get the total.
    ///         If offset >= total, returns an empty array.
    ///         If offset + limit > total, returns the remaining keys.
    /// @param owner   Key owner address.
    /// @param offset  Zero-based index of the first key to return.
    /// @param limit   Maximum number of keys to return per page.
    /// @return keys   Keys for the requested page (length <= limit).
    /// @return total  Total keys registered by this owner (all states).
    function keysOfPaginated(
        address owner,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory keys, uint256 total);

    /// @notice Returns the total number of keys registered by an owner (all states).
    function keyCountOf(address owner) external view returns (uint256);

    /// @notice Returns the full rotation chain starting from any key in the chain.
    /// @dev    Traces from the original key through all rotations to the current key.
    ///         The array is ordered oldest → newest.
    /// @param keyId  Any key ID in the rotation chain.
    /// @return       Array of key IDs from original to latest.
    function rotationChain(bytes32 keyId) external view returns (bytes32[] memory);

    /// @notice Returns whether a key can be used for new cryptographic operations.
    /// @dev    Returns true if and only if ALL of the following hold:
    ///           state == ACTIVE
    ///           AND (expiresAt == 0 OR block.timestamp < expiresAt)
    ///         ROTATED keys return false — they are valid for historical
    ///         signature verification only, not for new operations.
    ///         REVOKED keys always return false regardless of expiry.
    function isKeyUsable(bytes32 keyId) external view returns (bool);

    // ─── Configuration ───────────────────────────────────────────────────────

    /// @notice Minimum NIST security level required for key registration.
    /// @dev    Implementations SHOULD enforce Level 3 for production.
    ///         Returns 1, 2, 3, or 5.
    function minNistLevel() external view returns (uint256);

    /// @notice Maximum number of keys (all states) a single address may register.
    /// @dev    Caps the array growth that backs keysOfPaginated() to prevent
    ///         gas DoS. RECOMMENDED: 100.
    ///         Reverts with MaxKeysReached when exceeded.
    function maxKeysPerOwner() external view returns (uint256);

    /// @notice Returns all supported algorithm identifiers.
    /// @dev    In practice this is a small bounded set (NIST has standardized ≤9).
    function supportedAlgorithms() external view returns (bytes4[] memory);

    /// @notice Returns whether the given algorithm identifier is supported.
    function isAlgorithmSupported(bytes4 algorithm) external view returns (bool);

    /// @notice Returns the expected public key byte length for a given algorithm.
    function expectedKeySize(bytes4 algorithm) external view returns (uint256);
}
