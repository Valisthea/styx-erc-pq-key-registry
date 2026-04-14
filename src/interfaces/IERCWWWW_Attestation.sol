// SPDX-License-Identifier: CC0-1.0
pragma solidity >=0.8.0;

import "./IERCWWWW.sol";

// ─── Attestation Type Constants (file-level) ──────────────────────────────────
// These are file-level constants so they can be accessed after import without
// the IERCWWWW_Attestation.CONSTANT_NAME syntax, which requires Solidity ≥0.8.17.

/// @dev Key was generated inside a Hardware Security Module.
bytes4 constant ATT_HSM_GENERATED  = 0x48534D47; // "HSMG"

/// @dev Key generation hardware is FIPS 140-3 validated.
bytes4 constant ATT_FIPS_VALIDATED = 0x46495053; // "FIPS"

/// @dev Key generation process was independently audited.
bytes4 constant ATT_AUDITED        = 0x41554454; // "AUDT"

/// @dev Entropy source meets NIST SP 800-90B requirements.
bytes4 constant ATT_ENTROPY_PROOF  = 0x454E5450; // "ENTP"

// ─── Per-key attestation cap (max attestations stored per key) ──────────────────
uint256 constant MAX_ATTESTATIONS_PER_KEY  = 20;

// ─── Maximum attestation data payload size (bytes) ──────────────────────────────
uint256 constant MAX_ATTESTATION_DATA_SIZE = 1024;

/// @title  ERC-WWWW Key Attestation Extension
/// @author Valisthea (@Valisthea)
/// @notice Optional extension for third-party attestations about key generation quality.
///
/// @dev    Use cases:
///         - Enterprise compliance (FIPS 140-3 HSM-generated key proof)
///         - Auditor attestations (independently audited key ceremony)
///         - Entropy source certification (NIST SP 800-90B validated RNG)
///
///         Attestations are additive and non-exclusive. Multiple attesters
///         can attest to the same key with the same or different types.
///         Attestations are permanent — they cannot be removed after addition.
interface IERCWWWW_Attestation is IERCWWWW {

    struct Attestation {
        bytes32 keyId;           // Key being attested
        address attester;        // Account making the attestation
        bytes4 attestationType;  // Type of attestation (ATT_* constants above)
        uint256 timestamp;       // Block timestamp when attestation was recorded
        bytes data;              // Attestation-specific data (certificate hash, etc.)
    }

    // ─── Custom Errors ────────────────────────────────────────────────────────

    /// @dev Reverts when adding an attestation would exceed MAX_ATTESTATIONS_PER_KEY.
    error AttestationLimitReached(bytes32 keyId, uint256 limit);

    /// @dev Reverts when attestation data exceeds MAX_ATTESTATION_DATA_SIZE bytes.
    error AttestationDataTooLarge(uint256 size, uint256 max);

    // ─── Events ──────────────────────────────────────────────────────────────

    event KeyAttested(
        bytes32 indexed keyId,
        address indexed attester,
        bytes4 indexed attestationType
    );

    // ─── Functions ───────────────────────────────────────────────────────────

    /// @notice Submit an attestation for a registered key.
    /// @dev    The key MUST exist (any state). The attester is msg.sender.
    ///         Attestations are permanent and cannot be revoked.
    /// @param keyId           Key to attest.
    /// @param attestationType One of the ATT_* file-level constants or a custom bytes4.
    /// @param data            Attestation payload (certificate hash, report hash, etc.).
    function attestKey(
        bytes32 keyId,
        bytes4 attestationType,
        bytes calldata data
    ) external;

    /// @notice Returns all attestations recorded for a given key.
    /// @dev    May be large for popular keys — prefer attestationsOfPaginated()
    ///         for on-chain callers. Capped at MAX_ATTESTATIONS_PER_KEY entries.
    function attestationsOf(bytes32 keyId)
        external view returns (Attestation[] memory);

    /// @notice Returns a paginated slice of attestations for a given key.
    /// @param keyId   Key to query.
    /// @param offset  Zero-based index of the first attestation to return.
    /// @param limit   Maximum number of attestations to return.
    /// @return attestations  Attestations for the requested page.
    /// @return total         Total attestations recorded for this key.
    function attestationsOfPaginated(
        bytes32 keyId,
        uint256 offset,
        uint256 limit
    ) external view returns (Attestation[] memory attestations, uint256 total);

    /// @notice Returns whether a key has at least one attestation of the given type.
    function hasAttestation(bytes32 keyId, bytes4 attestationType)
        external view returns (bool);
}
