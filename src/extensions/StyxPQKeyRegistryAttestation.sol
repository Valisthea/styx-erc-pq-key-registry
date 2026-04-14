// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {StyxPQKeyRegistry} from "../StyxPQKeyRegistry.sol";
import {
    IERCWWWW_Attestation,
    MAX_ATTESTATIONS_PER_KEY,
    MAX_ATTESTATION_DATA_SIZE
} from "../interfaces/IERCWWWW_Attestation.sol";

/// @title  StyxPQKeyRegistryAttestation
/// @author Valisthea (@Valisthea)
/// @notice Extension of StyxPQKeyRegistry implementing the optional IERCWWWW_Attestation
///         interface for third-party key quality attestations (HSM, FIPS 140-3, audit proofs).
contract StyxPQKeyRegistryAttestation is StyxPQKeyRegistry, IERCWWWW_Attestation {

    // ─── Storage ──────────────────────────────────────────────────────────────

    /// @dev keyId → list of attestations
    mapping(bytes32 => Attestation[]) internal _attestations;

    /// @dev keyId → attestationType → exists (for O(1) hasAttestation checks)
    mapping(bytes32 => mapping(bytes4 => bool)) internal _hasAttestationMap;

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(uint256 maxKeysPerOwner_, uint256 minNistLevel_)
        StyxPQKeyRegistry(maxKeysPerOwner_, minNistLevel_)
    {}

    // ─── Attestation Functions ────────────────────────────────────────────────

    /// @inheritdoc IERCWWWW_Attestation
    function attestKey(
        bytes32 keyId,
        bytes4 attestationType,
        bytes calldata data
    ) external {
        if (_keys[keyId].registeredAt == 0) revert KeyNotFound(keyId);
        if (_attestations[keyId].length >= MAX_ATTESTATIONS_PER_KEY) {
            revert AttestationLimitReached(keyId, MAX_ATTESTATIONS_PER_KEY);
        }
        if (data.length > MAX_ATTESTATION_DATA_SIZE) {
            revert AttestationDataTooLarge(data.length, MAX_ATTESTATION_DATA_SIZE);
        }

        _attestations[keyId].push(Attestation({
            keyId:           keyId,
            attester:        msg.sender,
            attestationType: attestationType,
            timestamp:       block.timestamp,
            data:            data
        }));
        _hasAttestationMap[keyId][attestationType] = true;

        emit KeyAttested(keyId, msg.sender, attestationType);
    }

    /// @inheritdoc IERCWWWW_Attestation
    function attestationsOf(bytes32 keyId)
        external
        view
        returns (Attestation[] memory)
    {
        return _attestations[keyId];
    }

    /// @inheritdoc IERCWWWW_Attestation
    function attestationsOfPaginated(
        bytes32 keyId,
        uint256 offset,
        uint256 limit
    ) external view returns (Attestation[] memory attestations, uint256 total) {
        Attestation[] storage all = _attestations[keyId];
        total = all.length;

        if (offset >= total || limit == 0) {
            return (new Attestation[](0), total);
        }

        uint256 end = offset + limit > total ? total : offset + limit;
        uint256 length = end - offset;
        attestations = new Attestation[](length);
        for (uint256 i = 0; i < length; i++) {
            attestations[i] = all[offset + i];
        }
    }

    /// @inheritdoc IERCWWWW_Attestation
    function hasAttestation(bytes32 keyId, bytes4 attestationType)
        external
        view
        returns (bool)
    {
        return _hasAttestationMap[keyId][attestationType];
    }

    // ─── ERC-165 ──────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override
        returns (bool)
    {
        return interfaceId == type(IERCWWWW_Attestation).interfaceId
            || super.supportsInterface(interfaceId);
    }
}
