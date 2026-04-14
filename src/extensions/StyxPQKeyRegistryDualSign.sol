// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {StyxPQKeyRegistry} from "../StyxPQKeyRegistry.sol";
import {IERCWWWW_DualSign} from "../interfaces/IERCWWWW_DualSign.sol";
import {PQAlgorithms} from "../libraries/PQAlgorithms.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title  StyxPQKeyRegistryDualSign
/// @author Valisthea (@Valisthea)
/// @notice Extension implementing the IERCWWWW_DualSign interface.
///         Verifies dual classical (secp256k1 ECDSA) + PQ signatures over a
///         canonical EIP-712 digest.
///
/// @dev    PQ VERIFICATION NOTE:
///         Full on-chain verification of ML-DSA or SLH-DSA signatures is not
///         yet feasible (ML-DSA-65 ≈ 1.5M gas; SLH-DSA-256f ≈ 10M+ gas) without
///         EVM precompiles. The PQ side of verifyDualSignature validates that a
///         non-empty PQ signature is provided and that the referenced key is in a
///         valid state. Callers SHOULD verify the PQ signature off-chain before
///         relying on the dual-sign result for high-value operations.
contract StyxPQKeyRegistryDualSign is StyxPQKeyRegistry, IERCWWWW_DualSign {
    using ECDSA for bytes32;

    // ─── Domain separator (fork-safe, recomputed on chain-id change) ─────────

    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(uint256 maxKeysPerOwner_, uint256 minNistLevel_)
        StyxPQKeyRegistry(maxKeysPerOwner_, minNistLevel_)
    {
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
            ),
            keccak256("ERC-WWWW"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    /// @dev Returns the cached separator when chainId is unchanged, otherwise
    ///      recomputes it live — prevents cross-chain signature replay after a fork.
    function _domainSeparator() internal view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        }
        return _buildDomainSeparator();
    }

    // ─── Dual-Sign Functions ──────────────────────────────────────────────────

    /// @inheritdoc IERCWWWW_DualSign
    function verifyDualSignature(
        bytes32 keyId,
        bytes calldata message,
        bytes calldata classicalSig,
        bytes calldata pqSig,
        address classicalSigner
    ) external view returns (bool) {
        // Build the canonical EIP-712 digest (both signatures must cover this)
        bytes32 digest = keccak256(abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            _domainSeparator(),
            keccak256(message)
        ));

        // 1. Verify classical ECDSA signature
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, classicalSig);
        if (err != ECDSA.RecoverError.NoError || recovered != classicalSigner) {
            return false;
        }

        // 2. Validate PQ key state
        PQKeyInfo storage key = _keys[keyId];
        if (key.registeredAt == 0) return false;
        if (key.state == KeyState.REVOKED) return false;
        if (key.expiresAt != 0 && block.timestamp >= key.expiresAt) return false;

        // 3. PQ signature size validation per FIPS 204/205 algorithm spec.
        //    Full ML-DSA/SLH-DSA on-chain verification is not yet feasible without
        //    EVM precompiles (~1.5M gas for ML-DSA-65; ~10M+ for SLH-DSA-256f).
        //    We validate the minimum byte length per algorithm to reject trivially
        //    invalid submissions. Off-chain verification SHOULD be performed by
        //    callers before relying on the dual-sign result for high-value ops.
        uint256 expSigSize = PQAlgorithms.expectedSignatureSize(key.algorithm);
        if (expSigSize == 0) return false; // KEM key cannot produce signatures
        if (pqSig.length < expSigSize) return false;

        return true;
    }

    /// @inheritdoc IERCWWWW_DualSign
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    /// @inheritdoc IERCWWWW_DualSign
    function isDualSignReady(address account) external view returns (bool) {
        bytes32[] storage keys = _ownerKeys[account];
        for (uint256 i = 0; i < keys.length; i++) {
            PQKeyInfo storage key = _keys[keys[i]];
            if (
                key.state == KeyState.ACTIVE
                && (key.purpose == KeyPurpose.SIGNATURE || key.purpose == KeyPurpose.DUAL)
                && PQAlgorithms.isSignature(key.algorithm)
                && (key.expiresAt == 0 || block.timestamp < key.expiresAt)
            ) {
                return true;
            }
        }
        return false;
    }

    // ─── ERC-165 ──────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override
        returns (bool)
    {
        return interfaceId == type(IERCWWWW_DualSign).interfaceId
            || super.supportsInterface(interfaceId);
    }
}
