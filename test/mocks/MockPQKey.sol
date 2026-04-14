// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {PQAlgorithms} from "../../src/libraries/PQAlgorithms.sol";

/// @title  MockPQKey
/// @notice Test helper that generates deterministic pseudo-random byte sequences
///         of the correct size for each PQ algorithm. NOT cryptographically valid keys —
///         for use in Foundry tests only.
library MockPQKey {

    /// @notice Returns a deterministic mock public key of the correct size for `algorithm`.
    ///         The content is keccak256-derived from (algorithm, chunk index) pairs.
    function generate(bytes4 algorithm) internal pure returns (bytes memory key) {
        uint256 size = PQAlgorithms.expectedKeySize(algorithm);
        require(size > 0, "MockPQKey: unsupported algorithm");

        key = new bytes(size);
        uint256 chunks = (size + 31) / 32;
        for (uint256 i = 0; i < chunks; i++) {
            bytes32 chunk = keccak256(abi.encode(algorithm, i, "MOCK_PQ_KEY_SEED"));
            uint256 start = i * 32;
            for (uint256 j = 0; j < 32 && start + j < size; j++) {
                key[start + j] = chunk[j];
            }
        }
    }

    /// @notice Returns a mock key of the correct size but with a different seed,
    ///         useful when you need two distinct keys for the same algorithm.
    function generateAlt(bytes4 algorithm) internal pure returns (bytes memory key) {
        uint256 size = PQAlgorithms.expectedKeySize(algorithm);
        require(size > 0, "MockPQKey: unsupported algorithm");

        key = new bytes(size);
        uint256 chunks = (size + 31) / 32;
        for (uint256 i = 0; i < chunks; i++) {
            bytes32 chunk = keccak256(abi.encode(algorithm, i, "MOCK_PQ_KEY_ALT_SEED"));
            uint256 start = i * 32;
            for (uint256 j = 0; j < 32 && start + j < size; j++) {
                key[start + j] = chunk[j];
            }
        }
    }

    /// @notice Returns a third distinct mock key.
    function generateThird(bytes4 algorithm) internal pure returns (bytes memory key) {
        uint256 size = PQAlgorithms.expectedKeySize(algorithm);
        require(size > 0, "MockPQKey: unsupported algorithm");

        key = new bytes(size);
        uint256 chunks = (size + 31) / 32;
        for (uint256 i = 0; i < chunks; i++) {
            bytes32 chunk = keccak256(abi.encode(algorithm, i, "MOCK_PQ_KEY_THIRD_SEED"));
            uint256 start = i * 32;
            for (uint256 j = 0; j < 32 && start + j < size; j++) {
                key[start + j] = chunk[j];
            }
        }
    }

    /// @notice Returns a byte array of the wrong size (size - 1) for testing size validation.
    function generateWrongSize(bytes4 algorithm) internal pure returns (bytes memory key) {
        uint256 size = PQAlgorithms.expectedKeySize(algorithm);
        require(size > 0, "MockPQKey: unsupported algorithm");
        key = new bytes(size - 1);
    }

    /// @notice Returns a deterministic mock proof-of-possession of the correct minimum
    ///         size for `algorithm`. For signature algorithms, uses expectedSignatureSize.
    ///         For ML-KEM, returns a 32-byte mock shared secret.
    ///         NOT cryptographically valid — for Foundry tests only.
    function generateProof(bytes4 algorithm) internal pure returns (bytes memory proof) {
        uint256 size = PQAlgorithms.expectedProofSize(algorithm);
        require(size > 0, "MockPQKey: unsupported algorithm");

        proof = new bytes(size);
        uint256 chunks = (size + 31) / 32;
        for (uint256 i = 0; i < chunks; i++) {
            bytes32 chunk = keccak256(abi.encode(algorithm, i, "MOCK_PQ_PROOF_SEED"));
            uint256 start = i * 32;
            for (uint256 j = 0; j < 32 && start + j < size; j++) {
                proof[start + j] = chunk[j];
            }
        }
    }

    /// @notice Returns a proof of insufficient size (expectedProofSize - 1) for revert tests.
    function generateTooSmallProof(bytes4 algorithm) internal pure returns (bytes memory) {
        uint256 size = PQAlgorithms.expectedProofSize(algorithm);
        require(size > 0, "MockPQKey: unsupported algorithm");
        return new bytes(size - 1);
    }

    /// @notice Returns a mock proof for a KEM algorithm (32-byte shared secret).
    function generateKEMProof() internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256("MOCK_KEM_PROOF"));
    }
}
