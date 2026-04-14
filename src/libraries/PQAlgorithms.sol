// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title  PQAlgorithms
/// @author Valisthea (@Valisthea)
/// @notice Library of algorithm identifiers and metadata for NIST post-quantum standards.
///         FIPS 203 (ML-KEM / Kyber), FIPS 204 (ML-DSA / Dilithium), FIPS 205 (SLH-DSA / SPHINCS+).
library PQAlgorithms {

    // ─── Key Encapsulation — FIPS 203 (ML-KEM / Kyber) ──────────────────────
    bytes4 internal constant ML_KEM_512  = 0x4B454D31; // "KEM1" — NIST Level 1
    bytes4 internal constant ML_KEM_768  = 0x4B454D33; // "KEM3" — NIST Level 3
    bytes4 internal constant ML_KEM_1024 = 0x4B454D35; // "KEM5" — NIST Level 5

    // ─── Digital Signatures — FIPS 204 (ML-DSA / Dilithium) ─────────────────
    bytes4 internal constant ML_DSA_44   = 0x44534132; // "DSA2" — NIST Level 2
    bytes4 internal constant ML_DSA_65   = 0x44534133; // "DSA3" — NIST Level 3
    bytes4 internal constant ML_DSA_87   = 0x44534135; // "DSA5" — NIST Level 5

    // ─── Hash-Based Signatures — FIPS 205 (SLH-DSA / SPHINCS+) ─────────────
    bytes4 internal constant SLH_DSA_128 = 0x534C4831; // "SLH1" — NIST Level 1
    bytes4 internal constant SLH_DSA_192 = 0x534C4833; // "SLH3" — NIST Level 3
    bytes4 internal constant SLH_DSA_256 = 0x534C4835; // "SLH5" — NIST Level 5

    /// @notice Returns the expected public key byte length for a given algorithm.
    ///         Returns 0 for unknown algorithms.
    function expectedKeySize(bytes4 algorithm) internal pure returns (uint256) {
        if (algorithm == ML_KEM_512)  return 800;
        if (algorithm == ML_KEM_768)  return 1184;
        if (algorithm == ML_KEM_1024) return 1568;
        if (algorithm == ML_DSA_44)   return 1312;
        if (algorithm == ML_DSA_65)   return 1952;
        if (algorithm == ML_DSA_87)   return 2592;
        if (algorithm == SLH_DSA_128) return 32;
        if (algorithm == SLH_DSA_192) return 48;
        if (algorithm == SLH_DSA_256) return 64;
        return 0;
    }

    /// @notice Returns the NIST security level (1, 2, 3, or 5) for a given algorithm.
    ///         Returns 0 for unknown algorithms.
    function nistLevel(bytes4 algorithm) internal pure returns (uint256) {
        if (algorithm == ML_KEM_512  || algorithm == SLH_DSA_128) return 1;
        if (algorithm == ML_DSA_44)                                return 2;
        if (algorithm == ML_KEM_768  || algorithm == ML_DSA_65
                                     || algorithm == SLH_DSA_192) return 3;
        if (algorithm == ML_KEM_1024 || algorithm == ML_DSA_87
                                     || algorithm == SLH_DSA_256) return 5;
        return 0;
    }

    /// @notice Returns true if the algorithm is a Key Encapsulation Mechanism (ML-KEM family).
    function isKEM(bytes4 algorithm) internal pure returns (bool) {
        return algorithm == ML_KEM_512
            || algorithm == ML_KEM_768
            || algorithm == ML_KEM_1024;
    }

    /// @notice Returns true if the algorithm is a digital signature scheme
    ///         (ML-DSA or SLH-DSA family).
    function isSignature(bytes4 algorithm) internal pure returns (bool) {
        return algorithm == ML_DSA_44
            || algorithm == ML_DSA_65
            || algorithm == ML_DSA_87
            || algorithm == SLH_DSA_128
            || algorithm == SLH_DSA_192
            || algorithm == SLH_DSA_256;
    }

    /// @notice Returns the expected signature byte length for a given algorithm.
    ///         Uses the minimum size (s-variant) for SLH-DSA to accept both s and f
    ///         parameter-set signatures. Returns 0 for KEM algorithms (no signing).
    ///
    ///         Sources: FIPS 204 Table 1 (ML-DSA), FIPS 205 Table 2 (SLH-DSA).
    function expectedSignatureSize(bytes4 algorithm) internal pure returns (uint256) {
        if (algorithm == ML_DSA_44)   return 2420;
        if (algorithm == ML_DSA_65)   return 3309;
        if (algorithm == ML_DSA_87)   return 4627;
        if (algorithm == SLH_DSA_128) return 7856;   // SHA2-128s minimum
        if (algorithm == SLH_DSA_192) return 16224;  // SHA2-192s minimum
        if (algorithm == SLH_DSA_256) return 29792;  // SHA2-256s minimum
        return 0; // KEM algorithms have no signing capability
    }

    /// @notice Returns the minimum expected proof-of-possession byte length.
    ///         For signature algorithms, this equals expectedSignatureSize().
    ///         For ML-KEM, the proof is the decapsulated shared secret (32 bytes).
    function expectedProofSize(bytes4 algorithm) internal pure returns (uint256) {
        if (algorithm == ML_KEM_512 || algorithm == ML_KEM_768 || algorithm == ML_KEM_1024) {
            return 32; // ML-KEM shared secret is always 32 bytes (all parameter sets)
        }
        return expectedSignatureSize(algorithm);
    }

    /// @notice Returns true if the algorithm is known and supported.
    function isSupported(bytes4 algorithm) internal pure returns (bool) {
        return expectedKeySize(algorithm) > 0;
    }

    /// @notice Returns all 9 supported algorithm identifiers.
    function allAlgorithms() internal pure returns (bytes4[] memory algs) {
        algs = new bytes4[](9);
        algs[0] = ML_KEM_512;
        algs[1] = ML_KEM_768;
        algs[2] = ML_KEM_1024;
        algs[3] = ML_DSA_44;
        algs[4] = ML_DSA_65;
        algs[5] = ML_DSA_87;
        algs[6] = SLH_DSA_128;
        algs[7] = SLH_DSA_192;
        algs[8] = SLH_DSA_256;
    }
}
