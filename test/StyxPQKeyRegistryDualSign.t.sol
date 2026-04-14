// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StyxPQKeyRegistryDualSign} from "../src/extensions/StyxPQKeyRegistryDualSign.sol";
import {IERCWWWW} from "../src/interfaces/IERCWWWW.sol";
import {IERCWWWW_DualSign} from "../src/interfaces/IERCWWWW_DualSign.sol";
import {PQAlgorithms} from "../src/libraries/PQAlgorithms.sol";
import {MockPQKey} from "./mocks/MockPQKey.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract StyxPQKeyRegistryDualSignTest is Test {
    StyxPQKeyRegistryDualSign public registry;

    // Test signers
    uint256 internal alicePrivKey = 0xA11CE;
    address internal alice;

    bytes32 internal keyId;

    function setUp() public {
        alice = vm.addr(alicePrivKey);
        registry = new StyxPQKeyRegistryDualSign(100, 1);

        // Register and activate an ML-DSA-65 key for alice
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.prank(alice);
        keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
        vm.prank(alice);
        registry.activateKey(keyId);
    }

    // ─── domainSeparator ──────────────────────────────────────────────────────

    function test_domainSeparator_notZero() public view {
        assertNotEq(registry.domainSeparator(), bytes32(0));
    }

    function test_domainSeparator_stable() public view {
        // Two calls on same chain must return same value
        assertEq(registry.domainSeparator(), registry.domainSeparator());
    }

    // ─── isDualSignReady ──────────────────────────────────────────────────────

    function test_isDualSignReady_trueWhenActiveKey() public view {
        assertTrue(registry.isDualSignReady(alice));
    }

    function test_isDualSignReady_falseWithNoKey() public {
        address stranger = makeAddr("stranger");
        assertFalse(registry.isDualSignReady(stranger));
    }

    function test_isDualSignReady_falseAfterRevocation() public {
        vm.prank(alice);
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.OWNER_REQUEST);

        assertFalse(registry.isDualSignReady(alice));
    }

    function test_isDualSignReady_falseAfterExpiry() public {
        // Register a key with 100-second validity
        bytes memory pk2 = MockPQKey.generateAlt(PQAlgorithms.ML_DSA_65);
        vm.prank(alice);
        bytes32 keyId2 = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk2, 100
        );
        vm.prank(alice);
        registry.activateKey(keyId2);

        // First key is non-expiring and now rotated, second is expiring+active
        // Warp past expiry
        vm.warp(block.timestamp + 101);
        assertFalse(registry.isDualSignReady(alice));
    }

    // ─── verifyDualSignature — classical signature only ───────────────────────

    function test_verifyDualSig_returnsFalseOnClassicalFailure() public {
        bytes memory message = "Hello, post-quantum world!";
        bytes memory pqSig   = MockPQKey.generateProof(PQAlgorithms.ML_DSA_65);

        // Sign with wrong private key
        bytes32 digest = keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x01),
            registry.domainSeparator(),
            keccak256(message)
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD1, digest);
        bytes memory wrongSig = abi.encodePacked(r, s, v);

        assertFalse(registry.verifyDualSignature(keyId, message, wrongSig, pqSig, alice));
    }

    function test_verifyDualSig_returnsFalseOnRevokedKey() public {
        bytes memory message = "test message";
        bytes memory pqSig   = MockPQKey.generateProof(PQAlgorithms.ML_DSA_65);

        bytes32 digest = keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x01),
            registry.domainSeparator(),
            keccak256(message)
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivKey, digest);
        bytes memory classicSig = abi.encodePacked(r, s, v);

        // Revoke key
        vm.prank(alice);
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.KEY_COMPROMISED);

        assertFalse(registry.verifyDualSignature(keyId, message, classicSig, pqSig, alice));
    }

    function test_verifyDualSig_returnsFalseOnPQSigTooSmall() public {
        bytes memory message   = "test message";
        bytes memory pqSigTiny = new bytes(10); // way too small

        bytes32 digest = keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x01),
            registry.domainSeparator(),
            keccak256(message)
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivKey, digest);
        bytes memory classicSig = abi.encodePacked(r, s, v);

        assertFalse(registry.verifyDualSignature(keyId, message, classicSig, pqSigTiny, alice));
    }

    function test_verifyDualSig_returnsFalseOnEmptyPQSig() public {
        bytes memory message = "test message";
        bytes memory pqSig   = bytes("");

        bytes32 digest = keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x01),
            registry.domainSeparator(),
            keccak256(message)
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivKey, digest);
        bytes memory classicSig = abi.encodePacked(r, s, v);

        assertFalse(registry.verifyDualSignature(keyId, message, classicSig, pqSig, alice));
    }

    function test_verifyDualSig_returnsTrueWhenBothValid() public {
        bytes memory message = "Hello, post-quantum world!";
        bytes memory pqSig   = MockPQKey.generateProof(PQAlgorithms.ML_DSA_65);

        bytes32 digest = keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x01),
            registry.domainSeparator(),
            keccak256(message)
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivKey, digest);
        bytes memory classicSig = abi.encodePacked(r, s, v);

        assertTrue(registry.verifyDualSignature(keyId, message, classicSig, pqSig, alice));
    }

    function test_verifyDualSig_returnsFalseForKEMKey() public {
        // Register a KEM key and try to use it for dual-sign
        bytes memory kemPk = MockPQKey.generate(PQAlgorithms.ML_KEM_768);
        vm.prank(alice);
        bytes32 kemKeyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_KEM_768, IERCWWWW.KeyPurpose.ENCAPSULATION, kemPk, 0
        );
        vm.prank(alice);
        registry.activateKey(kemKeyId);

        bytes memory message = "test";
        bytes memory pqSig   = new bytes(1184); // ML-KEM-768 pk size, not a sig size

        bytes32 digest = keccak256(abi.encodePacked(
            bytes1(0x19), bytes1(0x01),
            registry.domainSeparator(),
            keccak256(message)
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivKey, digest);
        bytes memory classicSig = abi.encodePacked(r, s, v);

        // KEM key has no expectedSignatureSize → returns false
        assertFalse(registry.verifyDualSignature(kemKeyId, message, classicSig, pqSig, alice));
    }

    // ─── ERC-165 ──────────────────────────────────────────────────────────────

    function test_supportsInterface_dualSign() public view {
        assertTrue(registry.supportsInterface(type(IERCWWWW_DualSign).interfaceId));
        assertTrue(registry.supportsInterface(type(IERCWWWW).interfaceId));
        assertTrue(registry.supportsInterface(0x01ffc9a7)); // ERC-165
    }
}
