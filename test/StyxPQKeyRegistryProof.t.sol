// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StyxPQKeyRegistry} from "../src/StyxPQKeyRegistry.sol";
import {IERCWWWW} from "../src/interfaces/IERCWWWW.sol";
import {PQAlgorithms} from "../src/libraries/PQAlgorithms.sol";
import {MockPQKey} from "./mocks/MockPQKey.sol";

/// @notice Tests for registerPQKeyWithProof, proofHash, and admin configuration.
contract StyxPQKeyRegistryProofTest is Test {
    StyxPQKeyRegistry public registry;

    address internal alice = makeAddr("alice");
    address internal bob   = makeAddr("bob");

    function setUp() public {
        registry = new StyxPQKeyRegistry(100, 1);
    }

    // ─── registerPQKeyWithProof — happy paths ─────────────────────────────────

    function test_registerWithProof_signatureAlgo() public {
        bytes memory pk    = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        bytes memory proof = MockPQKey.generateProof(PQAlgorithms.ML_DSA_65);
        assertEq(proof.length, 3309); // ML-DSA-65 signature size

        vm.prank(alice);
        bytes32 keyId = registry.registerPQKeyWithProof(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE,
            pk, 0, proof
        );

        // Proof hash must be stored
        assertEq(registry.proofHash(keyId), keccak256(proof));
    }

    function test_registerWithProof_kemAlgo() public {
        bytes memory pk    = MockPQKey.generate(PQAlgorithms.ML_KEM_768);
        bytes memory proof = MockPQKey.generateKEMProof(); // 32-byte shared secret
        assertEq(proof.length, 32);

        vm.prank(alice);
        bytes32 keyId = registry.registerPQKeyWithProof(
            alice, PQAlgorithms.ML_KEM_768, IERCWWWW.KeyPurpose.ENCAPSULATION,
            pk, 0, proof
        );

        assertEq(registry.proofHash(keyId), keccak256(proof));
    }

    function test_registerWithProof_slhDsa() public {
        bytes memory pk    = MockPQKey.generate(PQAlgorithms.SLH_DSA_256);
        bytes memory proof = MockPQKey.generateProof(PQAlgorithms.SLH_DSA_256);
        assertEq(proof.length, 29792); // SLH-DSA-256 minimum sig size

        vm.prank(alice);
        bytes32 keyId = registry.registerPQKeyWithProof(
            alice, PQAlgorithms.SLH_DSA_256, IERCWWWW.KeyPurpose.SIGNATURE,
            pk, 0, proof
        );

        assertEq(registry.proofHash(keyId), keccak256(proof));
    }

    // ─── registerPQKeyWithProof — reverts ─────────────────────────────────────

    function test_registerWithProof_revertEmptyProof() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.InvalidProofOfPossession.selector, bytes32(0)
        ));
        registry.registerPQKeyWithProof(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE,
            pk, 0, bytes("")
        );
    }

    function test_registerWithProof_revertProofTooSmall_mlDsa() public {
        bytes memory pk    = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        bytes memory proof = MockPQKey.generateTooSmallProof(PQAlgorithms.ML_DSA_65);
        // proof.length = 3308 (one byte short of 3309)

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.InvalidProofOfPossession.selector, bytes32(0)
        ));
        registry.registerPQKeyWithProof(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE,
            pk, 0, proof
        );
    }

    function test_registerWithProof_revertProofTooSmall_kemAlgo() public {
        bytes memory pk    = MockPQKey.generate(PQAlgorithms.ML_KEM_512);
        bytes memory proof = new bytes(31); // 31 bytes — too small for 32-byte shared secret

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.InvalidProofOfPossession.selector, bytes32(0)
        ));
        registry.registerPQKeyWithProof(
            alice, PQAlgorithms.ML_KEM_512, IERCWWWW.KeyPurpose.ENCAPSULATION,
            pk, 0, proof
        );
    }

    // ─── proofHash — no proof registered ─────────────────────────────────────

    function test_proofHash_zeroForBasicRegistration() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.prank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );

        // No proof stored — returns zero
        assertEq(registry.proofHash(keyId), bytes32(0));
    }

    function test_proofHash_revertKeyNotFound() public {
        bytes32 fakeId = keccak256("nonexistent");
        vm.expectRevert(abi.encodeWithSelector(IERCWWWW.KeyNotFound.selector, fakeId));
        registry.proofHash(fakeId);
    }

    // ─── Admin functions — events ─────────────────────────────────────────────

    function test_setMaxKeysPerOwner_emitsEvent() public {
        uint256 oldMax = registry.maxKeysPerOwner();
        uint256 newMax = 50;

        vm.expectEmit(false, false, false, true);
        emit IERCWWWW.MaxKeysPerOwnerUpdated(oldMax, newMax);
        registry.setMaxKeysPerOwner(newMax);

        assertEq(registry.maxKeysPerOwner(), newMax);
    }

    function test_setMinNistLevel_emitsEvent() public {
        uint256 oldLevel = registry.minNistLevel();
        uint256 newLevel = 3;

        vm.expectEmit(false, false, false, true);
        emit IERCWWWW.MinNistLevelUpdated(oldLevel, newLevel);
        registry.setMinNistLevel(newLevel);

        assertEq(registry.minNistLevel(), newLevel);
    }

    function test_adminFunctions_rejectNonAdmin() public {
        vm.prank(alice);
        vm.expectRevert(); // AccessControl: account does not have role
        registry.setMaxKeysPerOwner(50);

        vm.prank(alice);
        vm.expectRevert();
        registry.setMinNistLevel(3);
    }

    // ─── Revoking a REGISTERED key (not yet activated) ───────────────────────

    function test_revokeRegisteredKey() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
        assertEq(uint8(registry.keyInfo(keyId).state), uint8(IERCWWWW.KeyState.REGISTERED));

        // Revoke without ever activating — should work
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.OWNER_REQUEST);
        vm.stopPrank();

        assertEq(uint8(registry.keyInfo(keyId).state), uint8(IERCWWWW.KeyState.REVOKED));
        assertFalse(registry.isKeyUsable(keyId));
    }

    // ─── DUAL purpose keys ────────────────────────────────────────────────────

    function test_dualPurpose_signatureAlgo() public {
        // ML-DSA with DUAL purpose is allowed
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_87);
        vm.prank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_87, IERCWWWW.KeyPurpose.DUAL, pk, 0
        );

        assertEq(uint8(registry.keyInfo(keyId).purpose), uint8(IERCWWWW.KeyPurpose.DUAL));
    }

    function test_dualPurpose_kemAlgo() public {
        // ML-KEM with DUAL purpose is allowed
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_KEM_1024);
        vm.prank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_KEM_1024, IERCWWWW.KeyPurpose.DUAL, pk, 0
        );

        assertEq(uint8(registry.keyInfo(keyId).purpose), uint8(IERCWWWW.KeyPurpose.DUAL));
    }

    // ─── Fuzz: register with any-length proof ≥ expected → always passes size check ──

    function testFuzz_registerWithProof_sufficientProof(uint16 extraBytes) public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_44);
        uint256 minSize = PQAlgorithms.expectedProofSize(PQAlgorithms.ML_DSA_44);

        // proof = minSize + extraBytes (never under-sized)
        bytes memory proof = new bytes(minSize + uint256(extraBytes));

        vm.prank(alice);
        bytes32 keyId = registry.registerPQKeyWithProof(
            alice, PQAlgorithms.ML_DSA_44, IERCWWWW.KeyPurpose.SIGNATURE,
            pk, 0, proof
        );

        assertEq(registry.proofHash(keyId), keccak256(proof));
    }

    function testFuzz_registerWithProof_insufficientProof(uint16 deficit) public {
        vm.assume(deficit > 0);
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_44);
        uint256 minSize = PQAlgorithms.expectedProofSize(PQAlgorithms.ML_DSA_44);
        vm.assume(deficit <= minSize);

        bytes memory proof = new bytes(minSize - uint256(deficit));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.InvalidProofOfPossession.selector, bytes32(0)
        ));
        registry.registerPQKeyWithProof(
            alice, PQAlgorithms.ML_DSA_44, IERCWWWW.KeyPurpose.SIGNATURE,
            pk, 0, proof
        );
    }
}
