// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StyxPQKeyRegistry} from "../src/StyxPQKeyRegistry.sol";
import {IERCWWWW} from "../src/interfaces/IERCWWWW.sol";
import {PQAlgorithms} from "../src/libraries/PQAlgorithms.sol";
import {MockPQKey} from "./mocks/MockPQKey.sol";

/// @notice Edge case and attack vector tests for StyxPQKeyRegistry.
contract StyxPQKeyRegistryEdgeCasesTest is Test {
    StyxPQKeyRegistry public registry;

    address internal alice = makeAddr("alice");
    address internal bob   = makeAddr("bob");

    function setUp() public {
        registry = new StyxPQKeyRegistry(100, 1);
    }

    // ─── Authorization checks ─────────────────────────────────────────────────

    function test_cannotActivateOthersKey() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.prank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.UnauthorizedKeyOwner.selector, bob, alice
        ));
        registry.activateKey(keyId);
    }

    function test_cannotRevokeOthersKey() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.prank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
        vm.prank(alice);
        registry.activateKey(keyId);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.UnauthorizedKeyOwner.selector, bob, alice
        ));
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.GOVERNANCE_ACTION);
    }

    function test_cannotRotateAcrossOwners() public {
        bytes memory pkA = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        bytes memory pkB = MockPQKey.generateAlt(PQAlgorithms.ML_DSA_65);

        vm.prank(alice);
        bytes32 aliceKeyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pkA, 0
        );
        vm.prank(alice);
        registry.activateKey(aliceKeyId);

        vm.prank(bob);
        bytes32 bobKeyId = registry.registerPQKey(
            bob, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pkB, 0
        );

        // Alice tries to rotate her key to Bob's — should fail (Bob's key owned by Bob)
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.UnauthorizedKeyOwner.selector, alice, bob
        ));
        registry.rotateKey(aliceKeyId, bobKeyId);
    }

    function test_cannotRotateDifferentAlgorithm() public {
        bytes memory pk65 = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        bytes memory pk87 = MockPQKey.generate(PQAlgorithms.ML_DSA_87);

        vm.startPrank(alice);
        bytes32 key65 = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk65, 0
        );
        registry.activateKey(key65);

        bytes32 key87 = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_87, IERCWWWW.KeyPurpose.SIGNATURE, pk87, 0
        );

        // Different algorithms — should revert
        vm.expectRevert();
        registry.rotateKey(key65, key87);
        vm.stopPrank();
    }

    // ─── State validation ─────────────────────────────────────────────────────

    function test_revokedKeyNotUsable() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
        registry.activateKey(keyId);
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.KEY_COMPROMISED);
        vm.stopPrank();

        assertFalse(registry.isKeyUsable(keyId));
        assertEq(uint8(registry.keyInfo(keyId).state), uint8(IERCWWWW.KeyState.REVOKED));
    }

    function test_expiredKeyNotUsable() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 100
        );
        registry.activateKey(keyId);
        vm.stopPrank();

        assertTrue(registry.isKeyUsable(keyId));
        vm.warp(block.timestamp + 101);
        assertFalse(registry.isKeyUsable(keyId));
    }

    function test_rotatedKeyStillVerifiable() public {
        bytes memory pk1 = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        bytes memory pk2 = MockPQKey.generateAlt(PQAlgorithms.ML_DSA_65);

        vm.startPrank(alice);
        bytes32 keyId1 = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk1, 0
        );
        registry.activateKey(keyId1);

        bytes32 keyId2 = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk2, 0
        );
        registry.rotateKey(keyId1, keyId2);
        vm.stopPrank();

        // Rotated key: not usable for new ops but still queryable
        assertFalse(registry.isKeyUsable(keyId1));
        assertEq(uint8(registry.keyInfo(keyId1).state), uint8(IERCWWWW.KeyState.ROTATED));

        // Public key still accessible for historical signature verification
        bytes memory stored = registry.publicKeyOf(keyId1);
        assertEq(stored, pk1);
    }

    // ─── Key ID determinism ───────────────────────────────────────────────────

    function test_keyIdDeterministic() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);

        // Compute expected keyId off-chain
        bytes32 expectedId = keccak256(abi.encode(
            block.chainid,
            address(registry),
            alice,
            PQAlgorithms.ML_DSA_65,
            keccak256(pk)
        ));

        vm.prank(alice);
        bytes32 registeredId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );

        assertEq(registeredId, expectedId);

        // Second call with same inputs → same keyId → reverts with KeyAlreadyRegistered
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.KeyAlreadyRegistered.selector, expectedId
        ));
        registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
    }

    function test_keyIdDifferentChain() public view {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);

        // Key ID for current chain (31337 in Foundry)
        bytes32 keyId1 = keccak256(abi.encode(
            block.chainid,
            address(registry),
            alice,
            PQAlgorithms.ML_DSA_65,
            keccak256(pk)
        ));

        // Key ID for mainnet (chainId 1) — different chain → different keyId
        bytes32 keyId2 = keccak256(abi.encode(
            uint256(1),
            address(registry),
            alice,
            PQAlgorithms.ML_DSA_65,
            keccak256(pk)
        ));

        assertNotEq(keyId1, keyId2);
    }

    // ─── Double-action reverts ────────────────────────────────────────────────

    function test_doubleActivateReverts() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
        registry.activateKey(keyId);

        // Now key is ACTIVE, not REGISTERED — activateKey should revert
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.KeyNotActive.selector, keyId, IERCWWWW.KeyState.ACTIVE
        ));
        registry.activateKey(keyId);
        vm.stopPrank();
    }

    function test_revokeAlreadyRevokedReverts() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
        registry.activateKey(keyId);
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.OWNER_REQUEST);

        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.KeyAlreadyRevoked.selector, keyId
        ));
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.OWNER_REQUEST);
        vm.stopPrank();
    }
}
