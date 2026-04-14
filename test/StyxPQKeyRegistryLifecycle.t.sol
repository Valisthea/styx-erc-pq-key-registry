// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StyxPQKeyRegistry} from "../src/StyxPQKeyRegistry.sol";
import {IERCWWWW} from "../src/interfaces/IERCWWWW.sol";
import {PQAlgorithms} from "../src/libraries/PQAlgorithms.sol";
import {MockPQKey} from "./mocks/MockPQKey.sol";

/// @notice Full lifecycle and multi-step sequence tests.
contract StyxPQKeyRegistryLifecycleTest is Test {
    StyxPQKeyRegistry public registry;

    address internal alice = makeAddr("alice");

    function setUp() public {
        registry = new StyxPQKeyRegistry(100, 1);
    }

    // ─── Full lifecycle ───────────────────────────────────────────────────────

    function test_fullLifecycle_registerActivateRotateRevoke() public {
        bytes memory pkA = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        bytes memory pkB = MockPQKey.generateAlt(PQAlgorithms.ML_DSA_65);

        vm.startPrank(alice);

        // 1. Register key A
        bytes32 keyA = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pkA, 0
        );
        assertEq(uint8(registry.keyInfo(keyA).state), uint8(IERCWWWW.KeyState.REGISTERED));

        // 2. Activate key A
        registry.activateKey(keyA);
        assertEq(uint8(registry.keyInfo(keyA).state), uint8(IERCWWWW.KeyState.ACTIVE));
        assertTrue(registry.isKeyUsable(keyA));

        // 3. Register & rotate to key B
        bytes32 keyB = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pkB, 0
        );
        registry.rotateKey(keyA, keyB);
        assertEq(uint8(registry.keyInfo(keyA).state), uint8(IERCWWWW.KeyState.ROTATED));
        assertEq(uint8(registry.keyInfo(keyB).state), uint8(IERCWWWW.KeyState.ACTIVE));
        assertFalse(registry.isKeyUsable(keyA));
        assertTrue(registry.isKeyUsable(keyB));

        // 4. Revoke key B
        registry.revokeKey(keyB, IERCWWWW.RevocationReason.KEY_COMPROMISED);
        assertEq(uint8(registry.keyInfo(keyB).state), uint8(IERCWWWW.KeyState.REVOKED));
        assertFalse(registry.isKeyUsable(keyB));
        assertEq(registry.activeKeyFor(alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE), bytes32(0));

        vm.stopPrank();
    }

    // ─── Rotation chain — depth 3 ─────────────────────────────────────────────

    function test_rotationChain_3deep() public {
        bytes memory pkA = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        bytes memory pkB = MockPQKey.generateAlt(PQAlgorithms.ML_DSA_65);
        bytes memory pkC = MockPQKey.generateThird(PQAlgorithms.ML_DSA_65);

        vm.startPrank(alice);

        bytes32 keyA = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pkA, 0
        );
        registry.activateKey(keyA);

        bytes32 keyB = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pkB, 0
        );
        registry.rotateKey(keyA, keyB);

        bytes32 keyC = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pkC, 0
        );
        registry.rotateKey(keyB, keyC);

        vm.stopPrank();

        // rotationChain from root → [A, B, C]
        bytes32[] memory chainFromA = registry.rotationChain(keyA);
        assertEq(chainFromA.length, 3);
        assertEq(chainFromA[0], keyA);
        assertEq(chainFromA[1], keyB);
        assertEq(chainFromA[2], keyC);

        // rotationChain from middle key B → should also return [A, B, C]
        bytes32[] memory chainFromB = registry.rotationChain(keyB);
        assertEq(chainFromB.length, 3);
        assertEq(chainFromB[0], keyA);
        assertEq(chainFromB[1], keyB);
        assertEq(chainFromB[2], keyC);

        // rotationChain from latest key C → [A, B, C]
        bytes32[] memory chainFromC = registry.rotationChain(keyC);
        assertEq(chainFromC.length, 3);
        assertEq(chainFromC[0], keyA);
        assertEq(chainFromC[2], keyC);
    }

    // ─── Multiple algorithms per owner ────────────────────────────────────────

    function test_multipleAlgorithmsPerOwner() public {
        bytes memory kyber  = MockPQKey.generate(PQAlgorithms.ML_KEM_1024);
        bytes memory dilith = MockPQKey.generate(PQAlgorithms.ML_DSA_87);
        bytes memory sphincs = MockPQKey.generate(PQAlgorithms.SLH_DSA_256);

        vm.startPrank(alice);

        bytes32 kemId = registry.registerPQKey(
            alice, PQAlgorithms.ML_KEM_1024, IERCWWWW.KeyPurpose.ENCAPSULATION, kyber, 0
        );
        bytes32 dsaId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_87, IERCWWWW.KeyPurpose.SIGNATURE, dilith, 0
        );
        bytes32 slhId = registry.registerPQKey(
            alice, PQAlgorithms.SLH_DSA_256, IERCWWWW.KeyPurpose.SIGNATURE, sphincs, 0
        );

        registry.activateKey(kemId);
        registry.activateKey(dsaId);
        registry.activateKey(slhId);
        vm.stopPrank();

        // All three active independently
        assertTrue(registry.isKeyUsable(kemId));
        assertTrue(registry.isKeyUsable(dsaId));
        assertTrue(registry.isKeyUsable(slhId));

        // Active lookups are independent per algorithm+purpose
        assertEq(
            registry.activeKeyFor(alice, PQAlgorithms.ML_KEM_1024, IERCWWWW.KeyPurpose.ENCAPSULATION),
            kemId
        );
        assertEq(
            registry.activeKeyFor(alice, PQAlgorithms.ML_DSA_87, IERCWWWW.KeyPurpose.SIGNATURE),
            dsaId
        );
        assertEq(
            registry.activeKeyFor(alice, PQAlgorithms.SLH_DSA_256, IERCWWWW.KeyPurpose.SIGNATURE),
            slhId
        );

        // All 3 in owner list
        assertEq(registry.keyCountOf(alice), 3);
    }
}
