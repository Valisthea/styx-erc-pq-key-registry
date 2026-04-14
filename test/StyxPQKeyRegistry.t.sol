// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StyxPQKeyRegistry} from "../src/StyxPQKeyRegistry.sol";
import {IERCWWWW} from "../src/interfaces/IERCWWWW.sol";
import {PQAlgorithms} from "../src/libraries/PQAlgorithms.sol";
import {MockPQKey} from "./mocks/MockPQKey.sol";

contract StyxPQKeyRegistryTest is Test {
    StyxPQKeyRegistry public registry;

    address internal alice = makeAddr("alice");
    address internal bob   = makeAddr("bob");

    function setUp() public {
        registry = new StyxPQKeyRegistry({
            maxKeysPerOwner_: 100,
            minNistLevel_: 1       // Level 1 for test flexibility
        });
    }

    // ─── Registration — Happy Paths ───────────────────────────────────────────

    function test_registerKey_ML_DSA_65() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        bytes32 expectedKeyId = keccak256(abi.encode(
            block.chainid, address(registry), alice,
            PQAlgorithms.ML_DSA_65, keccak256(pk)
        ));

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IERCWWWW.PQKeyRegistered(
            expectedKeyId, alice, PQAlgorithms.ML_DSA_65,
            IERCWWWW.KeyPurpose.SIGNATURE, 3
        );
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );

        assertEq(keyId, expectedKeyId);

        IERCWWWW.PQKeyInfo memory info = registry.keyInfo(keyId);
        assertEq(info.owner, alice);
        assertEq(info.algorithm, PQAlgorithms.ML_DSA_65);
        assertEq(uint8(info.purpose), uint8(IERCWWWW.KeyPurpose.SIGNATURE));
        assertEq(uint8(info.state), uint8(IERCWWWW.KeyState.REGISTERED));
        assertEq(info.nistLevel, 3);
        assertEq(info.expiresAt, 0);
        assertEq(info.registeredAt, block.timestamp);

        bytes memory storedPk = registry.publicKeyOf(keyId);
        assertEq(storedPk, pk);
    }

    function test_registerKey_ML_KEM_1024() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_KEM_1024);
        vm.prank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_KEM_1024, IERCWWWW.KeyPurpose.ENCAPSULATION, pk, 0
        );

        IERCWWWW.PQKeyInfo memory info = registry.keyInfo(keyId);
        assertEq(info.algorithm, PQAlgorithms.ML_KEM_1024);
        assertEq(uint8(info.purpose), uint8(IERCWWWW.KeyPurpose.ENCAPSULATION));
        assertEq(info.nistLevel, 5);
    }

    function test_registerKey_SLH_DSA_256() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.SLH_DSA_256);
        vm.prank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.SLH_DSA_256, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );

        IERCWWWW.PQKeyInfo memory info = registry.keyInfo(keyId);
        assertEq(info.algorithm, PQAlgorithms.SLH_DSA_256);
        assertEq(info.nistLevel, 5);
        assertEq(pk.length, 64);
    }

    // ─── Registration — Reverts ───────────────────────────────────────────────

    function test_registerKey_revertInvalidSize() public {
        bytes memory badPk = MockPQKey.generateWrongSize(PQAlgorithms.ML_DSA_65);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.InvalidPublicKeyFormat.selector,
            PQAlgorithms.ML_DSA_65,
            uint256(1952),
            uint256(1951)
        ));
        registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, badPk, 0
        );
    }

    function test_registerKey_revertUnsupportedAlgo() public {
        bytes4 unknown = 0xDEADBEEF;
        bytes memory pk = new bytes(100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.UnsupportedAlgorithm.selector, unknown
        ));
        registry.registerPQKey(
            alice, unknown, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
    }

    function test_registerKey_revertDuplicate() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.prank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.KeyAlreadyRegistered.selector, keyId
        ));
        registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
    }

    function test_registerKey_revertMaxKeys() public {
        // Set limit to 2
        registry.setMaxKeysPerOwner(2);

        vm.startPrank(alice);
        registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE,
            MockPQKey.generate(PQAlgorithms.ML_DSA_65), 0
        );
        registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_87, IERCWWWW.KeyPurpose.SIGNATURE,
            MockPQKey.generate(PQAlgorithms.ML_DSA_87), 0
        );
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.MaxKeysReached.selector, alice, uint256(2)
        ));
        registry.registerPQKey(
            alice, PQAlgorithms.SLH_DSA_256, IERCWWWW.KeyPurpose.SIGNATURE,
            MockPQKey.generate(PQAlgorithms.SLH_DSA_256), 0
        );
        vm.stopPrank();
    }

    function test_registerKey_revertNistLevelTooLow() public {
        // Deploy with minNistLevel = 3
        StyxPQKeyRegistry r3 = new StyxPQKeyRegistry(100, 3);
        // ML_DSA_44 is NIST Level 2 < 3
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_44);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.NistLevelTooLow.selector, uint256(2), uint256(3)
        ));
        r3.registerPQKey(
            alice, PQAlgorithms.ML_DSA_44, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
    }

    function test_registerKey_revertPurposeMismatch() public {
        // KEM algorithm with SIGNATURE purpose
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_KEM_1024);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW.AlgorithmPurposeMismatch.selector,
            PQAlgorithms.ML_KEM_1024,
            IERCWWWW.KeyPurpose.SIGNATURE
        ));
        registry.registerPQKey(
            alice, PQAlgorithms.ML_KEM_1024, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
    }

    // ─── Activation ──────────────────────────────────────────────────────────

    function test_activateKey() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );

        vm.expectEmit(true, true, false, false);
        emit IERCWWWW.PQKeyActivated(keyId, alice);
        registry.activateKey(keyId);
        vm.stopPrank();

        assertEq(uint8(registry.keyInfo(keyId).state), uint8(IERCWWWW.KeyState.ACTIVE));
        assertEq(registry.activeKeyFor(alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE), keyId);
        assertTrue(registry.isKeyUsable(keyId));
    }

    function test_activateKey_autoRotatesPrevious() public {
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
        // Activating keyId2 should auto-rotate keyId1
        registry.activateKey(keyId2);
        vm.stopPrank();

        assertEq(uint8(registry.keyInfo(keyId1).state), uint8(IERCWWWW.KeyState.ROTATED));
        assertEq(uint8(registry.keyInfo(keyId2).state), uint8(IERCWWWW.KeyState.ACTIVE));
        assertEq(registry.activeKeyFor(alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE), keyId2);
        assertFalse(registry.isKeyUsable(keyId1));
        assertTrue(registry.isKeyUsable(keyId2));
    }

    // ─── Rotation ─────────────────────────────────────────────────────────────

    function test_rotateKey() public {
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

        assertEq(uint8(registry.keyInfo(keyId1).state), uint8(IERCWWWW.KeyState.ROTATED));
        assertEq(uint8(registry.keyInfo(keyId2).state), uint8(IERCWWWW.KeyState.ACTIVE));
        assertEq(registry.keyInfo(keyId1).rotatedTo, keyId2);

        bytes32[] memory chain = registry.rotationChain(keyId1);
        assertEq(chain.length, 2);
        assertEq(chain[0], keyId1);
        assertEq(chain[1], keyId2);
    }

    // ─── Revocation ───────────────────────────────────────────────────────────

    function test_revokeKey() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
        registry.activateKey(keyId);

        vm.expectEmit(true, true, true, false);
        emit IERCWWWW.PQKeyRevoked(keyId, alice, IERCWWWW.RevocationReason.OWNER_REQUEST);
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.OWNER_REQUEST);
        vm.stopPrank();

        assertEq(uint8(registry.keyInfo(keyId).state), uint8(IERCWWWW.KeyState.REVOKED));
        assertFalse(registry.isKeyUsable(keyId));
    }

    function test_revokeKey_activeRemovesFromActive() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
        registry.activateKey(keyId);
        registry.revokeKey(keyId, IERCWWWW.RevocationReason.KEY_COMPROMISED);
        vm.stopPrank();

        bytes32 active = registry.activeKeyFor(alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE);
        assertEq(active, bytes32(0));
    }

    // ─── Expiration ───────────────────────────────────────────────────────────

    function test_keyExpiration() public {
        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        uint256 validity = 1 days;

        vm.startPrank(alice);
        bytes32 keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, validity
        );
        registry.activateKey(keyId);
        vm.stopPrank();

        assertTrue(registry.isKeyUsable(keyId));
        assertEq(registry.keyInfo(keyId).expiresAt, block.timestamp + validity);

        vm.warp(block.timestamp + validity + 1);
        assertFalse(registry.isKeyUsable(keyId));
    }

    // ─── Pagination ───────────────────────────────────────────────────────────

    function test_keysOfPaginated() public {
        bytes4 alg = PQAlgorithms.ML_DSA_65;
        bytes4 alg2 = PQAlgorithms.ML_DSA_87;
        bytes4 alg3 = PQAlgorithms.SLH_DSA_256;
        bytes4 alg4 = PQAlgorithms.ML_KEM_1024;
        bytes4 alg5 = PQAlgorithms.SLH_DSA_128;

        vm.startPrank(alice);
        registry.registerPQKey(alice, alg,  IERCWWWW.KeyPurpose.SIGNATURE,     MockPQKey.generate(alg),  0);
        registry.registerPQKey(alice, alg2, IERCWWWW.KeyPurpose.SIGNATURE,     MockPQKey.generate(alg2), 0);
        bytes32 id2 = registry.registerPQKey(alice, alg3, IERCWWWW.KeyPurpose.SIGNATURE,     MockPQKey.generate(alg3), 0);
        bytes32 id3 = registry.registerPQKey(alice, alg4, IERCWWWW.KeyPurpose.ENCAPSULATION, MockPQKey.generate(alg4), 0);
        bytes32 id4 = registry.registerPQKey(alice, alg5, IERCWWWW.KeyPurpose.SIGNATURE,     MockPQKey.generate(alg5), 0);
        vm.stopPrank();

        (bytes32[] memory page, uint256 total) = registry.keysOfPaginated(alice, 2, 2);
        assertEq(total, 5);
        assertEq(page.length, 2);
        assertEq(page[0], id2);
        assertEq(page[1], id3);

        // Empty page when offset >= total
        (bytes32[] memory empty, uint256 t2) = registry.keysOfPaginated(alice, 10, 5);
        assertEq(t2, 5);
        assertEq(empty.length, 0);

        // Clamp when offset + limit > total
        (bytes32[] memory tail, uint256 t3) = registry.keysOfPaginated(alice, 4, 10);
        assertEq(t3, 5);
        assertEq(tail.length, 1);
        assertEq(tail[0], id4);
    }

    // ─── ERC-165 ──────────────────────────────────────────────────────────────

    function test_supportsInterface() public view {
        bytes4 iface = type(IERCWWWW).interfaceId;
        assertTrue(registry.supportsInterface(iface));
        // ERC-165 itself
        assertTrue(registry.supportsInterface(0x01ffc9a7));
    }
}
