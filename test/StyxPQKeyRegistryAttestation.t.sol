// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StyxPQKeyRegistryAttestation} from "../src/extensions/StyxPQKeyRegistryAttestation.sol";
import {IERCWWWW} from "../src/interfaces/IERCWWWW.sol";
import {
    IERCWWWW_Attestation,
    ATT_HSM_GENERATED,
    ATT_FIPS_VALIDATED,
    ATT_AUDITED
} from "../src/interfaces/IERCWWWW_Attestation.sol";
import {PQAlgorithms} from "../src/libraries/PQAlgorithms.sol";
import {MockPQKey} from "./mocks/MockPQKey.sol";

contract StyxPQKeyRegistryAttestationTest is Test {
    StyxPQKeyRegistryAttestation public registry;

    address internal alice   = makeAddr("alice");
    address internal auditor = makeAddr("auditor");

    bytes32 internal keyId;

    function setUp() public {
        registry = new StyxPQKeyRegistryAttestation(100, 1);

        bytes memory pk = MockPQKey.generate(PQAlgorithms.ML_DSA_65);
        vm.prank(alice);
        keyId = registry.registerPQKey(
            alice, PQAlgorithms.ML_DSA_65, IERCWWWW.KeyPurpose.SIGNATURE, pk, 0
        );
    }

    function test_attestKey_basic() public {
        bytes memory attestData = abi.encode("HSM model: Thales Luna 7");

        vm.prank(auditor);
        vm.expectEmit(true, true, true, false);
        emit IERCWWWW_Attestation.KeyAttested(
            keyId, auditor, ATT_HSM_GENERATED
        );
        registry.attestKey(keyId, ATT_HSM_GENERATED, attestData);
    }

    function test_hasAttestation() public {
        assertFalse(registry.hasAttestation(keyId, ATT_HSM_GENERATED));

        vm.prank(auditor);
        registry.attestKey(keyId, ATT_HSM_GENERATED, "");

        assertTrue(registry.hasAttestation(keyId, ATT_HSM_GENERATED));
        assertFalse(registry.hasAttestation(keyId, ATT_FIPS_VALIDATED));
    }

    function test_attestationsOf() public {
        bytes memory d1 = "HSM attestation";
        bytes memory d2 = "FIPS certificate #12345";

        vm.prank(auditor);
        registry.attestKey(keyId, ATT_HSM_GENERATED, d1);
        vm.prank(auditor);
        registry.attestKey(keyId, ATT_FIPS_VALIDATED, d2);

        IERCWWWW_Attestation.Attestation[] memory atts = registry.attestationsOf(keyId);
        assertEq(atts.length, 2);
        assertEq(atts[0].attestationType, ATT_HSM_GENERATED);
        assertEq(atts[0].attester, auditor);
        assertEq(atts[1].attestationType, ATT_FIPS_VALIDATED);
    }

    function test_attestKey_revertKeyNotFound() public {
        bytes32 fakeId = keccak256("nonexistent");
        vm.prank(auditor);
        vm.expectRevert(abi.encodeWithSelector(IERCWWWW.KeyNotFound.selector, fakeId));
        registry.attestKey(fakeId, ATT_AUDITED, "");
    }

    function test_supportsInterface_attestation() public view {
        assertTrue(registry.supportsInterface(type(IERCWWWW_Attestation).interfaceId));
        assertTrue(registry.supportsInterface(type(IERCWWWW).interfaceId));
        assertTrue(registry.supportsInterface(0x01ffc9a7)); // ERC-165
    }
}
