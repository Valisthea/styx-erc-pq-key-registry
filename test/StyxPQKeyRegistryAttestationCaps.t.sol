// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StyxPQKeyRegistryAttestation} from "../src/extensions/StyxPQKeyRegistryAttestation.sol";
import {IERCWWWW} from "../src/interfaces/IERCWWWW.sol";
import {
    IERCWWWW_Attestation,
    ATT_HSM_GENERATED,
    ATT_FIPS_VALIDATED,
    ATT_AUDITED,
    ATT_ENTROPY_PROOF,
    MAX_ATTESTATIONS_PER_KEY,
    MAX_ATTESTATION_DATA_SIZE
} from "../src/interfaces/IERCWWWW_Attestation.sol";
import {PQAlgorithms} from "../src/libraries/PQAlgorithms.sol";
import {MockPQKey} from "./mocks/MockPQKey.sol";

contract StyxPQKeyRegistryAttestationCapsTest is Test {
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

    // ─── Attestation cap ─────────────────────────────────────────────────────

    function test_attestationCap_rejectsAt21() public {
        // Fill up to the cap (20)
        for (uint256 i = 0; i < MAX_ATTESTATIONS_PER_KEY; i++) {
            bytes4 customType = bytes4(uint32(i + 1));
            vm.prank(auditor);
            registry.attestKey(keyId, customType, "");
        }
        assertEq(registry.attestationsOf(keyId).length, MAX_ATTESTATIONS_PER_KEY);

        // 21st attestation must revert
        vm.prank(auditor);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW_Attestation.AttestationLimitReached.selector,
            keyId,
            MAX_ATTESTATIONS_PER_KEY
        ));
        registry.attestKey(keyId, ATT_HSM_GENERATED, "");
    }

    // ─── Data size cap ────────────────────────────────────────────────────────

    function test_attestationDataCap_exactlyMax_passes() public {
        bytes memory data = new bytes(MAX_ATTESTATION_DATA_SIZE); // exactly 1024 bytes
        vm.prank(auditor);
        registry.attestKey(keyId, ATT_HSM_GENERATED, data);
        assertEq(registry.attestationsOf(keyId).length, 1);
    }

    function test_attestationDataCap_overMax_reverts() public {
        bytes memory data = new bytes(MAX_ATTESTATION_DATA_SIZE + 1); // 1025 bytes
        vm.prank(auditor);
        vm.expectRevert(abi.encodeWithSelector(
            IERCWWWW_Attestation.AttestationDataTooLarge.selector,
            MAX_ATTESTATION_DATA_SIZE + 1,
            MAX_ATTESTATION_DATA_SIZE
        ));
        registry.attestKey(keyId, ATT_HSM_GENERATED, data);
    }

    // ─── Paginated attestations ───────────────────────────────────────────────

    function test_attestationsOfPaginated_basic() public {
        vm.prank(auditor);
        registry.attestKey(keyId, ATT_HSM_GENERATED, "data1");
        vm.prank(auditor);
        registry.attestKey(keyId, ATT_FIPS_VALIDATED, "data2");
        vm.prank(auditor);
        registry.attestKey(keyId, ATT_AUDITED, "data3");

        // First page: offset=0, limit=2 → 2 entries
        (IERCWWWW_Attestation.Attestation[] memory page, uint256 total) =
            registry.attestationsOfPaginated(keyId, 0, 2);
        assertEq(total, 3);
        assertEq(page.length, 2);
        assertEq(page[0].attestationType, ATT_HSM_GENERATED);
        assertEq(page[1].attestationType, ATT_FIPS_VALIDATED);

        // Second page: offset=2, limit=10 → 1 entry (clamped)
        (IERCWWWW_Attestation.Attestation[] memory tail, uint256 total2) =
            registry.attestationsOfPaginated(keyId, 2, 10);
        assertEq(total2, 3);
        assertEq(tail.length, 1);
        assertEq(tail[0].attestationType, ATT_AUDITED);
    }

    function test_attestationsOfPaginated_emptyWhenOffsetGtTotal() public {
        vm.prank(auditor);
        registry.attestKey(keyId, ATT_HSM_GENERATED, "");

        (IERCWWWW_Attestation.Attestation[] memory page, uint256 total) =
            registry.attestationsOfPaginated(keyId, 10, 5);
        assertEq(total, 1);
        assertEq(page.length, 0);
    }

    function test_attestationsOfPaginated_emptyWhenLimitZero() public {
        vm.prank(auditor);
        registry.attestKey(keyId, ATT_HSM_GENERATED, "");

        (IERCWWWW_Attestation.Attestation[] memory page, uint256 total) =
            registry.attestationsOfPaginated(keyId, 0, 0);
        assertEq(total, 1);
        assertEq(page.length, 0);
    }

    // ─── Fuzz: data size at boundary ─────────────────────────────────────────

    function testFuzz_attestKey_dataSize(uint16 size) public {
        bytes memory data = new bytes(size);
        if (size <= MAX_ATTESTATION_DATA_SIZE) {
            vm.prank(auditor);
            registry.attestKey(keyId, ATT_ENTROPY_PROOF, data);
            assertEq(registry.attestationsOf(keyId).length, 1);
        } else {
            vm.prank(auditor);
            vm.expectRevert(abi.encodeWithSelector(
                IERCWWWW_Attestation.AttestationDataTooLarge.selector,
                uint256(size),
                MAX_ATTESTATION_DATA_SIZE
            ));
            registry.attestKey(keyId, ATT_ENTROPY_PROOF, data);
        }
    }
}
