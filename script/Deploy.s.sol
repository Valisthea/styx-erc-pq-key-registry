// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {StyxPQKeyRegistryAttestation} from "../src/extensions/StyxPQKeyRegistryAttestation.sol";

/// @notice Deployment script for the Styx PQ Key Registry with Attestation extension.
///         Target: Base Sepolia testnet.
///
///         Usage:
///           forge script script/Deploy.s.sol:Deploy \
///             --rpc-url base_sepolia \
///             --broadcast \
///             --verify \
///             -vvvv
///
///         Required env vars:
///           PRIVATE_KEY         — deployer private key (without 0x prefix)
///           BASE_SEPOLIA_RPC_URL
///           BASESCAN_API_KEY
contract Deploy is Script {
    /// @dev maxKeysPerOwner = 100, minNistLevel = 3 (production recommended)
    uint256 constant MAX_KEYS  = 100;
    uint256 constant MIN_LEVEL = 3;

    function run() external returns (StyxPQKeyRegistryAttestation registry) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer    = vm.addr(deployerKey);

        console.log("Deployer  :", deployer);
        console.log("Chain ID  :", block.chainid);

        vm.startBroadcast(deployerKey);
        registry = new StyxPQKeyRegistryAttestation(MAX_KEYS, MIN_LEVEL);
        vm.stopBroadcast();

        console.log("Registry  :", address(registry));
        console.log("maxKeys   :", MAX_KEYS);
        console.log("minLevel  :", MIN_LEVEL);
    }
}
