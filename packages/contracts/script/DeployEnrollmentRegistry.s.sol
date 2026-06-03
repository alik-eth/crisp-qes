// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";

/// @notice Deploy EnrollmentRegistry to the local anvil for the identity E2E.
/// The OPRF service signs updateRoot with V3_ATTESTER_KEY; its derived address
/// MUST equal ENROLL_ATTESTER here, and genesisRoot MUST equal the service's
/// depth-20 zero-tree root (service/merkle.mjs).
/// Usage:
///   ENROLL_ATTESTER=0xbcD7... \
///   ENROLL_GENESIS_ROOT=0x1b49e706af69da35927cdf2b28b02fb2647245ac0ccbc376d062031185d3cd84 \
///   forge script script/DeployEnrollmentRegistry.s.sol \
///     --rpc-url <anvil> --private-key <key> --broadcast
contract DeployEnrollmentRegistry is Script {
    function run() external returns (EnrollmentRegistry reg) {
        address attester = vm.envAddress("ENROLL_ATTESTER");
        bytes32 genesisRoot = vm.envBytes32("ENROLL_GENESIS_ROOT");
        uint256 genesisLeafCount = vm.envOr("ENROLL_GENESIS_LEAFCOUNT", uint256(0));
        vm.startBroadcast();
        // admin = msg.sender (deployer keeps the attester-rotation lever).
        reg = new EnrollmentRegistry(attester, genesisRoot, genesisLeafCount, msg.sender);
        vm.stopBroadcast();
        require(address(reg) != address(0), "deploy failed");
        console.log("EnrollmentRegistry deployed:", address(reg));
        console.log("oprfAttester:", attester);
        console.logBytes32(genesisRoot);
    }
}
