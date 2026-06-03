// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {BallotRegistry} from "../src/BallotRegistry.sol";

/// @notice Deploy BallotRegistry to the operator chain (the Fly anvil).
/// Usage:
///   BALLOT_OPERATOR=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
///   forge script script/DeployBallotRegistry.s.sol \
///     --rpc-url <operator-rpc> --private-key <operator-key> --broadcast
contract DeployBallotRegistry is Script {
    function run() external returns (BallotRegistry reg) {
        address operator = vm.envAddress("BALLOT_OPERATOR");
        vm.startBroadcast();
        reg = new BallotRegistry(operator);
        vm.stopBroadcast();
        require(address(reg) != address(0), "deploy failed");
        console.log("BallotRegistry deployed:", address(reg));
        console.log("operator:", operator);
    }
}
