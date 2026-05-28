// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {UltraVerifier} from "../src/UltraVerifier.sol";
import {PetitionRegistry} from "../src/PetitionRegistry.sol";

contract Deploy is Script {
    function run() external returns (PetitionRegistry registry, UltraVerifier verifier) {
        bytes32 trustRoot = vm.envBytes32("DIIA_TRUST_ROOT");
        vm.startBroadcast();
        verifier = new UltraVerifier();
        registry = new PetitionRegistry(IVerifier(address(verifier)), trustRoot);
        vm.stopBroadcast();
        console.log("UltraVerifier:    ", address(verifier));
        console.log("PetitionRegistry: ", address(registry));
    }
}
