// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {UltraVerifier} from "../src/UltraVerifier.sol";
import {PetitionRegistry} from "../src/PetitionRegistry.sol";

contract Deploy is Script {
    /// @dev Default creation-deposit (0.001 ETH on Base), per spec §7 item 5.
    uint256 internal constant DEFAULT_CREATION_DEPOSIT = 0.001 ether;

    function run() external returns (PetitionRegistry registry, UltraVerifier verifier) {
        bytes32 trustRoot = vm.envBytes32("DIIA_TRUST_ROOT");
        uint256 creationDeposit = vm.envOr("CREATION_DEPOSIT_WEI", DEFAULT_CREATION_DEPOSIT);

        vm.startBroadcast();
        verifier = new UltraVerifier();
        registry = new PetitionRegistry(
            IVerifier(address(verifier)), trustRoot, creationDeposit
        );
        vm.stopBroadcast();
        console.log("UltraVerifier:    ", address(verifier));
        console.log("PetitionRegistry: ", address(registry));
        console.log("CREATION_DEPOSIT:", creationDeposit);
    }
}
