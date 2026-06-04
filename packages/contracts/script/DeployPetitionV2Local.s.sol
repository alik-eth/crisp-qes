// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IVerifierV2} from "../src/IVerifierV2.sol";
import {UltraVerifierV2} from "../src/UltraVerifierV2.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {PetitionRegistryV2} from "../src/PetitionRegistryV2.sol";

/// @dev docker-compose-dev: deploy UltraVerifierV2 + PetitionRegistryV2 wired to
/// the EXISTING EnrollmentRegistry (so an already-enrolled leaf counts), without
/// redeploying enrollment. forge script auto-links the verifier's ZKTranscriptLib.
/// Required env: V2_ENROLLMENT_REGISTRY. Optional: CREATION_DEPOSIT_WEI.
contract DeployPetitionV2Local is Script {
    function run() external returns (UltraVerifierV2 verifier, PetitionRegistryV2 registry) {
        address enrollmentAddr = vm.envAddress("V2_ENROLLMENT_REGISTRY");
        uint256 deposit = vm.envOr("CREATION_DEPOSIT_WEI", uint256(0.001 ether));
        vm.startBroadcast();
        verifier = new UltraVerifierV2();
        registry = new PetitionRegistryV2(
            IVerifierV2(address(verifier)), EnrollmentRegistry(enrollmentAddr), deposit
        );
        vm.stopBroadcast();
        console.log("UltraVerifierV2:    ", address(verifier));
        console.log("PetitionRegistryV2: ", address(registry));
        console.log("EnrollmentRegistry: ", enrollmentAddr);
    }
}
