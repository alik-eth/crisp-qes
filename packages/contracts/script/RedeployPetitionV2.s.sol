// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IVerifierV2} from "../src/IVerifierV2.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {PetitionRegistryV2} from "../src/PetitionRegistryV2.sol";

/// @dev Re-deploys ONLY PetitionRegistryV2 against the existing
///      UltraVerifierV2 + EnrollmentRegistry instances. Use after a
///      breaking storage change in PetitionRegistryV2 (e.g. revoke +
///      voteByNullifier refactor) so existing enrollments stay intact.
///
/// Required env: V2_VERIFIER, V2_ENROLLMENT_REGISTRY.
/// Optional env: CREATION_DEPOSIT_WEI (default 0.001 ether).
contract RedeployPetitionV2 is Script {
    uint256 internal constant DEFAULT_CREATION_DEPOSIT = 0.001 ether;

    function run() external returns (PetitionRegistryV2 registry) {
        address verifierAddr = vm.envAddress("V2_VERIFIER");
        address enrollmentAddr = vm.envAddress("V2_ENROLLMENT_REGISTRY");
        uint256 creationDeposit = vm.envOr(
            "CREATION_DEPOSIT_WEI",
            DEFAULT_CREATION_DEPOSIT
        );

        vm.startBroadcast();
        registry = new PetitionRegistryV2(
            IVerifierV2(verifierAddr),
            EnrollmentRegistry(enrollmentAddr),
            creationDeposit
        );
        vm.stopBroadcast();

        console.log("PetitionRegistryV2 (new): ", address(registry));
        console.log("Verifier (reused):        ", verifierAddr);
        console.log("EnrollmentRegistry (reused):", enrollmentAddr);
        console.log("CREATION_DEPOSIT:         ", creationDeposit);
    }
}
