// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IVerifierV2} from "../src/IVerifierV2.sol";
import {UltraVerifierV2} from "../src/UltraVerifierV2.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {PetitionRegistryV2} from "../src/PetitionRegistryV2.sol";

contract DeployV2 is Script {
    /// @dev Default creation-deposit (0.001 ETH on Base), per spec sec 7
    ///      item 5. Mirrors the MVP default.
    uint256 internal constant DEFAULT_CREATION_DEPOSIT = 0.001 ether;

    function run()
        external
        returns (
            EnrollmentRegistry enrollmentRegistry,
            UltraVerifierV2 verifier,
            PetitionRegistryV2 registry
        )
    {
        address oprfAttester = vm.envAddress("OPRF_ATTESTER");
        // Optional genesis root. Defaults to bytes32(0), meaning "empty
        // enrollment set"; the first `updateRoot` call rolls in the
        // initial batch.
        bytes32 genesisRoot = vm.envOr("V2_GENESIS_ROOT", bytes32(0));
        uint256 creationDeposit = vm.envOr("CREATION_DEPOSIT_WEI", DEFAULT_CREATION_DEPOSIT);

        vm.startBroadcast();
        enrollmentRegistry = new EnrollmentRegistry(oprfAttester, genesisRoot);
        verifier = new UltraVerifierV2();
        registry = new PetitionRegistryV2(
            IVerifierV2(address(verifier)), enrollmentRegistry, creationDeposit
        );
        vm.stopBroadcast();

        console.log("EnrollmentRegistry: ", address(enrollmentRegistry));
        console.log("UltraVerifierV2:    ", address(verifier));
        console.log("PetitionRegistryV2: ", address(registry));
        console.log("oprfAttester:       ", oprfAttester);
        console.log("CREATION_DEPOSIT:   ", creationDeposit);
    }
}
