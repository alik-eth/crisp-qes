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

    /// @dev Placeholder attester address used when `OPRF_ATTESTER` is not
    ///      yet set by backend. EnrollmentRegistry.updateRoot blocks while
    ///      the attester is at the zero address, but a non-zero placeholder
    ///      makes the deployed registry inspectable (`oprfAttester()` view
    ///      returns the placeholder so the web UI can detect "not yet
    ///      wired"). Admin must call `setOprfAttester(real)` before any
    ///      enrollment batch lands.
    address internal constant OPRF_ATTESTER_PLACEHOLDER =
        0x000000000000000000000000000000000000dEaD;

    function run()
        external
        returns (
            EnrollmentRegistry enrollmentRegistry,
            UltraVerifierV2 verifier,
            PetitionRegistryV2 registry
        )
    {
        // OPRF_ATTESTER is optional at deploy time: ship a placeholder so
        // the contracts build/deploy/test even when backend's signing key
        // isn't wired yet. Admin rotates to the real value via
        // `EnrollmentRegistry.setOprfAttester(...)` once available.
        address oprfAttester = vm.envOr("OPRF_ATTESTER", OPRF_ATTESTER_PLACEHOLDER);
        // Genesis root must match the OPRF service's current tree root.
        // Default `bytes32(0)` only makes sense for a fresh deploy where
        // backend's tree is also empty.
        bytes32 genesisRoot = vm.envOr("V2_GENESIS_ROOT", bytes32(0));
        // Genesis leaf count must equal backend's `leafCount` at deploy
        // time so the first signed `updateRoot(leafIndex=N)` verifies.
        // Default 0 for a fresh deploy.
        uint256 genesisLeafCount = vm.envOr("V2_GENESIS_LEAF_COUNT", uint256(0));
        uint256 creationDeposit = vm.envOr("CREATION_DEPOSIT_WEI", DEFAULT_CREATION_DEPOSIT);
        // Admin is whoever signed the deploy tx. Pass through env if the
        // production multisig is known up-front.
        address admin = vm.envOr("V2_ADMIN", msg.sender);

        vm.startBroadcast();
        enrollmentRegistry = new EnrollmentRegistry(
            oprfAttester, genesisRoot, genesisLeafCount, admin
        );
        verifier = new UltraVerifierV2();
        registry = new PetitionRegistryV2(
            IVerifierV2(address(verifier)), enrollmentRegistry, creationDeposit
        );
        vm.stopBroadcast();

        console.log("EnrollmentRegistry: ", address(enrollmentRegistry));
        console.log("UltraVerifierV2:    ", address(verifier));
        console.log("PetitionRegistryV2: ", address(registry));
        console.log("oprfAttester:       ", oprfAttester);
        console.log("admin:              ", admin);
        console.log("genesisLeafCount:   ", genesisLeafCount);
        console.log("CREATION_DEPOSIT:   ", creationDeposit);
        if (oprfAttester == OPRF_ATTESTER_PLACEHOLDER) {
            console.log("WARNING: deployed with placeholder attester; admin must");
            console.log("call EnrollmentRegistry.setOprfAttester(real) before any");
            console.log("OPRF batch can land.");
        }
    }
}
