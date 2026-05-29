// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {UltraVerifierV2} from "../src/UltraVerifierV2.sol";
import {IVerifierV2} from "../src/IVerifierV2.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {PetitionRegistryV2} from "../src/PetitionRegistryV2.sol";

/// Bench-only: measure v2 verifier + end-to-end `signPetition` gas with
/// the REAL UltraVerifierV2 (not the mock used elsewhere in the test
/// suite). Inputs come from `bench/v2-proof.bin` + the publicInputs
/// emitted by `node bench/v2-emit-proof.mjs`. Constants below must be
/// re-pasted whenever the circuit / witness changes.
contract UltraVerifierV2GasTest is Test {
    UltraVerifierV2 internal verifier;
    EnrollmentRegistry internal enrollment;
    PetitionRegistryV2 internal registry;

    // From bench/v2-publics.json (3 publics; emit-proof for the
    // `enrollment_secret = 0x42`, `petition_id = 999`, all-zero-sibling
    // depth-20 Merkle path synthetic witness):
    uint256 internal constant PETITION_ID = 1;
    bytes32 internal constant ENROLLMENT_ROOT =
        0x19b9f5ef991b2068acb4d82a2d1cbe68bc8a96ded0a35c26da464c232aac05a7;
    bytes32 internal constant NULLIFIER =
        0x15b0b99f501b69c71e5e07a610460901d1710d91d707dc094892a8eb8be81827;

    address internal creator = address(0xC0DE);
    address internal attester = address(0xA77E);

    function setUp() public {
        verifier = new UltraVerifierV2();
        enrollment = new EnrollmentRegistry(attester, ENROLLMENT_ROOT, 0, address(this));
        // Note: bench gas test doesn't exercise updateRoot, so the digest-
        // scheme change in this commit doesn't affect the numbers.
        registry = new PetitionRegistryV2(
            IVerifierV2(address(verifier)), enrollment, 0.001 ether
        );
        vm.deal(creator, 1 ether);
    }

    /// Verifier in isolation — what the deployed UltraVerifierV2 spends
    /// to accept a fresh proof. Comparable to the MVP's
    /// `UltraVerifier.verify` cost we measured at 2,676,476.
    function test_verify_gas() public {
        bytes32[] memory publicInputs = new bytes32[](3);
        publicInputs[0] = bytes32(PETITION_ID);
        publicInputs[1] = ENROLLMENT_ROOT;
        publicInputs[2] = NULLIFIER;

        bytes memory proof = vm.readFileBinary("../../bench/v2-proof.bin");
        emit log_named_uint("proof bytes", proof.length);
        emit log_named_uint("public inputs", publicInputs.length);

        bool ok = verifier.verify(proof, publicInputs);
        assertTrue(ok, "v2 verifier rejected a valid proof");
    }

    /// End-to-end `signPetition` — full call cost including calldata,
    /// nullifier SSTORE, event emission, and the inner verifier call.
    /// Comparable to MVP tx `0x349d…65c47` which spent 4,242,422 gas.
    function test_signPetition_e2e_gas() public {
        // Create petition #1 (matches our pinned PETITION_ID).
        vm.prank(creator);
        uint256 id = registry.createPetition{value: 0.001 ether}(
            bytes("v2 gas bench"),
            uint64(block.timestamp + 7 days),
            1
        );
        require(id == PETITION_ID, "id mismatch");

        bytes32[] memory publicInputs = new bytes32[](3);
        publicInputs[0] = bytes32(PETITION_ID);
        publicInputs[1] = ENROLLMENT_ROOT;
        publicInputs[2] = NULLIFIER;
        bytes memory proof = vm.readFileBinary("../../bench/v2-proof.bin");

        uint256 g0 = gasleft();
        registry.signPetition(id, NULLIFIER, proof, publicInputs);
        uint256 used = g0 - gasleft();
        emit log_named_uint("signPetition gas", used);
    }
}
