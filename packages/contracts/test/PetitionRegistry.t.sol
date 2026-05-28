// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {PetitionRegistry} from "../src/PetitionRegistry.sol";

contract MockVerifier is IVerifier {
    bool public accept = true;

    function setAccept(bool v) external {
        accept = v;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return accept;
    }
}

contract PetitionRegistryTest is Test {
    PetitionRegistry registry;
    MockVerifier verifier;
    bytes32 constant TRUST_ROOT = bytes32(uint256(0xDEADBEEF));

    function setUp() public {
        verifier = new MockVerifier();
        registry = new PetitionRegistry(IVerifier(address(verifier)), TRUST_ROOT);
    }

    function _create(uint32 threshold) internal returns (uint256 id) {
        id = registry.createPetition(bytes("Hello, world"), uint64(block.timestamp + 7 days), threshold);
    }

    function _publicInputs(uint256 id, bytes32 nullifier) internal pure returns (bytes32[] memory pi) {
        pi = new bytes32[](4);
        pi[0] = bytes32(id);
        pi[1] = nullifier;
        pi[2] = TRUST_ROOT;
        pi[3] = bytes32(0);
    }

    function test_create_and_sign_increments_count() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        registry.signPetition(id, nul, "", _publicInputs(id, nul));
        assertEq(registry.signatureCount(id), 1);
        assertTrue(registry.hasNullifier(id, nul));
    }

    function test_duplicate_nullifier_reverts() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(7));
        registry.signPetition(id, nul, "", _publicInputs(id, nul));
        vm.expectRevert(PetitionRegistry.NullifierAlreadyUsed.selector);
        registry.signPetition(id, nul, "", _publicInputs(id, nul));
    }

    function test_threshold_event_emitted_once() public {
        uint256 id = _create(2);
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        bytes32 c = bytes32(uint256(3));
        registry.signPetition(id, a, "", _publicInputs(id, a));
        vm.expectEmit(true, false, false, true);
        emit PetitionRegistry.ThresholdReached(id, 2, uint64(block.timestamp));
        registry.signPetition(id, b, "", _publicInputs(id, b));
        registry.signPetition(id, c, "", _publicInputs(id, c));
        assertEq(registry.signatureCount(id), 3);
    }

    function test_closed_after_deadline() public {
        uint256 id = _create(10);
        vm.warp(block.timestamp + 30 days);
        bytes32 nul = bytes32(uint256(1));
        vm.expectRevert(PetitionRegistry.PetitionClosed.selector);
        registry.signPetition(id, nul, "", _publicInputs(id, nul));
    }

    function test_rejects_bad_trust_root() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputs(id, nul);
        pi[2] = bytes32(uint256(0xBAD));
        vm.expectRevert(PetitionRegistry.InvalidTrustRoot.selector);
        registry.signPetition(id, nul, "", pi);
    }

    function test_rejects_when_verifier_returns_false() public {
        verifier.setAccept(false);
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        vm.expectRevert(PetitionRegistry.InvalidProof.selector);
        registry.signPetition(id, nul, "", _publicInputs(id, nul));
    }
}
