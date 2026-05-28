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
    uint256 constant DEPOSIT = 0.001 ether;

    // Canonical fake P-256 inputs for happy path.
    uint256 constant PUBKEY_X = uint256(0xA11CE);
    uint256 constant PUBKEY_Y = uint256(0xB0B);
    uint256 constant SIG_R    = uint256(0xC0FFEE);
    uint256 constant SIG_S    = uint256(0xDECAF);
    bytes32 constant MSG_HASH = bytes32(uint256(0xFEED));

    address creator = address(0xC0DE);

    function setUp() public {
        verifier = new MockVerifier();
        registry = new PetitionRegistry(IVerifier(address(verifier)), TRUST_ROOT, DEPOSIT);
        vm.deal(creator, 10 ether);
        // Default: mock the precompile to accept the canonical inputs.
        _mockP256(MSG_HASH, SIG_R, SIG_S, PUBKEY_X, PUBKEY_Y, true);
    }

    // ---------- helpers ----------

    function _mockP256(
        bytes32 msgHash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y,
        bool valid
    ) internal {
        bytes memory input = abi.encodePacked(msgHash, r, s, x, y);
        vm.mockCall(
            address(0x100),
            input,
            abi.encode(valid ? uint256(1) : uint256(0))
        );
    }

    function _create(uint32 threshold) internal returns (uint256 id) {
        vm.prank(creator);
        id = registry.createPetition{value: DEPOSIT}(
            bytes("Hello, world"), uint64(block.timestamp + 7 days), threshold
        );
    }

    function _publicInputs(uint256 id, bytes32 nullifier)
        internal
        pure
        returns (bytes32[] memory pi)
    {
        pi = new bytes32[](6);
        pi[0] = bytes32(id);
        pi[1] = nullifier;
        pi[2] = TRUST_ROOT;
        pi[3] = bytes32(PUBKEY_X);
        pi[4] = bytes32(PUBKEY_Y);
        pi[5] = MSG_HASH;
    }

    function _sign(uint256 id, bytes32 nul) internal {
        registry.signPetition(
            id, nul, PUBKEY_X, PUBKEY_Y, SIG_R, SIG_S, "", _publicInputs(id, nul)
        );
    }

    // ---------- happy path ----------

    function test_create_and_sign_increments_count() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        _sign(id, nul);
        assertEq(registry.signatureCount(id), 1);
        assertTrue(registry.hasNullifier(id, nul));
    }

    function test_duplicate_nullifier_reverts() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(7));
        _sign(id, nul);
        vm.expectRevert(PetitionRegistry.NullifierAlreadyUsed.selector);
        _sign(id, nul);
    }

    function test_threshold_event_emitted_once() public {
        uint256 id = _create(2);
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        bytes32 c = bytes32(uint256(3));
        _sign(id, a);
        vm.expectEmit(true, false, false, true);
        emit PetitionRegistry.ThresholdReached(id, 2, uint64(block.timestamp));
        _sign(id, b);
        _sign(id, c);
        assertEq(registry.signatureCount(id), 3);
    }

    function test_closed_after_deadline() public {
        uint256 id = _create(10);
        vm.warp(block.timestamp + 30 days);
        bytes32 nul = bytes32(uint256(1));
        vm.expectRevert(PetitionRegistry.PetitionClosed.selector);
        _sign(id, nul);
    }

    function test_rejects_bad_trust_root() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputs(id, nul);
        pi[2] = bytes32(uint256(0xBAD));
        vm.expectRevert(PetitionRegistry.InvalidTrustRoot.selector);
        registry.signPetition(id, nul, PUBKEY_X, PUBKEY_Y, SIG_R, SIG_S, "", pi);
    }

    function test_rejects_when_verifier_returns_false() public {
        verifier.setAccept(false);
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        vm.expectRevert(PetitionRegistry.InvalidProof.selector);
        _sign(id, nul);
    }

    function test_rejects_when_precompile_returns_zero() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        // Override precompile mock to refuse.
        _mockP256(MSG_HASH, SIG_R, SIG_S, PUBKEY_X, PUBKEY_Y, false);
        vm.expectRevert(PetitionRegistry.InvalidSignature.selector);
        _sign(id, nul);
    }

    function test_rejects_when_pubkey_mismatches_public_input() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputs(id, nul);
        // Lie in calldata: pubkeyX claimed != publicInputs[3].
        vm.expectRevert(PetitionRegistry.InvalidProof.selector);
        registry.signPetition(
            id, nul, PUBKEY_X + 1, PUBKEY_Y, SIG_R, SIG_S, "", pi
        );
    }

    // ---------- deposit ----------

    function test_create_requires_exact_deposit() public {
        vm.prank(creator);
        vm.expectRevert(PetitionRegistry.WrongDeposit.selector);
        registry.createPetition{value: DEPOSIT - 1}(
            bytes("hi"), uint64(block.timestamp + 1 days), 1
        );

        vm.prank(creator);
        vm.expectRevert(PetitionRegistry.WrongDeposit.selector);
        registry.createPetition{value: DEPOSIT + 1}(
            bytes("hi"), uint64(block.timestamp + 1 days), 1
        );
    }

    function test_deposit_locked_event_on_create() public {
        vm.prank(creator);
        vm.expectEmit(true, false, false, true);
        emit PetitionRegistry.DepositLocked(1, DEPOSIT);
        registry.createPetition{value: DEPOSIT}(
            bytes("hi"), uint64(block.timestamp + 1 days), 1
        );
        assertEq(address(registry).balance, DEPOSIT);
    }

    function test_withdraw_only_after_deadline() public {
        uint256 id = _create(3);
        vm.prank(creator);
        vm.expectRevert(PetitionRegistry.PetitionStillOpen.selector);
        registry.withdrawDeposit(id);
    }

    function test_withdraw_only_by_creator() public {
        uint256 id = _create(3);
        vm.warp(block.timestamp + 30 days);
        vm.prank(address(0xBEEF));
        vm.expectRevert(PetitionRegistry.NotCreator.selector);
        registry.withdrawDeposit(id);
    }

    function test_withdraw_refunds_exactly_once() public {
        uint256 id = _create(3);
        vm.warp(block.timestamp + 30 days);
        uint256 balBefore = creator.balance;

        vm.prank(creator);
        vm.expectEmit(true, false, false, true);
        emit PetitionRegistry.DepositRefunded(id, DEPOSIT);
        registry.withdrawDeposit(id);
        assertEq(creator.balance, balBefore + DEPOSIT);
        assertEq(address(registry).balance, 0);

        vm.prank(creator);
        vm.expectRevert(PetitionRegistry.DepositAlreadyRefunded.selector);
        registry.withdrawDeposit(id);
    }

    function test_withdraw_unknown_petition_reverts() public {
        vm.prank(creator);
        vm.expectRevert(PetitionRegistry.UnknownPetition.selector);
        registry.withdrawDeposit(999);
    }
}
