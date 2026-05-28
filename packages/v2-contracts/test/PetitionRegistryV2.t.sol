// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IVerifierV2} from "../src/IVerifierV2.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {PetitionRegistryV2} from "../src/PetitionRegistryV2.sol";

contract MockVerifierV2 is IVerifierV2 {
    bool public accept = true;

    function setAccept(bool v) external {
        accept = v;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return accept;
    }
}

contract PetitionRegistryV2Test is Test {
    PetitionRegistryV2 internal registry;
    EnrollmentRegistry internal enrollment;
    MockVerifierV2 internal verifier;

    bytes32 internal constant GENESIS_ROOT = bytes32(uint256(0xCAFEBABE));
    uint256 internal constant DEPOSIT = 0.001 ether;

    address internal creator = address(0xC0DE);

    // The OPRF attester is generated from a fixed seed so tests can
    // reproducibly sign root updates with `vm.sign`.
    uint256 internal attesterPk = 0xA77E57E8;
    address internal attester;

    function setUp() public {
        attester = vm.addr(attesterPk);
        enrollment = new EnrollmentRegistry(attester, GENESIS_ROOT);
        verifier = new MockVerifierV2();
        registry = new PetitionRegistryV2(
            IVerifierV2(address(verifier)), enrollment, DEPOSIT
        );
        vm.deal(creator, 10 ether);
    }

    // ---------- helpers ----------

    function _create(uint32 threshold, PetitionRegistryV2.BallotMode mode)
        internal
        returns (uint256 id)
    {
        vm.prank(creator);
        id = registry.createPetition{value: DEPOSIT}(
            bytes("Hello, v2"),
            uint64(block.timestamp + 7 days),
            threshold,
            mode
        );
    }

    /// @dev Uses the local `GENESIS_ROOT` constant (not
    ///      `enrollment.enrollmentRoot()`) so that callers wrapped by
    ///      `vm.expectRevert` don't accidentally consume the cheat-code
    ///      slot with a benign view call before the call-under-test
    ///      actually fires.
    function _publicInputs(uint256 id, bytes32 nullifier)
        internal
        pure
        returns (bytes32[] memory pi)
    {
        pi = new bytes32[](3);
        pi[0] = bytes32(id);
        pi[1] = GENESIS_ROOT;
        pi[2] = nullifier;
    }

    function _sign(uint256 id, uint8 vote, bytes32 nul) internal {
        registry.signPetition(id, vote, nul, "", _publicInputs(id, nul));
    }

    // ---------- creation ----------

    function test_create_petition_records_mode_and_emits() public {
        vm.expectEmit(true, true, false, true);
        emit PetitionRegistryV2.PetitionCreated(
            1,
            creator,
            uint64(block.timestamp + 7 days),
            5,
            PetitionRegistryV2.BallotMode.YesNoAbstain
        );
        uint256 id = _create(5, PetitionRegistryV2.BallotMode.YesNoAbstain);
        assertEq(id, 1);

        PetitionRegistryV2.Petition memory p = registry.getPetition(id);
        assertEq(uint8(p.mode), uint8(PetitionRegistryV2.BallotMode.YesNoAbstain));
        assertEq(p.signatureCount, 0);
    }

    function test_create_rejects_wrong_deposit() public {
        vm.prank(creator);
        vm.expectRevert(PetitionRegistryV2.WrongDeposit.selector);
        registry.createPetition{value: 0}(
            bytes("hi"),
            uint64(block.timestamp + 1 days),
            1,
            PetitionRegistryV2.BallotMode.Signature
        );
    }

    function test_create_rejects_past_deadline() public {
        vm.prank(creator);
        vm.expectRevert(PetitionRegistryV2.DeadlineInPast.selector);
        registry.createPetition{value: DEPOSIT}(
            bytes("hi"),
            uint64(block.timestamp),
            1,
            PetitionRegistryV2.BallotMode.Signature
        );
    }

    // ---------- happy path ----------

    function test_sign_in_signature_mode_increments_count() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(1));
        _sign(id, 0, nul);
        assertEq(registry.signatureCount(id), 1);
        assertTrue(registry.hasNullifier(id, nul));
    }

    function test_yesno_mode_bumps_yes_and_no_counters() public {
        uint256 id = _create(10, PetitionRegistryV2.BallotMode.YesNo);
        _sign(id, 1, bytes32(uint256(1)));
        _sign(id, 0, bytes32(uint256(2)));
        _sign(id, 1, bytes32(uint256(3)));
        (uint32 y, uint32 n, uint32 a) = registry.voteCounts(id);
        assertEq(y, 2);
        assertEq(n, 1);
        assertEq(a, 0);
        assertEq(registry.signatureCount(id), 3);
    }

    function test_yesnoabstain_mode_bumps_all_three_counters() public {
        uint256 id = _create(10, PetitionRegistryV2.BallotMode.YesNoAbstain);
        _sign(id, 1, bytes32(uint256(1)));
        _sign(id, 0, bytes32(uint256(2)));
        _sign(id, 2, bytes32(uint256(3)));
        (uint32 y, uint32 n, uint32 a) = registry.voteCounts(id);
        assertEq(y, 1);
        assertEq(n, 1);
        assertEq(a, 1);
    }

    function test_threshold_event_emitted_once() public {
        uint256 id = _create(2, PetitionRegistryV2.BallotMode.Signature);
        _sign(id, 0, bytes32(uint256(1)));
        vm.expectEmit(true, false, false, true);
        emit PetitionRegistryV2.ThresholdReached(id, 2, uint64(block.timestamp));
        _sign(id, 0, bytes32(uint256(2)));
        _sign(id, 0, bytes32(uint256(3))); // no second event
        assertEq(registry.signatureCount(id), 3);
    }

    // ---------- revert paths ----------

    function test_duplicate_nullifier_reverts() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(7));
        _sign(id, 0, nul);
        vm.expectRevert(PetitionRegistryV2.NullifierAlreadyUsed.selector);
        _sign(id, 0, nul);
    }

    function test_closed_after_deadline() public {
        uint256 id = _create(10, PetitionRegistryV2.BallotMode.Signature);
        vm.warp(block.timestamp + 30 days);
        vm.expectRevert(PetitionRegistryV2.PetitionClosed.selector);
        _sign(id, 0, bytes32(uint256(1)));
    }

    function test_rejects_when_verifier_returns_false() public {
        verifier.setAccept(false);
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        vm.expectRevert(PetitionRegistryV2.InvalidProof.selector);
        _sign(id, 0, bytes32(uint256(1)));
    }

    /// @dev `publicInputs.length` must be exactly 3 (v2 spec). A 4-input
    ///      array - the kind of bug a left-over MVP code path would
    ///      produce - reverts with `InvalidProof`.
    function test_rejects_when_public_inputs_wrong_length() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = new bytes32[](4);
        pi[0] = bytes32(id);
        pi[1] = enrollment.enrollmentRoot();
        pi[2] = nul;
        pi[3] = bytes32(0);
        vm.expectRevert(PetitionRegistryV2.InvalidProof.selector);
        registry.signPetition(id, 0, nul, "", pi);
    }

    function test_rejects_when_petition_id_mismatch_in_proof() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputs(id, nul);
        pi[0] = bytes32(uint256(id + 1));
        vm.expectRevert(PetitionRegistryV2.InvalidProof.selector);
        registry.signPetition(id, 0, nul, "", pi);
    }

    function test_rejects_when_nullifier_mismatch_in_proof() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputs(id, nul);
        pi[2] = bytes32(uint256(0xBAD));
        vm.expectRevert(PetitionRegistryV2.InvalidProof.selector);
        registry.signPetition(id, 0, nul, "", pi);
    }

    function test_rejects_when_enrollment_root_mismatch_in_proof() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputs(id, nul);
        pi[1] = bytes32(uint256(0xDEAD));
        vm.expectRevert(PetitionRegistryV2.InvalidEnrollmentRoot.selector);
        registry.signPetition(id, 0, nul, "", pi);
    }

    /// @dev Mode-bound vote rejection: in Signature mode the only valid
    ///      vote is 0; anything else is a caller bug and reverts.
    function test_rejects_invalid_vote_in_signature_mode() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        vm.expectRevert(PetitionRegistryV2.InvalidVote.selector);
        _sign(id, 2, bytes32(uint256(1)));
    }

    function test_rejects_invalid_vote_in_yesno_mode() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.YesNo);
        // YesNo accepts 0 (No) or 1 (Yes); 2 is invalid.
        vm.expectRevert(PetitionRegistryV2.InvalidVote.selector);
        _sign(id, 2, bytes32(uint256(1)));
    }

    function test_rejects_invalid_vote_in_yesnoabstain_mode() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.YesNoAbstain);
        // YesNoAbstain accepts 0/1/2; 3 is out of range.
        vm.expectRevert(PetitionRegistryV2.InvalidVote.selector);
        _sign(id, 3, bytes32(uint256(1)));
    }

    // ---------- deposit refund ----------

    function test_withdraw_after_deadline_refunds_creator() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        uint256 before = creator.balance;
        vm.warp(block.timestamp + 30 days);
        vm.prank(creator);
        registry.withdrawDeposit(id);
        assertEq(creator.balance, before + DEPOSIT);
    }

    function test_withdraw_rejects_still_open() public {
        uint256 id = _create(3, PetitionRegistryV2.BallotMode.Signature);
        vm.prank(creator);
        vm.expectRevert(PetitionRegistryV2.PetitionStillOpen.selector);
        registry.withdrawDeposit(id);
    }
}

contract EnrollmentRegistryTest is Test {
    EnrollmentRegistry internal enrollment;

    uint256 internal attesterPk = 0xA77E57E8;
    address internal attester;
    bytes32 internal constant GENESIS_ROOT = bytes32(uint256(0xCAFEBABE));

    function setUp() public {
        attester = vm.addr(attesterPk);
        enrollment = new EnrollmentRegistry(attester, GENESIS_ROOT);
    }

    function _signUpdate(
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes32[] memory newCommitments
    ) internal view returns (bytes memory) {
        bytes32 commitmentsHash = keccak256(abi.encodePacked(newCommitments));
        bytes32 digest = keccak256(
            abi.encode(
                oldRoot, newRoot, commitmentsHash, block.chainid, address(enrollment)
            )
        );
        bytes32 ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, ethSigned);
        return abi.encodePacked(r, s, v);
    }

    function test_genesis_root_set() public view {
        assertEq(enrollment.enrollmentRoot(), GENESIS_ROOT);
        assertEq(enrollment.oprfAttester(), attester);
    }

    function test_update_root_with_valid_signature() public {
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = bytes32(uint256(1));
        commitments[1] = bytes32(uint256(2));
        bytes memory sig = _signUpdate(GENESIS_ROOT, newRoot, commitments);

        vm.expectEmit(true, true, false, true);
        emit EnrollmentRegistry.RootUpdated(GENESIS_ROOT, newRoot, block.number);
        enrollment.updateRoot(newRoot, commitments, sig);

        assertEq(enrollment.enrollmentRoot(), newRoot);
        assertTrue(enrollment.isCommitmentUsed(bytes32(uint256(1))));
        assertTrue(enrollment.isCommitmentUsed(bytes32(uint256(2))));
        assertFalse(enrollment.isCommitmentUsed(bytes32(uint256(3))));
    }

    function test_update_root_rejects_bad_signature() public {
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = bytes32(uint256(1));
        // Sign with the wrong key.
        bytes32 digest = keccak256(
            abi.encode(
                GENESIS_ROOT,
                newRoot,
                keccak256(abi.encodePacked(commitments)),
                block.chainid,
                address(enrollment)
            )
        );
        bytes32 ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(0xDEAD), ethSigned);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        enrollment.updateRoot(newRoot, commitments, sig);
    }

    function test_update_root_rejects_replay_after_chain_advance() public {
        // First update succeeds.
        bytes32 root1 = bytes32(uint256(0xBEEF));
        bytes32[] memory c1 = new bytes32[](1);
        c1[0] = bytes32(uint256(1));
        bytes memory sig1 = _signUpdate(GENESIS_ROOT, root1, c1);
        enrollment.updateRoot(root1, c1, sig1);

        // Replaying the same signature with the new root in storage must
        // fail (signed digest contained the old root, not the new one).
        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        enrollment.updateRoot(root1, c1, sig1);
    }

    function test_update_root_rejects_empty_batch() public {
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes32[] memory empty = new bytes32[](0);
        bytes memory sig = _signUpdate(GENESIS_ROOT, newRoot, empty);

        vm.expectRevert(EnrollmentRegistry.EmptyBatch.selector);
        enrollment.updateRoot(newRoot, empty, sig);
    }
}
