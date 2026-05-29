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
        enrollment = new EnrollmentRegistry(attester, GENESIS_ROOT, 0, address(this));
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

    function _revoke(uint256 id, bytes32 nul) internal {
        registry.revokeVote(id, nul, "", _publicInputs(id, nul));
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

    // ---------- revocation ----------

    function test_revokeVote_signatureMode_decrementsCount() public {
        uint256 id = _create(5, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(0xA1));
        _sign(id, 0, nul);
        _sign(id, 0, bytes32(uint256(0xA2)));
        assertEq(registry.signatureCount(id), 2);

        vm.expectEmit(true, true, false, true);
        emit PetitionRegistryV2.PetitionRevoked(id, nul, 1);
        _revoke(id, nul);

        assertEq(registry.signatureCount(id), 1);
        assertFalse(registry.hasNullifier(id, nul));
        assertTrue(registry.hasNullifier(id, bytes32(uint256(0xA2))));
    }

    function test_revokeVote_yesNoMode_decrementsTheRightCounter() public {
        uint256 id = _create(99, PetitionRegistryV2.BallotMode.YesNo);
        bytes32 nulYes = bytes32(uint256(0xB1));
        bytes32 nulNo = bytes32(uint256(0xB2));
        _sign(id, 1, nulYes);
        _sign(id, 0, nulNo);
        (uint32 y, uint32 n,) = registry.voteCounts(id);
        assertEq(y, 1);
        assertEq(n, 1);

        _revoke(id, nulYes);
        (y, n,) = registry.voteCounts(id);
        assertEq(y, 0);
        assertEq(n, 1);
        assertEq(registry.signatureCount(id), 1);

        _revoke(id, nulNo);
        (y, n,) = registry.voteCounts(id);
        assertEq(y, 0);
        assertEq(n, 0);
        assertEq(registry.signatureCount(id), 0);
    }

    function test_revokeVote_yesNoAbstainMode_decrementsAllThree() public {
        uint256 id = _create(99, PetitionRegistryV2.BallotMode.YesNoAbstain);
        bytes32 nulNo = bytes32(uint256(0xC1));
        bytes32 nulYes = bytes32(uint256(0xC2));
        bytes32 nulAbs = bytes32(uint256(0xC3));
        _sign(id, 0, nulNo);
        _sign(id, 1, nulYes);
        _sign(id, 2, nulAbs);
        (uint32 y, uint32 n, uint32 a) = registry.voteCounts(id);
        assertEq(y, 1);
        assertEq(n, 1);
        assertEq(a, 1);

        _revoke(id, nulNo);
        (y, n, a) = registry.voteCounts(id);
        assertEq(y, 1);
        assertEq(n, 0);
        assertEq(a, 1);

        _revoke(id, nulYes);
        (y, n, a) = registry.voteCounts(id);
        assertEq(y, 0);
        assertEq(n, 0);
        assertEq(a, 1);

        _revoke(id, nulAbs);
        (y, n, a) = registry.voteCounts(id);
        assertEq(y, 0);
        assertEq(n, 0);
        assertEq(a, 0);
        assertEq(registry.signatureCount(id), 0);
    }

    function test_revokeVote_clearsNullifierSlot() public {
        uint256 id = _create(5, PetitionRegistryV2.BallotMode.YesNoAbstain);
        bytes32 nul = bytes32(uint256(0xD1));
        _sign(id, 2, nul);
        assertTrue(registry.hasNullifier(id, nul));
        assertEq(registry.voteByNullifier(id, nul), 3); // 1 + 2

        _revoke(id, nul);
        assertFalse(registry.hasNullifier(id, nul));
        assertEq(registry.voteByNullifier(id, nul), 0);
    }

    function test_revokeVote_thresholdReachedStaysSticky() public {
        // Threshold=1: a single signature flips `thresholdReached`. Per
        // spec, revoke must NOT clear that bit — the political fact is
        // logged. Once threshold is reached the petition leaves the Open
        // state, so revoke must revert with PetitionClosed.
        uint256 id = _create(1, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(0xE1));
        _sign(id, 0, nul);
        assertEq(
            uint8(registry.petitionStatus(id)),
            uint8(PetitionRegistryV2.PetitionStatus.ThresholdReached)
        );

        vm.expectRevert(PetitionRegistryV2.PetitionClosed.selector);
        _revoke(id, nul);

        // And the bit is still set.
        PetitionRegistryV2.Petition memory p = registry.getPetition(id);
        assertTrue(p.thresholdReached);
    }

    function test_revokeVote_revertsWhenNotSigned() public {
        uint256 id = _create(5, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(0xF1));
        vm.expectRevert(PetitionRegistryV2.NullifierNotUsed.selector);
        _revoke(id, nul);
    }

    function test_revokeVote_revertsWhenPetitionClosed() public {
        uint256 id = _create(5, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(0xF2));
        _sign(id, 0, nul);
        vm.warp(block.timestamp + 30 days);
        vm.expectRevert(PetitionRegistryV2.PetitionClosed.selector);
        _revoke(id, nul);
    }

    function test_revokeVote_revertsWhenInvalidProof() public {
        uint256 id = _create(5, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(0xF3));
        _sign(id, 0, nul);
        verifier.setAccept(false);
        vm.expectRevert(PetitionRegistryV2.InvalidProof.selector);
        _revoke(id, nul);
    }

    function test_revokeVote_revertsWhenUnknownPetition() public {
        vm.expectRevert(PetitionRegistryV2.UnknownPetition.selector);
        _revoke(999, bytes32(uint256(0xF4)));
    }

    function test_revokeVote_revertsWhenPublicInputsWrongLength() public {
        uint256 id = _create(5, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(0xF5));
        _sign(id, 0, nul);
        bytes32[] memory pi = new bytes32[](2);
        pi[0] = bytes32(id);
        pi[1] = nul;
        vm.expectRevert(PetitionRegistryV2.InvalidProof.selector);
        registry.revokeVote(id, nul, "", pi);
    }

    function test_resign_afterRevoke_allowed_andCanChangeVote() public {
        // Sign Yes, revoke, then re-sign No with the same nullifier.
        uint256 id = _create(99, PetitionRegistryV2.BallotMode.YesNo);
        bytes32 nul = bytes32(uint256(0x101));
        _sign(id, 1, nul);
        (uint32 y, uint32 n,) = registry.voteCounts(id);
        assertEq(y, 1);
        assertEq(n, 0);

        _revoke(id, nul);
        (y, n,) = registry.voteCounts(id);
        assertEq(y, 0);
        assertEq(n, 0);
        assertEq(registry.signatureCount(id), 0);

        // Re-sign with same nullifier — the clean slot allows it.
        _sign(id, 0, nul);
        (y, n,) = registry.voteCounts(id);
        assertEq(y, 0);
        assertEq(n, 1);
        assertEq(registry.signatureCount(id), 1);
        assertEq(registry.voteByNullifier(id, nul), 1); // 1 + 0
    }

    function test_hasNullifier_viewReturnsCorrectBool_afterSignAndRevoke() public {
        uint256 id = _create(5, PetitionRegistryV2.BallotMode.Signature);
        bytes32 nul = bytes32(uint256(0x202));
        assertFalse(registry.hasNullifier(id, nul));
        _sign(id, 0, nul);
        assertTrue(registry.hasNullifier(id, nul));
        _revoke(id, nul);
        assertFalse(registry.hasNullifier(id, nul));
    }

    function test_voteByNullifier_storesEncodedValue() public {
        // Encoding is `1 + vote`, so vote=0/1/2 -> 1/2/3.
        uint256 id = _create(99, PetitionRegistryV2.BallotMode.YesNoAbstain);
        bytes32 n0 = bytes32(uint256(0x301));
        bytes32 n1 = bytes32(uint256(0x302));
        bytes32 n2 = bytes32(uint256(0x303));
        _sign(id, 0, n0);
        _sign(id, 1, n1);
        _sign(id, 2, n2);
        assertEq(registry.voteByNullifier(id, n0), 1);
        assertEq(registry.voteByNullifier(id, n1), 2);
        assertEq(registry.voteByNullifier(id, n2), 3);
        // Unset slot reads 0.
        assertEq(registry.voteByNullifier(id, bytes32(uint256(0x304))), 0);
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
    uint256 internal constant GENESIS_LEAF_COUNT = 0;

    function setUp() public {
        attester = vm.addr(attesterPk);
        enrollment = new EnrollmentRegistry(
            attester, GENESIS_ROOT, GENESIS_LEAF_COUNT, address(this)
        );
    }

    /// @dev Reproduces backend's signed digest byte-for-byte.
    function _signUpdate(
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes32[] memory newCommitments
    ) internal view returns (bytes memory) {
        bytes32 commitmentsHash = keccak256(abi.encodePacked(newCommitments));
        bytes32 inner = keccak256(abi.encode(
            oldRoot, newRoot, commitmentsHash, block.chainid, address(enrollment)
        ));
        bytes32 ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", inner)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, ethSigned);
        return abi.encodePacked(r, s, v);
    }

    function _singletonBatch(bytes32 c) internal pure returns (bytes32[] memory arr) {
        arr = new bytes32[](1);
        arr[0] = c;
    }

    function test_genesis_state_set() public view {
        assertEq(enrollment.enrollmentRoot(), GENESIS_ROOT);
        assertEq(enrollment.oprfAttester(), attester);
        assertEq(enrollment.leafCount(), GENESIS_LEAF_COUNT);
    }

    function test_previewDigest_matches_test_helper() public view {
        // The contract's `previewDigest` view must produce exactly the
        // same hash the test helper produces — so backend can self-check
        // the digest format by calling the view, independent of any
        // off-chain re-implementation drift.
        bytes32 newRoot = bytes32(uint256(0xFACADE));
        bytes32[] memory commitments = _singletonBatch(bytes32(uint256(1)));
        bytes32 expectedInner = keccak256(abi.encode(
            GENESIS_ROOT,
            newRoot,
            keccak256(abi.encodePacked(commitments)),
            block.chainid,
            address(enrollment)
        ));
        bytes32 expectedEth = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", expectedInner)
        );
        (bytes32 inner, bytes32 ethSigned) = enrollment.previewDigest(newRoot, commitments);
        assertEq(inner, expectedInner);
        assertEq(ethSigned, expectedEth);
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
        assertEq(enrollment.leafCount(), GENESIS_LEAF_COUNT + 2);
        assertTrue(enrollment.isCommitmentUsed(bytes32(uint256(1))));
        assertTrue(enrollment.isCommitmentUsed(bytes32(uint256(2))));
        assertFalse(enrollment.isCommitmentUsed(bytes32(uint256(3))));
    }

    function test_update_root_emits_CommitmentInserted_with_indices() public {
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes32[] memory commitments = new bytes32[](3);
        commitments[0] = bytes32(uint256(0xAA));
        commitments[1] = bytes32(uint256(0xBB));
        commitments[2] = bytes32(uint256(0xCC));
        bytes memory sig = _signUpdate(GENESIS_ROOT, newRoot, commitments);

        vm.expectEmit(true, true, false, false);
        emit EnrollmentRegistry.CommitmentInserted(0, bytes32(uint256(0xAA)));
        vm.expectEmit(true, true, false, false);
        emit EnrollmentRegistry.CommitmentInserted(1, bytes32(uint256(0xBB)));
        vm.expectEmit(true, true, false, false);
        emit EnrollmentRegistry.CommitmentInserted(2, bytes32(uint256(0xCC)));
        enrollment.updateRoot(newRoot, commitments, sig);
        assertEq(enrollment.leafCount(), 3);
    }

    function test_update_root_advances_through_multiple_batches() public {
        bytes32 r0 = GENESIS_ROOT;
        bytes32 r1 = bytes32(uint256(0xA1));
        bytes32 r2 = bytes32(uint256(0xA2));
        bytes32 r3 = bytes32(uint256(0xA3));
        bytes32[] memory b1 = _singletonBatch(bytes32(uint256(0x11)));
        bytes32[] memory b2 = _singletonBatch(bytes32(uint256(0x22)));
        bytes32[] memory b3 = _singletonBatch(bytes32(uint256(0x33)));

        enrollment.updateRoot(r1, b1, _signUpdate(r0, r1, b1));
        assertEq(enrollment.leafCount(), 1);
        enrollment.updateRoot(r2, b2, _signUpdate(r1, r2, b2));
        assertEq(enrollment.leafCount(), 2);
        enrollment.updateRoot(r3, b3, _signUpdate(r2, r3, b3));
        assertEq(enrollment.leafCount(), 3);
        assertEq(enrollment.enrollmentRoot(), r3);
    }

    function test_update_root_rejects_bad_signature() public {
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes32[] memory commitments = _singletonBatch(bytes32(uint256(1)));
        // Sign the right payload with the WRONG key.
        bytes32 inner = keccak256(abi.encode(
            GENESIS_ROOT,
            newRoot,
            keccak256(abi.encodePacked(commitments)),
            block.chainid,
            address(enrollment)
        ));
        bytes32 ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", inner)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(0xDEAD), ethSigned);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        enrollment.updateRoot(newRoot, commitments, sig);
    }

    function test_update_root_rejects_replay() public {
        bytes32 root1 = bytes32(uint256(0xBEEF));
        bytes32[] memory commitments = _singletonBatch(bytes32(uint256(1)));
        bytes memory sig1 = _signUpdate(GENESIS_ROOT, root1, commitments);
        enrollment.updateRoot(root1, commitments, sig1);

        // After the first update enrollmentRoot moved to root1, so the
        // contract recomputes the digest with oldRoot=root1 — the signed
        // signature recovers to a different address now → BadSignature.
        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        enrollment.updateRoot(root1, commitments, sig1);
    }

    function test_update_root_rejects_when_commitments_tampered() public {
        // Signer signs over commitments={A}; relayer slips in
        // commitments={A,B}. The on-chain digest now hashes a different
        // commitmentsHash → BadSignature.
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes32[] memory honest = _singletonBatch(bytes32(uint256(0xAA)));
        bytes memory sig = _signUpdate(GENESIS_ROOT, newRoot, honest);
        bytes32[] memory tampered = new bytes32[](2);
        tampered[0] = bytes32(uint256(0xAA));
        tampered[1] = bytes32(uint256(0xBB));
        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        enrollment.updateRoot(newRoot, tampered, sig);
    }

    function test_update_root_rejects_empty_batch() public {
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes32[] memory empty = new bytes32[](0);
        bytes memory sig = _signUpdate(GENESIS_ROOT, newRoot, empty);
        vm.expectRevert(EnrollmentRegistry.EmptyBatch.selector);
        enrollment.updateRoot(newRoot, empty, sig);
    }

    // ---------- admin / attester rotation ----------

    function test_admin_can_rotate_attester() public {
        address newAttester = address(0xABCD);
        vm.expectEmit(true, true, false, true);
        emit EnrollmentRegistry.OprfAttesterChanged(attester, newAttester);
        enrollment.setOprfAttester(newAttester);
        assertEq(enrollment.oprfAttester(), newAttester);
    }

    function test_non_admin_cannot_rotate_attester() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(EnrollmentRegistry.NotAdmin.selector);
        enrollment.setOprfAttester(address(0xABCD));
    }

    function test_rotate_attester_rejects_zero() public {
        vm.expectRevert(EnrollmentRegistry.ZeroAddress.selector);
        enrollment.setOprfAttester(address(0));
    }

    function test_admin_transfer_moves_lever() public {
        address newAdmin = address(0xADAD);
        vm.expectEmit(true, true, false, true);
        emit EnrollmentRegistry.AdminTransferred(address(this), newAdmin);
        enrollment.transferAdmin(newAdmin);
        vm.expectRevert(EnrollmentRegistry.NotAdmin.selector);
        enrollment.setOprfAttester(address(0xABCD));
        vm.prank(newAdmin);
        enrollment.setOprfAttester(address(0xABCD));
        assertEq(enrollment.oprfAttester(), address(0xABCD));
    }

    function test_deploy_with_placeholder_attester_blocks_updateRoot() public {
        EnrollmentRegistry placeholder = new EnrollmentRegistry(
            address(0), GENESIS_ROOT, GENESIS_LEAF_COUNT, address(this)
        );
        bytes32 newRoot = bytes32(uint256(0xFADE));
        bytes32[] memory commitments = _singletonBatch(bytes32(uint256(1)));
        // Build a sig that would otherwise pass against `placeholder`.
        bytes32 inner = keccak256(abi.encode(
            GENESIS_ROOT,
            newRoot,
            keccak256(abi.encodePacked(commitments)),
            block.chainid,
            address(placeholder)
        ));
        bytes32 ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", inner)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, ethSigned);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        placeholder.updateRoot(newRoot, commitments, sig);

        placeholder.setOprfAttester(attester);
        placeholder.updateRoot(newRoot, commitments, sig);
        assertEq(placeholder.enrollmentRoot(), newRoot);
        assertEq(placeholder.leafCount(), GENESIS_LEAF_COUNT + 1);
    }

    function test_genesis_leaf_count_offsets_first_index() public {
        // The contract supports launching against a backend tree that
        // already has N leaves. The first inserted leaf logs at index N.
        uint256 N = 7;
        EnrollmentRegistry r = new EnrollmentRegistry(
            attester, GENESIS_ROOT, N, address(this)
        );
        bytes32 newRoot = bytes32(uint256(0xF00D));
        bytes32[] memory commitments = _singletonBatch(bytes32(uint256(0xCC)));
        // Have to sign against `r`, not `enrollment`, because address(this)
        // differs in the digest.
        bytes32 inner = keccak256(abi.encode(
            GENESIS_ROOT,
            newRoot,
            keccak256(abi.encodePacked(commitments)),
            block.chainid,
            address(r)
        ));
        bytes32 ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", inner)
        );
        (uint8 v, bytes32 sigR, bytes32 sigS) = vm.sign(attesterPk, ethSigned);
        bytes memory sig = abi.encodePacked(sigR, sigS, v);
        vm.expectEmit(true, true, false, false);
        emit EnrollmentRegistry.CommitmentInserted(N, bytes32(uint256(0xCC)));
        r.updateRoot(newRoot, commitments, sig);
        assertEq(r.leafCount(), N + 1);
    }
}
