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
    uint256 internal constant GENESIS_LEAF_COUNT = 0;
    bytes24 internal constant DOMAIN = "CRISP_QES_OPRF_ROOT_V2.1";

    function setUp() public {
        attester = vm.addr(attesterPk);
        enrollment = new EnrollmentRegistry(
            attester, GENESIS_ROOT, GENESIS_LEAF_COUNT, address(this)
        );
    }

    /// @dev Reproduces the digest backend's OPRF signer is pinned to.
    ///      Must match `EnrollmentRegistry.updateRoot` byte-for-byte.
    function _digest(bytes32 oldRoot, bytes32 newRoot, uint256 leafIndex)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(DOMAIN, oldRoot, newRoot, leafIndex));
    }

    function _signUpdate(bytes32 oldRoot, bytes32 newRoot, uint256 leafIndex)
        internal
        view
        returns (bytes memory)
    {
        bytes32 d = _digest(oldRoot, newRoot, leafIndex);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, d);
        return abi.encodePacked(r, s, v);
    }

    function test_genesis_state_set() public view {
        assertEq(enrollment.enrollmentRoot(), GENESIS_ROOT);
        assertEq(enrollment.oprfAttester(), attester);
        assertEq(enrollment.leafCount(), GENESIS_LEAF_COUNT);
        assertEq(bytes24(enrollment.DOMAIN_OPRF_ROOT()), DOMAIN);
    }

    function test_previewDigest_matches_test_helper() public view {
        // The contract's `previewDigest` view must produce exactly the
        // same hash the test helper produces — so backend can self-check
        // the digest format by calling the view, independent of any
        // off-chain re-implementation drift.
        bytes32 newRoot = bytes32(uint256(0xFACADE));
        uint256 leafIndex = GENESIS_LEAF_COUNT;
        assertEq(
            enrollment.previewDigest(newRoot, leafIndex),
            _digest(GENESIS_ROOT, newRoot, leafIndex)
        );
    }

    function test_update_root_with_valid_signature() public {
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes memory sig = _signUpdate(GENESIS_ROOT, newRoot, GENESIS_LEAF_COUNT);

        vm.expectEmit(true, true, true, true);
        emit EnrollmentRegistry.RootUpdated(
            GENESIS_ROOT, newRoot, GENESIS_LEAF_COUNT, block.number
        );
        enrollment.updateRoot(newRoot, GENESIS_LEAF_COUNT, sig);

        assertEq(enrollment.enrollmentRoot(), newRoot);
        assertEq(enrollment.leafCount(), GENESIS_LEAF_COUNT + 1);
    }

    function test_update_root_advances_through_multiple_inserts() public {
        bytes32 r0 = GENESIS_ROOT;
        bytes32 r1 = bytes32(uint256(0xA1));
        bytes32 r2 = bytes32(uint256(0xA2));
        bytes32 r3 = bytes32(uint256(0xA3));

        enrollment.updateRoot(r1, 0, _signUpdate(r0, r1, 0));
        assertEq(enrollment.leafCount(), 1);
        enrollment.updateRoot(r2, 1, _signUpdate(r1, r2, 1));
        assertEq(enrollment.leafCount(), 2);
        enrollment.updateRoot(r3, 2, _signUpdate(r2, r3, 2));
        assertEq(enrollment.leafCount(), 3);
        assertEq(enrollment.enrollmentRoot(), r3);
    }

    function test_update_root_rejects_bad_signature() public {
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        // Sign the right payload with the WRONG key.
        bytes32 d = _digest(GENESIS_ROOT, newRoot, GENESIS_LEAF_COUNT);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(0xDEAD), d);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        enrollment.updateRoot(newRoot, GENESIS_LEAF_COUNT, sig);
    }

    function test_update_root_rejects_index_mismatch() public {
        // Signature is correctly issued, but leafIndex skips ahead. The
        // contract must reject — strict monotone, no holes.
        bytes32 newRoot = bytes32(uint256(0xBEEF));
        bytes memory sig = _signUpdate(GENESIS_ROOT, newRoot, 5);
        vm.expectRevert(EnrollmentRegistry.IndexMismatch.selector);
        enrollment.updateRoot(newRoot, 5, sig);
    }

    function test_update_root_rejects_replay() public {
        bytes32 root1 = bytes32(uint256(0xBEEF));
        bytes memory sig1 = _signUpdate(GENESIS_ROOT, root1, 0);
        enrollment.updateRoot(root1, 0, sig1);

        // Replaying the same call must fail. After the first update the
        // contract's leafCount is 1, so the IndexMismatch gate trips
        // first (cheaper revert) — that's fine, replay is blocked.
        vm.expectRevert(EnrollmentRegistry.IndexMismatch.selector);
        enrollment.updateRoot(root1, 0, sig1);
    }

    function test_update_root_rejects_when_oldRoot_drifts() public {
        // Sign against the GENESIS_ROOT, then sneak an updateRoot through
        // after the root has already moved. The signature recovers fine
        // off the old digest but the on-chain digest now uses a different
        // oldRoot (the current enrollmentRoot), so ecrecover returns a
        // different address → BadSignature.
        bytes32 root1 = bytes32(uint256(0xBEEF));
        bytes32 root2 = bytes32(uint256(0xCAFE));
        bytes memory sig1 = _signUpdate(GENESIS_ROOT, root1, 0);
        enrollment.updateRoot(root1, 0, sig1);

        // Now try a stale signature signed against GENESIS_ROOT for the
        // next leafIndex (1) — the contract recomputes the digest using
        // the CURRENT enrollmentRoot (= root1), so the recovery diverges.
        bytes32 staleDigest = _digest(GENESIS_ROOT, root2, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, staleDigest);
        bytes memory staleSig = abi.encodePacked(r, s, v);

        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        enrollment.updateRoot(root2, 1, staleSig);
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
        // The old admin loses the lever immediately.
        vm.expectRevert(EnrollmentRegistry.NotAdmin.selector);
        enrollment.setOprfAttester(address(0xABCD));
        // The new admin gains it.
        vm.prank(newAdmin);
        enrollment.setOprfAttester(address(0xABCD));
        assertEq(enrollment.oprfAttester(), address(0xABCD));
    }

    function test_deploy_with_placeholder_attester_blocks_updateRoot() public {
        // Mirrors the DeployV2.s.sol "ship before backend is ready" flow:
        // attester starts at address(0); admin rotates to real later. The
        // attester==0 gate must trip before ecrecover gets to silently
        // return address(0) on malformed input.
        EnrollmentRegistry placeholder = new EnrollmentRegistry(
            address(0), GENESIS_ROOT, GENESIS_LEAF_COUNT, address(this)
        );
        bytes32 newRoot = bytes32(uint256(0xFADE));
        bytes32 d = _digest(GENESIS_ROOT, newRoot, GENESIS_LEAF_COUNT);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPk, d);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(EnrollmentRegistry.BadSignature.selector);
        placeholder.updateRoot(newRoot, GENESIS_LEAF_COUNT, sig);

        // Admin wires the real attester; the same signature now lands.
        placeholder.setOprfAttester(attester);
        placeholder.updateRoot(newRoot, GENESIS_LEAF_COUNT, sig);
        assertEq(placeholder.enrollmentRoot(), newRoot);
        assertEq(placeholder.leafCount(), GENESIS_LEAF_COUNT + 1);
    }

    function test_genesis_leaf_count_offsets_first_index() public {
        // The contract supports launching against a backend tree that
        // already has N leaves (the OPRF service runs ahead of the
        // contract during scaffolding). The first valid leafIndex must
        // equal genesisLeafCount.
        uint256 N = 7;
        EnrollmentRegistry r = new EnrollmentRegistry(
            attester, GENESIS_ROOT, N, address(this)
        );
        bytes32 newRoot = bytes32(uint256(0xF00D));
        // leafIndex=0 is no longer valid because leafCount starts at N.
        bytes memory wrongSig = _signUpdate(GENESIS_ROOT, newRoot, 0);
        vm.expectRevert(EnrollmentRegistry.IndexMismatch.selector);
        r.updateRoot(newRoot, 0, wrongSig);
        // leafIndex=N is the correct first index.
        bytes memory rightSig = _signUpdate(GENESIS_ROOT, newRoot, N);
        r.updateRoot(newRoot, N, rightSig);
        assertEq(r.leafCount(), N + 1);
    }
}
