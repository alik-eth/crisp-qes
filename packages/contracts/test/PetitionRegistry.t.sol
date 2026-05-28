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

    // Canonical fake P-256 inputs for the happy path.
    // The leaf is the citizen's signing key; the intermediate is the Diia
    // CA whose SPKI commit lives in the trust-root Merkle tree.
    uint256 constant LEAF_PUBKEY_X = uint256(0xA11CE);
    uint256 constant LEAF_PUBKEY_Y = uint256(0xB0B);
    uint256 constant LEAF_SIG_R    = uint256(0xC0FFEE);
    uint256 constant LEAF_SIG_S    = uint256(0xDECAF);
    uint256 constant INTER_PUBKEY_X = uint256(0xCA1FE);
    uint256 constant INTER_PUBKEY_Y = uint256(0xCABA1);
    uint256 constant INTER_SIG_R    = uint256(0x515AB);
    uint256 constant INTER_SIG_S    = uint256(0x517E5);

    bytes32 constant SIGNED_ATTRS_HASH = bytes32(uint256(0xFEED));
    bytes32 constant LEAF_TBS_HASH     = bytes32(uint256(0xBEEF));

    address creator = address(0xC0DE);

    function setUp() public {
        verifier = new MockVerifier();
        registry = new PetitionRegistry(IVerifier(address(verifier)), TRUST_ROOT, DEPOSIT);
        vm.deal(creator, 10 ether);
        // Default: precompile accepts both verifications on the canonical inputs.
        _mockP256(LEAF_TBS_HASH, INTER_SIG_R, INTER_SIG_S, INTER_PUBKEY_X, INTER_PUBKEY_Y, true);
        _mockP256(SIGNED_ATTRS_HASH, LEAF_SIG_R, LEAF_SIG_S, LEAF_PUBKEY_X, LEAF_PUBKEY_Y, true);
    }

    // ---------- helpers ----------

    function _splitHash(bytes32 h) internal pure returns (bytes32 hi, bytes32 lo) {
        hi = bytes32(uint256(h) >> 128);
        lo = bytes32(uint256(h) & ((uint256(1) << 128) - 1));
    }

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
        return _publicInputsFor(id, nullifier, LEAF_TBS_HASH, SIGNED_ATTRS_HASH);
    }

    function _publicInputsFor(
        uint256 id,
        bytes32 nullifier,
        bytes32 leafTbsHash,
        bytes32 signedAttrsHash
    ) internal pure returns (bytes32[] memory pi) {
        (bytes32 tbsHi, bytes32 tbsLo) = _splitHash(leafTbsHash);
        (bytes32 saHi, bytes32 saLo) = _splitHash(signedAttrsHash);
        pi = new bytes32[](11);
        pi[0] = bytes32(id);
        pi[1] = nullifier;
        pi[2] = TRUST_ROOT;
        pi[3] = bytes32(LEAF_PUBKEY_X);
        pi[4] = bytes32(LEAF_PUBKEY_Y);
        pi[5] = bytes32(INTER_PUBKEY_X);
        pi[6] = bytes32(INTER_PUBKEY_Y);
        pi[7] = tbsHi;
        pi[8] = tbsLo;
        pi[9] = saHi;
        pi[10] = saLo;
    }

    function _calldata(uint256 id, bytes32 nul)
        internal
        pure
        returns (PetitionRegistry.SignCalldata memory c)
    {
        c = PetitionRegistry.SignCalldata({
            petitionId: id,
            nullifier: nul,
            leafPubkeyX: LEAF_PUBKEY_X,
            leafPubkeyY: LEAF_PUBKEY_Y,
            leafSigR: LEAF_SIG_R,
            leafSigS: LEAF_SIG_S,
            intermediatePubkeyX: INTER_PUBKEY_X,
            intermediatePubkeyY: INTER_PUBKEY_Y,
            intermediateSigR: INTER_SIG_R,
            intermediateSigS: INTER_SIG_S
        });
    }

    function _sign(uint256 id, bytes32 nul) internal {
        registry.signPetition(_calldata(id, nul), "", _publicInputs(id, nul));
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
        registry.signPetition(_calldata(id, nul), "", pi);
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
        // Override leaf-side precompile to refuse. The intermediate-side
        // mock from setUp still accepts, so the failure is attributed to
        // the leaf signature, not the cert chain.
        _mockP256(SIGNED_ATTRS_HASH, LEAF_SIG_R, LEAF_SIG_S, LEAF_PUBKEY_X, LEAF_PUBKEY_Y, false);
        vm.expectRevert(PetitionRegistry.InvalidSignature.selector);
        _sign(id, nul);
    }

    /// @dev Intermediate signature failure must surface as `InvalidCertChain`,
    ///      not the leaf-side `InvalidSignature` — the cert chain is checked
    ///      first so a forged leaf cert against an unrelated intermediate
    ///      can't masquerade as a "bad signature" anomaly.
    function test_rejects_when_intermediate_precompile_returns_zero() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        _mockP256(LEAF_TBS_HASH, INTER_SIG_R, INTER_SIG_S, INTER_PUBKEY_X, INTER_PUBKEY_Y, false);
        vm.expectRevert(PetitionRegistry.InvalidCertChain.selector);
        _sign(id, nul);
    }

    function test_rejects_when_pubkey_mismatches_public_input() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        // Lie in calldata: leafPubkeyX claimed != publicInputs[3].
        PetitionRegistry.SignCalldata memory c = _calldata(id, nul);
        c.leafPubkeyX = LEAF_PUBKEY_X + 1;
        vm.expectRevert(PetitionRegistry.InvalidProof.selector);
        registry.signPetition(c, "", _publicInputs(id, nul));
    }

    function test_rejects_when_intermediate_pubkey_mismatches_public_input() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        PetitionRegistry.SignCalldata memory c = _calldata(id, nul);
        c.intermediatePubkeyX = INTER_PUBKEY_X + 1;
        vm.expectRevert(PetitionRegistry.InvalidProof.selector);
        registry.signPetition(c, "", _publicInputs(id, nul));
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

    // ---------- hi/lo limb reconstruction ----------

    /// @dev Exercises the failure mode that motivated the hi/lo split: a
    ///      SHA-256 digest whose top bit is set is larger than the BN254
    ///      prime and would have round-tripped to a different value
    ///      through a single Field public input. With the split, the
    ///      contract reassembles each `bytes32` byte-for-byte and feeds
    ///      it to the precompile. We exercise both reassembly paths
    ///      simultaneously (`leafTbsHash` and `signedAttrsHash`).
    function test_hi_lo_roundtrip_with_top_bit_set() public {
        bytes32 highTbs = bytes32(
            0xFFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100
        );
        bytes32 highSa = bytes32(
            0xFEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210
        );
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(42));

        // Both mocks must see the *reassembled* hashes, not the limb form.
        _mockP256(highTbs, INTER_SIG_R, INTER_SIG_S, INTER_PUBKEY_X, INTER_PUBKEY_Y, true);
        _mockP256(highSa, LEAF_SIG_R, LEAF_SIG_S, LEAF_PUBKEY_X, LEAF_PUBKEY_Y, true);

        registry.signPetition(
            _calldata(id, nul),
            "",
            _publicInputsFor(id, nul, highTbs, highSa)
        );
        assertEq(registry.signatureCount(id), 1);

        // Sanity: confirm the round-trip identity actually held.
        (bytes32 tbsHi, bytes32 tbsLo) = _splitHash(highTbs);
        (bytes32 saHi, bytes32 saLo) = _splitHash(highSa);
        assertEq(bytes32((uint256(tbsHi) << 128) | uint256(tbsLo)), highTbs);
        assertEq(bytes32((uint256(saHi) << 128) | uint256(saLo)), highSa);
        // Each limb fits in 128 bits.
        assertEq(uint256(tbsHi) >> 128, 0);
        assertEq(uint256(tbsLo) >> 128, 0);
        assertEq(uint256(saHi) >> 128, 0);
        assertEq(uint256(saLo) >> 128, 0);
    }
}
