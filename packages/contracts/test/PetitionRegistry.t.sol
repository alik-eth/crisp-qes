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
    // CA whose SPKI commit lives in the trust-root Merkle tree. All four
    // pubkey coordinates are now published as 128-bit limb pairs through
    // the public-input array, so the contract reassembles them inside
    // `signPetition` rather than reading them from calldata directly.
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

    function _splitU256(uint256 v) internal pure returns (bytes32 hi, bytes32 lo) {
        hi = bytes32(v >> 128);
        lo = bytes32(v & ((uint256(1) << 128) - 1));
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
        return _publicInputsFor(
            id,
            nullifier,
            LEAF_PUBKEY_X,
            LEAF_PUBKEY_Y,
            INTER_PUBKEY_X,
            INTER_PUBKEY_Y,
            LEAF_TBS_HASH,
            SIGNED_ATTRS_HASH
        );
    }

    function _publicInputsFor(
        uint256 id,
        bytes32 nullifier,
        uint256 leafX,
        uint256 leafY,
        uint256 interX,
        uint256 interY,
        bytes32 leafTbsHash,
        bytes32 signedAttrsHash
    ) internal pure returns (bytes32[] memory pi) {
        pi = new bytes32[](15);
        pi[0] = bytes32(id);
        pi[1] = nullifier;
        pi[2] = TRUST_ROOT;
        _writeU256Limbs(pi, 3, leafX);
        _writeU256Limbs(pi, 5, leafY);
        _writeU256Limbs(pi, 7, interX);
        _writeU256Limbs(pi, 9, interY);
        _writeHashLimbs(pi, 11, leafTbsHash);
        _writeHashLimbs(pi, 13, signedAttrsHash);
    }

    function _writeU256Limbs(bytes32[] memory pi, uint256 at, uint256 v) internal pure {
        (bytes32 hi, bytes32 lo) = _splitU256(v);
        pi[at] = hi;
        pi[at + 1] = lo;
    }

    function _writeHashLimbs(bytes32[] memory pi, uint256 at, bytes32 h) internal pure {
        (bytes32 hi, bytes32 lo) = _splitHash(h);
        pi[at] = hi;
        pi[at + 1] = lo;
    }

    function _calldata(uint256 id, bytes32 nul)
        internal
        pure
        returns (PetitionRegistry.SignCalldata memory c)
    {
        c = PetitionRegistry.SignCalldata({
            petitionId: id,
            nullifier: nul,
            leafSigR: LEAF_SIG_R,
            leafSigS: LEAF_SIG_S,
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

    /// @dev Lying about the leaf pubkey: the prover supplies limb pairs
    ///      that reconstruct to a pubkey the precompile mock isn't set up
    ///      to accept, so the leaf-side P256.verify returns 0 and the
    ///      contract reverts with `InvalidSignature`. This replaces the
    ///      old "pubkey != publicInputs[3]" pre-flight check (no such
    ///      check exists anymore — pubkeys *come from* publicInputs).
    function test_rejects_when_leaf_pubkey_limbs_mismatch() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputsFor(
            id,
            nul,
            LEAF_PUBKEY_X + 1, // tampered
            LEAF_PUBKEY_Y,
            INTER_PUBKEY_X,
            INTER_PUBKEY_Y,
            LEAF_TBS_HASH,
            SIGNED_ATTRS_HASH
        );
        vm.expectRevert(PetitionRegistry.InvalidSignature.selector);
        registry.signPetition(_calldata(id, nul), "", pi);
    }

    function test_rejects_when_intermediate_pubkey_limbs_mismatch() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputsFor(
            id,
            nul,
            LEAF_PUBKEY_X,
            LEAF_PUBKEY_Y,
            INTER_PUBKEY_X + 1, // tampered
            INTER_PUBKEY_Y,
            LEAF_TBS_HASH,
            SIGNED_ATTRS_HASH
        );
        vm.expectRevert(PetitionRegistry.InvalidCertChain.selector);
        registry.signPetition(_calldata(id, nul), "", pi);
    }

    /// @dev A limb with bits above 2^128 violates the on-chain invariant
    ///      that each limb is a 128-bit half. The contract gates this with
    ///      `>> 128 != 0` before even calling the ZK verifier.
    function test_rejects_oversized_pubkey_limb() public {
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(1));
        bytes32[] memory pi = _publicInputs(id, nul);
        // Set bit 200 in the leaf_x_hi slot — clearly outside the 128-bit window.
        pi[3] = bytes32((uint256(1) << 200) | uint256(pi[3]));
        vm.expectRevert(PetitionRegistry.InvalidProof.selector);
        registry.signPetition(_calldata(id, nul), "", pi);
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

    /// @dev Exercises the failure mode that motivated all hi/lo splits:
    ///      P-256 coordinates and SHA-256 digests whose top bit is set
    ///      exceed the BN254 prime and would have round-tripped to a
    ///      different value through a single Field public input. With
    ///      the splits, the contract reassembles each 256-bit value
    ///      byte-for-byte from its two 128-bit limbs and feeds it to the
    ///      precompile. We exercise all four reassembly paths
    ///      (leaf pubkey, intermediate pubkey, leafTbsHash, signedAttrsHash)
    ///      simultaneously by setting the top bit on every one.
    function test_hi_lo_roundtrip_with_top_bit_set() public {
        // All four 256-bit values have their top bit set (top byte 0xFF /
        // 0x80) — the exact pattern that the user's Diia demo fixture
        // tripped over (leaf pubkey.x = 0x83db…).
        uint256 leafX  = 0x83db112233445566778899aabbccddeeff00112233445566778899aabbccddee;
        uint256 leafY  = 0xc0bb112233445566778899aabbccddeeff00112233445566778899aabbccddee;
        uint256 interX = 0xfe11223344556677889900aabbccddeeff112233445566778899aabbccdd0011;
        uint256 interY = 0x80aaccee11223344556677889900112233445566778899aabbccddee00112233;
        bytes32 highTbs = bytes32(
            0xFFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100
        );
        bytes32 highSa = bytes32(
            0xFEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210
        );
        uint256 id = _create(3);
        bytes32 nul = bytes32(uint256(42));

        // All four precompile mocks must see the *reassembled* values.
        _mockP256(highTbs, INTER_SIG_R, INTER_SIG_S, interX, interY, true);
        _mockP256(highSa, LEAF_SIG_R, LEAF_SIG_S, leafX, leafY, true);

        registry.signPetition(
            _calldata(id, nul),
            "",
            _publicInputsFor(id, nul, leafX, leafY, interX, interY, highTbs, highSa)
        );
        assertEq(registry.signatureCount(id), 1);

        // Sanity: every 256-bit value round-trips through the limb split.
        _assertU256RoundTrips(leafX);
        _assertU256RoundTrips(leafY);
        _assertU256RoundTrips(interX);
        _assertU256RoundTrips(interY);
        _assertHashRoundTrips(highTbs);
        _assertHashRoundTrips(highSa);
    }

    function _assertU256RoundTrips(uint256 v) internal pure {
        (bytes32 hi, bytes32 lo) = _splitU256(v);
        require(uint256(hi) >> 128 == 0, "hi limb leaks");
        require(uint256(lo) >> 128 == 0, "lo limb leaks");
        require(((uint256(hi) << 128) | uint256(lo)) == v, "u256 round-trip mismatch");
    }

    function _assertHashRoundTrips(bytes32 h) internal pure {
        (bytes32 hi, bytes32 lo) = _splitHash(h);
        require(uint256(hi) >> 128 == 0, "hi limb leaks");
        require(uint256(lo) >> 128 == 0, "lo limb leaks");
        require(bytes32((uint256(hi) << 128) | uint256(lo)) == h, "bytes32 round-trip mismatch");
    }
}
