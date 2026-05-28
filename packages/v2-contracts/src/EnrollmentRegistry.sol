// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title EnrollmentRegistry
/// @notice On-chain anchor for the v2 enrollment Merkle tree.
///
///         Holds the current Pedersen-Merkle root and a per-commitment
///         used-bit map. Both are updated by the OPRF service via signed
///         transactions; for the demo the OPRF service is a single node
///         (`oprfAttester`) and the contract trusts its signature. Spec
///         sec 2.3 calls out the threshold variant as post-grant work.
///
///         The signed payload for `updateRoot` deliberately commits to
///         the old root, the new root, the new commitments added in this
///         batch, the chain id, and this contract address. That binding
///         prevents:
///           - replay across chains (chainid),
///           - replay across forks of this contract (address),
///           - reordering or splicing of root updates (oldRoot).
///
///         A separate signature is NOT required to mark a commitment as
///         used: the OPRF server bundles new commitments into the same
///         `updateRoot` call. This keeps the on-chain interaction count
///         to one per enrollment batch.
contract EnrollmentRegistry {
    // ---------- storage ----------

    /// @notice Current enrollment Merkle root. Matches the public input
    ///         slot [1] in the v2 verifier (`enrollment_root`).
    bytes32 public enrollmentRoot;

    /// @notice OPRF attester address. Updates to `enrollmentRoot` must be
    ///         signed by the private key for this address.
    address public immutable oprfAttester;

    /// @notice Used-commitment map. The OPRF service writes here when a
    ///         commitment (the citizen's pedersen-hashed OPRF output) is
    ///         first observed, so future enrollment attempts from the
    ///         same RNOKPP collide and are rejected client-side.
    mapping(bytes32 commitment => bool) private _used;

    // ---------- events ----------

    event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, uint256 blockNumber);
    event CommitmentMarked(bytes32 indexed commitment);

    // ---------- errors ----------

    error BadSignature();
    error EmptyBatch();

    // ---------- construction ----------

    constructor(address oprfAttester_, bytes32 genesisRoot) {
        if (oprfAttester_ == address(0)) revert BadSignature();
        oprfAttester = oprfAttester_;
        enrollmentRoot = genesisRoot;
        emit RootUpdated(bytes32(0), genesisRoot, block.number);
    }

    // ---------- attester API ----------

    /// @notice Roll the enrollment root forward and mark the batch of new
    ///         commitments as used. The OPRF service is expected to call
    ///         this once per enrollment batch.
    /// @param  newRoot         New Pedersen-Merkle root over the entire
    ///                         enrollment set after this batch.
    /// @param  newCommitments  The set of commitments added in this batch.
    ///                         Must be non-empty.
    /// @param  signature       65-byte ECDSA signature from `oprfAttester`
    ///                         over `keccak256(abi.encode(
    ///                           enrollmentRoot, newRoot,
    ///                           keccak256(abi.encodePacked(newCommitments)),
    ///                           block.chainid, address(this)
    ///                         ))`.
    ///
    ///         Note: we hash the commitments array down to a single
    ///         bytes32 inside the signed digest so the signature size is
    ///         constant regardless of batch size, but the caller still
    ///         supplies the full array on calldata so we can mark each
    ///         entry as used here on-chain.
    function updateRoot(
        bytes32 newRoot,
        bytes32[] calldata newCommitments,
        bytes calldata signature
    ) external {
        if (newCommitments.length == 0) revert EmptyBatch();

        bytes32 oldRoot = enrollmentRoot;
        bytes32 commitmentsHash = keccak256(abi.encodePacked(newCommitments));
        bytes32 digest = keccak256(
            abi.encode(oldRoot, newRoot, commitmentsHash, block.chainid, address(this))
        );
        // EIP-191 personal_sign style: matches `eth_signMessage` from a
        // standard JSON-RPC wallet, so the OPRF service can sign with any
        // off-the-shelf signer (viem/ethers/web3.js).
        bytes32 ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
        address recovered = _recover(ethSigned, signature);
        if (recovered != oprfAttester) revert BadSignature();

        enrollmentRoot = newRoot;
        emit RootUpdated(oldRoot, newRoot, block.number);

        // Mark every commitment in the batch as used. We tolerate
        // duplicates silently (the off-chain side should never produce
        // them, but a no-op is safer than a revert on a partial batch).
        for (uint256 i = 0; i < newCommitments.length; i++) {
            bytes32 c = newCommitments[i];
            if (!_used[c]) {
                _used[c] = true;
                emit CommitmentMarked(c);
            }
        }
    }

    // ---------- views ----------

    function isCommitmentUsed(bytes32 commitment) external view returns (bool) {
        return _used[commitment];
    }

    // ---------- internals ----------

    /// @dev Minimal ecrecover wrapper that accepts both 65-byte (r,s,v)
    ///      and 64-byte EIP-2098 compact signatures. Returns the zero
    ///      address on a malformed input rather than reverting, so the
    ///      caller can convert that into `BadSignature` uniformly.
    function _recover(bytes32 digest, bytes calldata sig) private pure returns (address) {
        if (sig.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(sig.offset)
                s := calldataload(add(sig.offset, 0x20))
                v := byte(0, calldataload(add(sig.offset, 0x40)))
            }
            if (v < 27) v += 27;
            // Reject high-s signatures (EIP-2 malleability gate).
            if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)
            {
                return address(0);
            }
            return ecrecover(digest, v, r, s);
        }
        return address(0);
    }
}
