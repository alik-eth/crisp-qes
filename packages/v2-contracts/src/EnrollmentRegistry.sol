// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title EnrollmentRegistry
/// @notice On-chain anchor for the v2 enrollment Merkle tree.
///
///         Holds the current Pedersen-Merkle root and a strict-monotone
///         leaf insertion counter. Both advance via attester-signed
///         `updateRoot` calls; for the demo the OPRF service is a
///         single node (`oprfAttester`) and the contract trusts its
///         signature. Spec sec 2.3 calls out the threshold variant as
///         post-grant work.
///
///         **Digest scheme** (pinned with team-lead 2026-05-29 and
///         implemented byte-for-byte by backend at crisp-qes-v2-oprf):
///
///             commitmentsHash = keccak256(abi.encodePacked(newCommitments))
///             inner           = keccak256(abi.encode(
///                                 oldRoot,                  // bytes32
///                                 newRoot,                  // bytes32
///                                 commitmentsHash,          // bytes32
///                                 block.chainid,            // uint256
///                                 address(this)             // address
///                               ))
///             ethSigned       = keccak256(abi.encodePacked(
///                                 "\x19Ethereum Signed Message:\n32",
///                                 inner
///                               ))
///             sig             = secp256k1 (r, s, v) over ethSigned
///
///         This is the EIP-191 personal_sign envelope, so the OPRF
///         service can use any off-the-shelf signer (viem's
///         `signMessage({ message: { raw: inner } })`, ethers'
///         `signMessage(arrayify(inner))`) and the contract gate matches
///         what `MessageHashUtils.toEthSignedMessageHash` produces.
///
///         The chain id + contract address inside `inner` prevent
///         cross-chain and cross-instance replay even when the same
///         attester key is reused across deploys.
///
///         **Strict-monotone insertion.** `leafCount` advances by
///         `newCommitments.length` per accepted call. The (oldRoot,
///         newRoot) binding inside the digest already prevents replay
///         within a single registry: once we move past `newRoot` the
///         signed `oldRoot` no longer matches `enrollmentRoot`. The
///         leafCount counter is for off-chain indexers + tests.
contract EnrollmentRegistry {
    // ---------- storage ----------

    /// @notice Current enrollment Merkle root. Matches the public input
    ///         slot [1] in the v2 verifier (`enrollment_root`).
    bytes32 public enrollmentRoot;

    /// @notice Number of leaves inserted into the enrollment tree so far.
    ///         Bumped by `newCommitments.length` per accepted `updateRoot`.
    ///         At deploy time set from `genesisLeafCount` so the registry
    ///         can launch in sync with backend's pre-existing tree state.
    uint256 public leafCount;

    /// @notice OPRF attester address. Updates to `enrollmentRoot` must be
    ///         signed by the private key for this address. Mutable via
    ///         `setOprfAttester` so the deploy script can ship with a
    ///         placeholder before backend's real key is provisioned, and
    ///         so we can rotate it without redeploying. The migration
    ///         story to a threshold OPRF (spec sec 2.3 post-grant) also
    ///         needs this lever.
    address public oprfAttester;

    /// @notice Admin authorised to rotate `oprfAttester`. Set at construction;
    ///         can be moved with `transferAdmin`. Distinct from `oprfAttester`
    ///         so a compromised attester key cannot rotate itself.
    address public admin;

    /// @notice Used-commitment map. Populated inside `updateRoot` for
    ///         every leaf the attester publishes. Off-chain clients can
    ///         use this to surface "already enrolled" errors before
    ///         submitting a new attestation. Spec sec 2.3.
    mapping(bytes32 commitment => bool) private _used;

    // ---------- events ----------

    event RootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, uint256 blockNumber);
    event CommitmentInserted(uint256 indexed leafIndex, bytes32 indexed commitment);
    event OprfAttesterChanged(address indexed oldAttester, address indexed newAttester);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    // ---------- errors ----------

    error BadSignature();
    error EmptyBatch();
    error NotAdmin();
    error ZeroAddress();

    // ---------- construction ----------

    /// @param oprfAttester_    Initial attester. May be a placeholder when
    ///                         backend's key isn't ready; admin can rotate
    ///                         via `setOprfAttester` later.
    /// @param genesisRoot      Initial enrollment Merkle root. Must equal
    ///                         the root backend's tree is currently at.
    ///                         For an empty depth-20 zero-tree pass the
    ///                         canonical zero-tree root.
    /// @param genesisLeafCount Number of leaves already inserted into
    ///                         backend's tree at deploy time. Typically
    ///                         `0` for a fresh deploy.
    /// @param admin_           Address allowed to rotate the attester. The
    ///                         deploy script defaults this to `msg.sender`
    ///                         so the deployer keeps the lever; pass a
    ///                         multisig here for production.
    constructor(
        address oprfAttester_,
        bytes32 genesisRoot,
        uint256 genesisLeafCount,
        address admin_
    ) {
        if (admin_ == address(0)) revert ZeroAddress();
        oprfAttester = oprfAttester_;
        admin = admin_;
        enrollmentRoot = genesisRoot;
        leafCount = genesisLeafCount;
        emit RootUpdated(bytes32(0), genesisRoot, block.number);
        emit OprfAttesterChanged(address(0), oprfAttester_);
        emit AdminTransferred(address(0), admin_);
    }

    // ---------- admin API ----------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    /// @notice Rotate the OPRF attester. Admin-only. Useful for the
    ///         "ship before backend is ready" workflow and for the
    ///         eventual threshold-OPRF migration (spec sec 2.3).
    function setOprfAttester(address newAttester) external onlyAdmin {
        if (newAttester == address(0)) revert ZeroAddress();
        address old = oprfAttester;
        oprfAttester = newAttester;
        emit OprfAttesterChanged(old, newAttester);
    }

    /// @notice Hand the admin role to a new address (e.g. multisig).
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        address old = admin;
        admin = newAdmin;
        emit AdminTransferred(old, newAdmin);
    }

    // ---------- attester API ----------

    /// @notice Advance the enrollment root and bind the leaves inserted
    ///         in this batch. Anyone may call this; the gate is the
    ///         attester-signed digest. Each commitment is marked used
    ///         and emitted as a `CommitmentInserted` event keyed by its
    ///         leaf index.
    ///
    /// @param  newRoot         New Pedersen-Merkle root after inserting
    ///                         `newCommitments`.
    /// @param  newCommitments  Leaves added in this batch. Length >= 1.
    ///                         Each is `s = pedersen([N_hi, N_lo], 0)`
    ///                         per the v2 formula pin.
    /// @param  signature       65-byte ECDSA `(r, s, v)` from
    ///                         `oprfAttester` over the EIP-191-wrapped
    ///                         digest defined in the contract header.
    function updateRoot(
        bytes32 newRoot,
        bytes32[] calldata newCommitments,
        bytes calldata signature
    ) external {
        if (newCommitments.length == 0) revert EmptyBatch();
        // Block updates until the real attester is wired up. Without this
        // guard a placeholder-deployed registry would accept any garbage
        // signature whose recovery yields address(0).
        if (oprfAttester == address(0)) revert BadSignature();

        bytes32 oldRoot = enrollmentRoot;
        bytes32 commitmentsHash = keccak256(abi.encodePacked(newCommitments));
        bytes32 inner = keccak256(abi.encode(
            oldRoot, newRoot, commitmentsHash, block.chainid, address(this)
        ));
        // EIP-191 personal_sign envelope. Matches viem
        // `signMessage({ message: { raw: inner } })` and OZ
        // `MessageHashUtils.toEthSignedMessageHash(inner)`.
        bytes32 ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", inner)
        );
        address recovered = _recover(ethSigned, signature);
        if (recovered != oprfAttester) revert BadSignature();

        enrollmentRoot = newRoot;
        uint256 baseIndex = leafCount;
        unchecked {
            // Overflow is impossible in practice: TREE_DEPTH=20 caps the
            // tree at 2^20 leaves.
            leafCount = baseIndex + newCommitments.length;
        }
        emit RootUpdated(oldRoot, newRoot, block.number);

        for (uint256 i = 0; i < newCommitments.length; i++) {
            bytes32 c = newCommitments[i];
            // Duplicates are tolerated silently (backend already enforces
            // uniqueness at /oprf/register; a no-op here is safer than a
            // partial-batch revert).
            if (!_used[c]) {
                _used[c] = true;
                unchecked {
                    emit CommitmentInserted(baseIndex + i, c);
                }
            }
        }
    }

    // ---------- views ----------

    function isCommitmentUsed(bytes32 commitment) external view returns (bool) {
        return _used[commitment];
    }

    /// @notice Reconstruct the exact 32-byte digest backend must sign for
    ///         a `(newRoot, newCommitments)` batch against the current
    ///         `enrollmentRoot`. Exposed so backend's signer can
    ///         self-check without re-implementing the encoding.
    function previewDigest(bytes32 newRoot, bytes32[] calldata newCommitments)
        external
        view
        returns (bytes32 inner, bytes32 ethSigned)
    {
        bytes32 commitmentsHash = keccak256(abi.encodePacked(newCommitments));
        inner = keccak256(abi.encode(
            enrollmentRoot, newRoot, commitmentsHash, block.chainid, address(this)
        ));
        ethSigned = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", inner)
        );
    }

    // ---------- internals ----------

    /// @dev Minimal ecrecover wrapper. Accepts the canonical 65-byte
    ///      (r, s, v) layout. Returns the zero address on a malformed
    ///      input rather than reverting, so the caller can convert that
    ///      into `BadSignature` uniformly.
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
