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
///         **Digest scheme** (pinned with backend / crisp-qes-v2-oprf):
///
///             body  = abi.encodePacked(
///                       bytes24("CRISP_QES_OPRF_ROOT_V2.1"),
///                       oldRoot,                              // bytes32
///                       newRoot,                              // bytes32
///                       leafIndex                             // uint256
///                     )
///             h     = keccak256(body)
///             sig   = secp256k1 over h, NO EIP-191 wrap
///
///         `leafIndex` must equal the registry's current `leafCount`,
///         giving strict-monotone insertion order: replays, reorderings,
///         and forks are all rejected because the next valid signature
///         is always against the just-advanced state.
///
///         **Replay-protection caveat (testnet/prototype only).** The
///         digest does NOT include `block.chainid` or `address(this)`.
///         The `bytes24("CRISP_QES_OPRF_ROOT_V2.1")` domain prefix
///         pins the protocol version, but two registries on the same
///         chain (or one on testnet + one on mainnet) sharing the
///         attester key would both accept the same signed update. For
///         v2.1's grant deliverable that's acceptable — the attester
///         key is bound to a single Fly deployment + single chain.
///         **v2.2 mainnet MUST add chainid + address(this) to the
///         digest** (~2 lines either side, in this contract and in
///         backend's signer).
contract EnrollmentRegistry {
    // ---------- storage ----------

    /// @notice Current enrollment Merkle root. Matches the public input
    ///         slot [1] in the v2 verifier (`enrollment_root`).
    bytes32 public enrollmentRoot;

    /// @notice Number of leaves inserted into the enrollment tree so far.
    ///         The next valid `updateRoot` must carry `leafIndex == leafCount`.
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

    /// @notice Domain tag baked into every `updateRoot` signature.
    ///         Exactly 24 ASCII bytes. Pinned with backend in 2026-05-29
    ///         coordination — DO NOT change without bumping the version
    ///         suffix and re-keying the off-chain signer.
    bytes24 public constant DOMAIN_OPRF_ROOT = "CRISP_QES_OPRF_ROOT_V2.1";

    // ---------- events ----------

    event RootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 indexed leafIndex,
        uint256 blockNumber
    );
    event OprfAttesterChanged(address indexed oldAttester, address indexed newAttester);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    // ---------- errors ----------

    error BadSignature();
    error IndexMismatch();
    error NotAdmin();
    error ZeroAddress();

    // ---------- construction ----------

    /// @param oprfAttester_    Initial attester. May be a placeholder when
    ///                         backend's key isn't ready; admin can rotate
    ///                         via `setOprfAttester` later.
    /// @param genesisRoot      Initial enrollment Merkle root. Must equal
    ///                         the root backend's tree is currently at.
    ///                         For an empty depth-20 zero-tree pass that
    ///                         tree's known root; for a backfilled tree
    ///                         pass backend's `currentRoot`.
    /// @param genesisLeafCount Number of leaves already inserted into
    ///                         backend's tree at deploy time. The next
    ///                         signed `updateRoot` must carry
    ///                         `leafIndex == genesisLeafCount`. Typically
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
        // oprfAttester_ may be zero at deploy time (the deploy script
        // ships a placeholder when backend's real key is still pending).
        // setOprfAttester wires up the real value before the first
        // updateRoot is attempted; the updateRoot path hard-rejects
        // attester==address(0) so this is safe.
        oprfAttester = oprfAttester_;
        admin = admin_;
        enrollmentRoot = genesisRoot;
        leafCount = genesisLeafCount;
        emit RootUpdated(bytes32(0), genesisRoot, genesisLeafCount, block.number);
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

    /// @notice Advance the enrollment root by one leaf. Anyone may call
    ///         this; the gate is the attester-signed digest. Each call
    ///         inserts the leaf at position `leafIndex` and bumps
    ///         `leafCount` to `leafIndex + 1`.
    ///
    /// @param  newRoot   New Pedersen-Merkle root after inserting the
    ///                   leaf at `leafIndex`.
    /// @param  leafIndex Insertion position. MUST equal the current
    ///                   `leafCount` (strict monotone).
    /// @param  signature 65-byte ECDSA `(r, s, v)` from `oprfAttester`
    ///                   over the digest defined in the contract header.
    function updateRoot(
        bytes32 newRoot,
        uint256 leafIndex,
        bytes calldata signature
    ) external {
        // Strict-monotone insertion. Replays, reorderings, and forks all
        // bounce here because the next valid leafIndex is always the
        // just-advanced count.
        if (leafIndex != leafCount) revert IndexMismatch();
        // Block updates until the real attester is wired up. Without this
        // guard a placeholder-deployed registry would accept any garbage
        // signature whose recovery yields address(0) (which is what
        // ecrecover returns for malformed inputs).
        if (oprfAttester == address(0)) revert BadSignature();

        bytes32 oldRoot = enrollmentRoot;
        bytes32 digest = keccak256(
            abi.encodePacked(DOMAIN_OPRF_ROOT, oldRoot, newRoot, leafIndex)
        );
        // NO EIP-191 wrap — backend signs `h` directly. See contract
        // header for the digest scheme rationale.
        address recovered = _recover(digest, signature);
        if (recovered != oprfAttester) revert BadSignature();

        enrollmentRoot = newRoot;
        unchecked {
            // Overflow is impossible in practice: TREE_DEPTH=20 caps the
            // tree at 2^20 leaves and the gate above rejects any index
            // outside `[0, leafCount]`. `unchecked` saves a few gas per
            // update.
            leafCount = leafIndex + 1;
        }
        emit RootUpdated(oldRoot, newRoot, leafIndex, block.number);
    }

    // ---------- views ----------

    /// @notice Reconstruct the exact 32-byte digest the off-chain signer
    ///         must sign for a given `(newRoot, leafIndex)` against the
    ///         current `enrollmentRoot`. Exposed so backend's signer can
    ///         self-check without re-implementing the encoding.
    function previewDigest(bytes32 newRoot, uint256 leafIndex)
        external
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(DOMAIN_OPRF_ROOT, enrollmentRoot, newRoot, leafIndex)
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
