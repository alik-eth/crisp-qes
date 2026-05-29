// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifierV2} from "./IVerifierV2.sol";
import {EnrollmentRegistry} from "./EnrollmentRegistry.sol";

/// @title PetitionRegistryV2
/// @notice v2 petition registry. A petition is a one-directional support
///         instrument: an enrolled citizen *signs* to support it, and may
///         *revoke* (withdraw) that signature until the deadline. The
///         threshold counts active (un-revoked) signatures.
///
///         There is deliberately NO Yes/No/Abstain ballot. Not signing is
///         the dissent; a multi-choice vote is a different instrument
///         (a referendum/poll) with different legitimacy rules and is out
///         of scope for this contract.
///
///         The off-chain Diia QES + CAdES walk is gone; eligibility is now
///         reduced to membership in the `EnrollmentRegistry`'s Merkle tree,
///         gated by a single 3-public-input UltraHonk proof.
///
///         See `docs/specs/2026-05-29-crisp-qes-v2-refined.md` sec 3 and
///         the partner v2 circuit at `packages/circuit/src/main.nr`.
///
///         Public-input layout (FIXED, asserted in `signPetition`):
///           [0]  petition_id
///           [1]  enrollment_root
///           [2]  nullifier
contract PetitionRegistryV2 {
    // ---------- types ----------

    struct Petition {
        address creator;
        uint64 createdAt;
        uint64 deadline;
        uint32 threshold;
        uint32 signatureCount; // active (un-revoked) signatures
        bool thresholdReached;
        bool depositRefunded;
        bytes32 textHash; // keccak256(fullText)
        bytes fullText;   // UTF-8, on-chain (gas-bounded; see MVP spec sec 7 Q2)
    }

    // ---------- storage ----------

    IVerifierV2 public immutable verifier;
    EnrollmentRegistry public immutable enrollmentRegistry;
    uint256 public immutable CREATION_DEPOSIT;

    uint256 public nextPetitionId = 1;
    mapping(uint256 => Petition) internal _petitions;
    /// @notice Per-(petition, nullifier) "has this citizen signed?" flag.
    ///         `false` = not signed (or revoked); `true` = an active
    ///         signature. `revokeVote` flips it back to `false` so the
    ///         citizen can re-sign later.
    mapping(uint256 => mapping(bytes32 => bool)) internal _signed;

    // ---------- events ----------

    event PetitionCreated(
        uint256 indexed id,
        address indexed creator,
        uint64 deadline,
        uint32 threshold
    );
    event PetitionSigned(uint256 indexed id, bytes32 indexed nullifier, uint32 newCount);
    /// @notice Emitted when a citizen revokes a previously-recorded
    ///         signature. `newCount` mirrors the field emitted by
    ///         `PetitionSigned` (the post-decrement `signatureCount`).
    event PetitionRevoked(uint256 indexed id, bytes32 indexed nullifier, uint32 newCount);
    event ThresholdReached(uint256 indexed id, uint32 threshold, uint64 reachedAt);
    event DepositLocked(uint256 indexed id, uint256 amount);
    event DepositRefunded(uint256 indexed id, uint256 amount);

    // ---------- errors ----------

    error EmptyText();
    error TextTooLarge();
    error DeadlineInPast();
    error UnknownPetition();
    error PetitionClosed();
    error NullifierAlreadyUsed();
    error NullifierNotUsed();
    error InvalidProof();
    error InvalidEnrollmentRoot();
    error WrongDeposit();
    error NotCreator();
    error DepositAlreadyRefunded();
    error PetitionStillOpen();
    error RefundTransferFailed();

    uint256 public constant MAX_TEXT_BYTES = 8 * 1024;
    uint256 public constant DEFAULT_CREATION_DEPOSIT = 0.001 ether;

    // ---------- construction ----------

    constructor(
        IVerifierV2 verifier_,
        EnrollmentRegistry enrollmentRegistry_,
        uint256 creationDeposit_
    ) {
        verifier = verifier_;
        enrollmentRegistry = enrollmentRegistry_;
        CREATION_DEPOSIT = creationDeposit_;
    }

    // ---------- creator API ----------

    /// @notice Create a petition. Caller must attach exactly
    ///         `CREATION_DEPOSIT` wei. The deposit is locked until
    ///         `deadline` passes and is then refundable via
    ///         `withdrawDeposit`.
    function createPetition(
        bytes calldata fullText,
        uint64 deadline,
        uint32 threshold
    ) external payable returns (uint256 id) {
        if (msg.value != CREATION_DEPOSIT) revert WrongDeposit();
        if (fullText.length == 0) revert EmptyText();
        if (fullText.length > MAX_TEXT_BYTES) revert TextTooLarge();
        if (deadline <= block.timestamp) revert DeadlineInPast();

        id = nextPetitionId++;
        Petition storage p = _petitions[id];
        p.creator = msg.sender;
        p.createdAt = uint64(block.timestamp);
        p.deadline = deadline;
        p.threshold = threshold;
        p.textHash = keccak256(fullText);
        p.fullText = fullText;

        emit PetitionCreated(id, msg.sender, deadline, threshold);
        emit DepositLocked(id, msg.value);
    }

    /// @notice Refund the creation deposit to the petition's creator. May
    ///         only be called once and only after the petition's deadline
    ///         has passed. Refunded irrespective of whether the threshold
    ///         was reached. Identical machinery to the MVP.
    function withdrawDeposit(uint256 id) external {
        Petition storage p = _petitions[id];
        if (p.creator == address(0)) revert UnknownPetition();
        if (msg.sender != p.creator) revert NotCreator();
        if (block.timestamp <= p.deadline) revert PetitionStillOpen();
        if (p.depositRefunded) revert DepositAlreadyRefunded();

        p.depositRefunded = true;
        (bool ok,) = payable(p.creator).call{value: CREATION_DEPOSIT}("");
        if (!ok) revert RefundTransferFailed();
        emit DepositRefunded(id, CREATION_DEPOSIT);
    }

    // ---------- signer API ----------

    /// @notice Submit a privacy-preserving signature (support) for a
    ///         petition.
    ///
    ///         The proof binds `(petitionId, enrollmentRoot, nullifier)`.
    ///         The contract additionally enforces:
    ///           - the proof's `enrollmentRoot` slot matches the *current*
    ///             on-chain root (so an enrolled citizen can only sign
    ///             under a root the OPRF service has anchored);
    ///           - the nullifier hasn't already signed this petition.
    ///
    /// @param petitionId   Target petition id.
    /// @param nullifier    Per-(citizen, petition) nullifier, also pinned
    ///                     in `publicInputs[2]`.
    /// @param proof        UltraHonk proof bytes from the v2 circuit.
    /// @param publicInputs Length-3 array: `[petition_id, enrollment_root,
    ///                     nullifier]`. Must match the v2 circuit's public
    ///                     input order.
    function signPetition(
        uint256 petitionId,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        Petition storage pet = _petitions[petitionId];
        if (pet.creator == address(0)) revert UnknownPetition();
        if (block.timestamp > pet.deadline) revert PetitionClosed();
        if (_signed[petitionId][nullifier]) revert NullifierAlreadyUsed();

        // Public-input shape check.
        if (publicInputs.length != 3) revert InvalidProof();
        if (uint256(publicInputs[0]) != petitionId) revert InvalidProof();
        if (publicInputs[2] != nullifier) revert InvalidProof();
        if (publicInputs[1] != enrollmentRegistry.enrollmentRoot()) {
            revert InvalidEnrollmentRoot();
        }

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        _signed[petitionId][nullifier] = true;
        uint32 newCount = ++pet.signatureCount;

        emit PetitionSigned(petitionId, nullifier, newCount);

        if (!pet.thresholdReached && newCount >= pet.threshold) {
            pet.thresholdReached = true;
            emit ThresholdReached(petitionId, pet.threshold, uint64(block.timestamp));
        }
    }

    /// @notice Revoke a previously-recorded signature. Frees the
    ///         `(petitionId, nullifier)` slot so the citizen can re-sign
    ///         later.
    ///
    ///         Requires a fresh proof against the current enrollment root —
    ///         identical shape to `signPetition`, no zk changes — to make
    ///         sure only the slot's owner can revoke it (the nullifier in
    ///         `publicInputs[2]` is bound to the signer's secret by the
    ///         circuit).
    ///
    /// @dev `thresholdReached` is intentionally NOT cleared: once a petition
    ///      has crossed its threshold, the political fact is "logged" and
    ///      revocations cannot retroactively un-cross it. This matches the
    ///      spec's sticky-threshold invariant. (A threshold-reached petition
    ///      leaves the Open state, so revoke reverts with PetitionClosed.)
    ///
    /// @param petitionId   Target petition id.
    /// @param nullifier    The same nullifier used in the prior
    ///                     `signPetition` call.
    /// @param proof        UltraHonk proof bytes from the v2 circuit.
    /// @param publicInputs Length-3 array: `[petition_id, enrollment_root,
    ///                     nullifier]`.
    function revokeVote(
        uint256 petitionId,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        Petition storage pet = _petitions[petitionId];
        if (pet.creator == address(0)) revert UnknownPetition();
        if (block.timestamp > pet.deadline) revert PetitionClosed();
        if (pet.thresholdReached) revert PetitionClosed();

        if (!_signed[petitionId][nullifier]) revert NullifierNotUsed();

        // Same public-input shape check as signPetition.
        if (publicInputs.length != 3) revert InvalidProof();
        if (uint256(publicInputs[0]) != petitionId) revert InvalidProof();
        if (publicInputs[2] != nullifier) revert InvalidProof();
        if (publicInputs[1] != enrollmentRegistry.enrollmentRoot()) {
            revert InvalidEnrollmentRoot();
        }

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        _signed[petitionId][nullifier] = false;
        uint32 newCount = --pet.signatureCount;

        emit PetitionRevoked(petitionId, nullifier, newCount);
    }

    // ---------- views ----------

    /// @notice Whether `nf` currently holds an active signature on `id`.
    function hasNullifier(uint256 id, bytes32 nf) external view returns (bool) {
        return _signed[id][nf];
    }

    function getPetition(uint256 id) external view returns (Petition memory) {
        if (_petitions[id].creator == address(0)) revert UnknownPetition();
        return _petitions[id];
    }

    function signatureCount(uint256 id) external view returns (uint32) {
        return _petitions[id].signatureCount;
    }

    enum PetitionStatus {
        Unknown,
        Open,
        Closed,
        ThresholdReached
    }

    function petitionStatus(uint256 id) external view returns (PetitionStatus) {
        Petition storage p = _petitions[id];
        if (p.creator == address(0)) return PetitionStatus.Unknown;
        if (p.thresholdReached) return PetitionStatus.ThresholdReached;
        if (block.timestamp > p.deadline) return PetitionStatus.Closed;
        return PetitionStatus.Open;
    }
}
