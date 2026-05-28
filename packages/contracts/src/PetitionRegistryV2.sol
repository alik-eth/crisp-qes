// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifierV2} from "./IVerifierV2.sol";
import {EnrollmentRegistry} from "./EnrollmentRegistry.sol";

/// @title PetitionRegistryV2
/// @notice v2 petition registry. The off-chain Diia QES + CAdES walk is
///         gone; eligibility is now reduced to membership in the
///         `EnrollmentRegistry`'s Merkle tree, gated by a single 3-public-
///         input UltraHonk proof.
///
///         See `docs/specs/2026-05-29-crisp-qes-v2-refined.md` sec 3 and
///         the partner v2 circuit at `packages/v2-circuit/src/main.nr`.
///
///         Public-input layout (FIXED, asserted in `signPetition`):
///           [0]  petition_id
///           [1]  enrollment_root
///           [2]  nullifier
///
///         Ballot mode is set at creation time. The chosen mode constrains
///         which `vote` values are accepted at signing time:
///           Signature      => vote must be 0 (the "signed it" bit)
///           YesNo          => vote ∈ {0=No, 1=Yes}
///           YesNoAbstain   => vote ∈ {0=No, 1=Yes, 2=Abstain}
///
///         v2.2: replace transparent vote counters with FHE-aggregated
///         ciphertexts (spec sec 4). For v2.1 the counts are public so
///         the demo can show live tallies in the web UI without a
///         dedicated decryption step.
contract PetitionRegistryV2 {
    // ---------- types ----------

    enum BallotMode {
        Signature,
        YesNo,
        YesNoAbstain
    }

    struct Petition {
        address creator;
        uint64 createdAt;
        uint64 deadline;
        uint32 threshold;
        uint32 signatureCount; // total signed/voted, mode-agnostic
        bool thresholdReached;
        bool depositRefunded;
        BallotMode mode;
        // v2.2: replace these three transparent counters with FHE
        // ciphertexts aggregated under a threshold-FHE key. For the demo
        // they're public; the privacy guarantee still holds because each
        // counter is bumped by an anonymous nullifier-bound proof.
        uint32 yesCount;
        uint32 noCount;
        uint32 abstainCount;
        bytes32 textHash; // keccak256(fullText)
        bytes fullText;   // UTF-8, on-chain (gas-bounded; see MVP spec sec 7 Q2)
    }

    // ---------- storage ----------

    IVerifierV2 public immutable verifier;
    EnrollmentRegistry public immutable enrollmentRegistry;
    uint256 public immutable CREATION_DEPOSIT;

    uint256 public nextPetitionId = 1;
    mapping(uint256 => Petition) internal _petitions;
    mapping(uint256 => mapping(bytes32 => bool)) public hasNullifier;

    // ---------- events ----------

    event PetitionCreated(
        uint256 indexed id,
        address indexed creator,
        uint64 deadline,
        uint32 threshold,
        BallotMode mode
    );
    event PetitionSigned(uint256 indexed id, bytes32 indexed nullifier, uint32 newCount);
    event PetitionVoted(
        uint256 indexed id,
        uint8 vote,
        bytes32 indexed nullifier,
        uint32 newCount
    );
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
    error InvalidProof();
    error InvalidEnrollmentRoot();
    error InvalidVote();
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
    ///         `withdrawDeposit`. `mode` chooses the ballot shape and
    ///         constrains valid `vote` values at signing time.
    function createPetition(
        bytes calldata fullText,
        uint64 deadline,
        uint32 threshold,
        BallotMode mode
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
        p.mode = mode;
        p.textHash = keccak256(fullText);
        p.fullText = fullText;

        emit PetitionCreated(id, msg.sender, deadline, threshold, mode);
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

    /// @notice Submit a privacy-preserving signature/vote for a petition.
    ///
    ///         The proof binds `(petitionId, enrollmentRoot, nullifier)`.
    ///         The contract additionally enforces:
    ///           - the proof's `enrollmentRoot` slot matches the *current*
    ///             on-chain root (so an enrolled citizen can only sign
    ///             under a root the OPRF service has anchored);
    ///           - the nullifier hasn't been used for this petition;
    ///           - the supplied `vote` value fits the petition's ballot
    ///             mode.
    ///
    /// @param petitionId   Target petition id.
    /// @param vote         Ballot value, mode-dependent (see `BallotMode`).
    /// @param nullifier    Per-(citizen, petition) nullifier, also pinned
    ///                     in `publicInputs[2]`.
    /// @param proof        UltraHonk proof bytes from the v2 circuit.
    /// @param publicInputs Length-3 array: `[petition_id, enrollment_root,
    ///                     nullifier]`. Must match the v2 circuit's public
    ///                     input order.
    function signPetition(
        uint256 petitionId,
        uint8 vote,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        Petition storage pet = _petitions[petitionId];
        if (pet.creator == address(0)) revert UnknownPetition();
        if (block.timestamp > pet.deadline) revert PetitionClosed();
        if (hasNullifier[petitionId][nullifier]) revert NullifierAlreadyUsed();

        // Public-input shape check.
        if (publicInputs.length != 3) revert InvalidProof();
        if (uint256(publicInputs[0]) != petitionId) revert InvalidProof();
        if (publicInputs[2] != nullifier) revert InvalidProof();
        if (publicInputs[1] != enrollmentRegistry.enrollmentRoot()) {
            revert InvalidEnrollmentRoot();
        }

        // Mode-bound vote validation. Done before the verifier call so a
        // bogus vote on a valid proof still reverts cheaply.
        _assertVoteValid(pet.mode, vote);

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        hasNullifier[petitionId][nullifier] = true;
        uint32 newCount = ++pet.signatureCount;

        // Bump the mode-specific counter.
        if (pet.mode == BallotMode.Signature) {
            // Signature mode: only the aggregate count matters; nothing
            // per-vote-bin to bump.
            emit PetitionSigned(petitionId, nullifier, newCount);
        } else if (pet.mode == BallotMode.YesNo) {
            if (vote == 0) pet.noCount += 1;
            else pet.yesCount += 1;
            emit PetitionVoted(petitionId, vote, nullifier, newCount);
        } else {
            // YesNoAbstain
            if (vote == 0) pet.noCount += 1;
            else if (vote == 1) pet.yesCount += 1;
            else pet.abstainCount += 1;
            emit PetitionVoted(petitionId, vote, nullifier, newCount);
        }

        if (!pet.thresholdReached && newCount >= pet.threshold) {
            pet.thresholdReached = true;
            emit ThresholdReached(petitionId, pet.threshold, uint64(block.timestamp));
        }
    }

    // ---------- views ----------

    function getPetition(uint256 id) external view returns (Petition memory) {
        if (_petitions[id].creator == address(0)) revert UnknownPetition();
        return _petitions[id];
    }

    function signatureCount(uint256 id) external view returns (uint32) {
        return _petitions[id].signatureCount;
    }

    function voteCounts(uint256 id)
        external
        view
        returns (uint32 yesCount, uint32 noCount, uint32 abstainCount)
    {
        Petition storage p = _petitions[id];
        return (p.yesCount, p.noCount, p.abstainCount);
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

    // ---------- internals ----------

    function _assertVoteValid(BallotMode mode, uint8 vote) private pure {
        if (mode == BallotMode.Signature) {
            // Signature mode accepts only vote=0 (the canonical "signed"
            // bit). Anything else is a caller bug.
            if (vote != 0) revert InvalidVote();
        } else if (mode == BallotMode.YesNo) {
            if (vote > 1) revert InvalidVote();
        } else {
            if (vote > 2) revert InvalidVote();
        }
    }
}
