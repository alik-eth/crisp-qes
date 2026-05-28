// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifier} from "./IVerifier.sol";

/// @title PetitionRegistry
/// @notice Single global registry for privacy-preserving petition signatures.
///         Eligibility is proven off-chain via a Noir circuit; this contract
///         enforces nullifier uniqueness per petition and counts signatures.
///         See docs/specs/2026-05-19-crisp-qes-pivot-design.md §1, §2.
contract PetitionRegistry {
    // ---------- types ----------

    struct Petition {
        address creator;
        uint64 createdAt;
        uint64 deadline;
        uint32 threshold;
        uint32 signatureCount;
        bool thresholdReached;
        bytes32 textHash; // keccak256(fullText)
        bytes fullText;   // UTF-8, on-chain (gas-bounded; see §7 Q2)
    }

    // ---------- storage ----------

    IVerifier public immutable verifier;
    bytes32 public immutable trustRoot; // pinned Diia Poseidon Merkle root

    uint256 public nextPetitionId = 1;
    mapping(uint256 => Petition) internal _petitions;
    mapping(uint256 => mapping(bytes32 => bool)) public hasNullifier;

    // ---------- events ----------

    event PetitionCreated(
        uint256 indexed id, address indexed creator, uint64 deadline, uint32 threshold
    );
    event PetitionSigned(uint256 indexed id, bytes32 indexed nullifier, uint32 newCount);
    event ThresholdReached(uint256 indexed id, uint32 threshold, uint64 reachedAt);

    // ---------- errors ----------

    error EmptyText();
    error TextTooLarge();
    error DeadlineInPast();
    error UnknownPetition();
    error PetitionClosed();
    error NullifierAlreadyUsed();
    error InvalidProof();
    error InvalidTrustRoot();

    uint256 public constant MAX_TEXT_BYTES = 8 * 1024;

    // ---------- construction ----------

    constructor(IVerifier verifier_, bytes32 trustRoot_) {
        verifier = verifier_;
        trustRoot = trustRoot_;
    }

    // ---------- creator API ----------

    function createPetition(bytes calldata fullText, uint64 deadline, uint32 threshold)
        external
        returns (uint256 id)
    {
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
    }

    // ---------- signer API ----------

    /// @notice Submit a privacy-preserving signature for `petitionId`.
    /// @param petitionId target petition.
    /// @param nullifier  Poseidon(pubkey.x, pubkey.y, petitionId, DOMAIN).
    /// @param proof      Barretenberg proof bytes.
    /// @param publicInputs ordered public signals expected by the verifier.
    function signPetition(
        uint256 petitionId,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        Petition storage p = _petitions[petitionId];
        if (p.creator == address(0)) revert UnknownPetition();
        if (block.timestamp > p.deadline) revert PetitionClosed();
        if (hasNullifier[petitionId][nullifier]) revert NullifierAlreadyUsed();

        // Public-signal layout, mirroring spec §2.1:
        //   [0] petition_id
        //   [1] nullifier
        //   [2] trust_root
        //   [3] chain_bindings (may be 0 for relayer flow)
        if (publicInputs.length != 4) revert InvalidProof();
        if (uint256(publicInputs[0]) != petitionId) revert InvalidProof();
        if (publicInputs[1] != nullifier) revert InvalidProof();
        if (publicInputs[2] != trustRoot) revert InvalidTrustRoot();
        // publicInputs[3] (chain_bindings) is informational; relayer flow uses 0.

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        hasNullifier[petitionId][nullifier] = true;
        uint32 newCount = ++p.signatureCount;
        emit PetitionSigned(petitionId, nullifier, newCount);

        if (!p.thresholdReached && newCount >= p.threshold) {
            p.thresholdReached = true;
            emit ThresholdReached(petitionId, p.threshold, uint64(block.timestamp));
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
