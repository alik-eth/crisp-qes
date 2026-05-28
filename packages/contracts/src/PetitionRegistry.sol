// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVerifier} from "./IVerifier.sol";
import {P256} from "./P256.sol";

/// @title PetitionRegistry
/// @notice Single global registry for privacy-preserving petition signatures.
///         Eligibility (the Diia certificate chain, Merkle membership, and the
///         binding of `signedAttrs` to `(petition_id, petition_text_hash)`) is
///         proven off-chain via the Noir circuit. The actual P-256 ECDSA
///         signature over `signedAttrs` is verified on-chain via the RIP-7212
///         precompile at `0x0000…0100`. The contract also enforces nullifier
///         uniqueness per petition and a refundable spam-control deposit on
///         petition creation.
///         See docs/specs/2026-05-19-crisp-qes-pivot-design.md §1, §2.1, §2.3, §7.
contract PetitionRegistry {
    // ---------- types ----------

    struct Petition {
        address creator;
        uint64 createdAt;
        uint64 deadline;
        uint32 threshold;
        uint32 signatureCount;
        bool thresholdReached;
        bool depositRefunded;
        bytes32 textHash; // keccak256(fullText)
        bytes fullText;   // UTF-8, on-chain (gas-bounded; see §7 Q2)
    }

    // ---------- storage ----------

    IVerifier public immutable verifier;
    bytes32 public immutable trustRoot; // pinned Diia Poseidon Merkle root
    uint256 public immutable CREATION_DEPOSIT;

    uint256 public nextPetitionId = 1;
    mapping(uint256 => Petition) internal _petitions;
    mapping(uint256 => mapping(bytes32 => bool)) public hasNullifier;

    // ---------- events ----------

    event PetitionCreated(
        uint256 indexed id, address indexed creator, uint64 deadline, uint32 threshold
    );
    event PetitionSigned(uint256 indexed id, bytes32 indexed nullifier, uint32 newCount);
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
    error InvalidTrustRoot();
    error InvalidSignature();
    error InvalidCertChain();
    error WrongDeposit();
    error NotCreator();
    error DepositAlreadyRefunded();
    error PetitionStillOpen();
    error RefundTransferFailed();

    uint256 public constant MAX_TEXT_BYTES = 8 * 1024;
    uint256 public constant DEFAULT_CREATION_DEPOSIT = 0.001 ether;

    // ---------- construction ----------

    constructor(IVerifier verifier_, bytes32 trustRoot_, uint256 creationDeposit_) {
        verifier = verifier_;
        trustRoot = trustRoot_;
        CREATION_DEPOSIT = creationDeposit_;
    }

    // ---------- creator API ----------

    /// @notice Create a petition. Caller must attach exactly `CREATION_DEPOSIT`
    ///         wei. The deposit is locked until `deadline` passes and is then
    ///         refundable via `withdrawDeposit`.
    function createPetition(bytes calldata fullText, uint64 deadline, uint32 threshold)
        external
        payable
        returns (uint256 id)
    {
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

    /// @notice Refund the creation deposit to the petition's creator. May only
    ///         be called once and only after the petition's deadline has
    ///         passed. The deposit is refunded irrespective of whether the
    ///         threshold was reached.
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

    /// @notice Parameters for `signPetition`. Grouped into a struct so the
    ///         function signature stays under Solidity's stack-depth limit
    ///         (we'd otherwise have 12 positional uint256/bytes32 args).
    struct SignCalldata {
        uint256 petitionId;
        bytes32 nullifier;
        uint256 leafPubkeyX;
        uint256 leafPubkeyY;
        uint256 leafSigR;
        uint256 leafSigS;
        uint256 intermediatePubkeyX;
        uint256 intermediatePubkeyY;
        uint256 intermediateSigR;
        uint256 intermediateSigS;
    }

    /// @notice Submit a privacy-preserving signature for a petition.
    ///
    ///         Public-signal layout (asserted below) — see spec §2.1 (D-v2):
    ///           [0]  petition_id
    ///           [1]  nullifier
    ///           [2]  trust_root
    ///           [3]  leaf_pubkey_x
    ///           [4]  leaf_pubkey_y
    ///           [5]  intermediate_pubkey_x
    ///           [6]  intermediate_pubkey_y
    ///           [7]  leaf_tbs_sha256_hi      (high 16 bytes, BE)
    ///           [8]  leaf_tbs_sha256_lo      (low  16 bytes, BE)
    ///           [9]  signed_attrs_sha256_hi  (high 16 bytes, BE)
    ///           [10] signed_attrs_sha256_lo  (low  16 bytes, BE)
    ///
    ///         The 4 hi/lo limbs are required because BN254's prime is
    ///         below 2^254, so a single Field cannot losslessly carry a
    ///         full 256-bit SHA-256 output. Each 128-bit limb is bounded
    ///         on-chain too, then concatenated back into the bytes32 each
    ///         precompile call needs.
    ///
    ///         Two RIP-7212 P-256 verifications run here:
    ///           1. intermediate -> leaf TBS  (proves the leaf cert was
    ///              issued by a trust-rooted intermediate; failure reverts
    ///              with `InvalidCertChain`).
    ///           2. leaf -> signedAttrs       (the citizen signature over
    ///              the petition-bound `messageDigest`; failure reverts
    ///              with `InvalidSignature`).
    /// @param p           Grouped calldata, see `SignCalldata`.
    /// @param proof       Barretenberg proof bytes.
    /// @param publicInputs ordered public signals expected by the verifier (length 11).
    function signPetition(
        SignCalldata calldata p,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        Petition storage pet = _petitions[p.petitionId];
        if (pet.creator == address(0)) revert UnknownPetition();
        if (block.timestamp > pet.deadline) revert PetitionClosed();
        if (hasNullifier[p.petitionId][p.nullifier]) revert NullifierAlreadyUsed();

        if (publicInputs.length != 11) revert InvalidProof();
        if (uint256(publicInputs[0]) != p.petitionId) revert InvalidProof();
        if (publicInputs[1] != p.nullifier) revert InvalidProof();
        if (publicInputs[2] != trustRoot) revert InvalidTrustRoot();
        if (uint256(publicInputs[3]) != p.leafPubkeyX) revert InvalidProof();
        if (uint256(publicInputs[4]) != p.leafPubkeyY) revert InvalidProof();
        if (uint256(publicInputs[5]) != p.intermediatePubkeyX) revert InvalidProof();
        if (uint256(publicInputs[6]) != p.intermediatePubkeyY) revert InvalidProof();
        // Each of the 4 limbs must fit in 128 bits so the bytes32
        // reconstructions below are lossless. The circuit guarantees this
        // (be_bytes16_to_field never sees more than 16 input bytes); the
        // belt-and-braces check on-chain blocks a buggy / malicious
        // witness from smuggling high bits past the verifier.
        if (uint256(publicInputs[7]) >> 128 != 0) revert InvalidProof();
        if (uint256(publicInputs[8]) >> 128 != 0) revert InvalidProof();
        if (uint256(publicInputs[9]) >> 128 != 0) revert InvalidProof();
        if (uint256(publicInputs[10]) >> 128 != 0) revert InvalidProof();

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        bytes32 leafTbsHash = bytes32(
            (uint256(publicInputs[7]) << 128) | uint256(publicInputs[8])
        );
        bytes32 signedAttrsHash = bytes32(
            (uint256(publicInputs[9]) << 128) | uint256(publicInputs[10])
        );

        // 1. Intermediate signed the leaf TBSCertificate.
        if (
            !P256.verify(
                leafTbsHash,
                p.intermediateSigR,
                p.intermediateSigS,
                p.intermediatePubkeyX,
                p.intermediatePubkeyY
            )
        ) {
            revert InvalidCertChain();
        }

        // 2. Leaf signed the signedAttrs (which the circuit pinned to this
        //    petition via the messageDigest binding).
        if (
            !P256.verify(
                signedAttrsHash,
                p.leafSigR,
                p.leafSigS,
                p.leafPubkeyX,
                p.leafPubkeyY
            )
        ) {
            revert InvalidSignature();
        }

        hasNullifier[p.petitionId][p.nullifier] = true;
        uint32 newCount = ++pet.signatureCount;
        emit PetitionSigned(p.petitionId, p.nullifier, newCount);

        if (!pet.thresholdReached && newCount >= pet.threshold) {
            pet.thresholdReached = true;
            emit ThresholdReached(p.petitionId, pet.threshold, uint64(block.timestamp));
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
