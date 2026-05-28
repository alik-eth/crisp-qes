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

    /// @notice Submit a privacy-preserving signature for `petitionId`.
    ///
    ///         Public-signal layout (asserted below) — see spec §2.1:
    ///           [0] petition_id
    ///           [1] nullifier
    ///           [2] trust_root
    ///           [3] pubkey_x
    ///           [4] pubkey_y
    ///           [5] signedAttrsSha256_hi (high 16 bytes, BE)
    ///           [6] signedAttrsSha256_lo (low  16 bytes, BE)
    ///
    ///         The hi/lo split is required because BN254's prime is below
    ///         2^254, so a single Field cannot losslessly carry the full
    ///         256-bit SHA-256 output. Each 128-bit limb is safely inside
    ///         the field, and we reconstruct the raw `bytes32 msgHash`
    ///         here before feeding the RIP-7212 P-256 precompile.
    ///
    ///         The Noir proof attests that `(pubkey_x, pubkey_y,
    ///         signedAttrsSha256)` is bound to a Diia cert under the pinned
    ///         trust root and to the petition. The RIP-7212 precompile then
    ///         attests that those exact values constitute a valid P-256 ECDSA
    ///         signature.
    /// @param petitionId target petition.
    /// @param nullifier  Poseidon(pubkey.x, pubkey.y, petitionId, DOMAIN).
    /// @param pubkeyX    P-256 public key affine X — must equal publicInputs[3].
    /// @param pubkeyY    P-256 public key affine Y — must equal publicInputs[4].
    /// @param sigR       P-256 signature scalar r.
    /// @param sigS       P-256 signature scalar s.
    /// @param proof      Barretenberg proof bytes.
    /// @param publicInputs ordered public signals expected by the verifier.
    function signPetition(
        uint256 petitionId,
        bytes32 nullifier,
        uint256 pubkeyX,
        uint256 pubkeyY,
        uint256 sigR,
        uint256 sigS,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        Petition storage p = _petitions[petitionId];
        if (p.creator == address(0)) revert UnknownPetition();
        if (block.timestamp > p.deadline) revert PetitionClosed();
        if (hasNullifier[petitionId][nullifier]) revert NullifierAlreadyUsed();

        if (publicInputs.length != 7) revert InvalidProof();
        if (uint256(publicInputs[0]) != petitionId) revert InvalidProof();
        if (publicInputs[1] != nullifier) revert InvalidProof();
        if (publicInputs[2] != trustRoot) revert InvalidTrustRoot();
        if (uint256(publicInputs[3]) != pubkeyX) revert InvalidProof();
        if (uint256(publicInputs[4]) != pubkeyY) revert InvalidProof();
        // Each limb must fit in 128 bits so the reconstruction below is
        // lossless. The circuit guarantees this (be_bytes16_to_field never
        // sees more than 16 input bytes), but we double-check on-chain so
        // a buggy or malicious witness cannot smuggle high bits past the
        // verifier.
        if (uint256(publicInputs[5]) >> 128 != 0) revert InvalidProof();
        if (uint256(publicInputs[6]) >> 128 != 0) revert InvalidProof();

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        bytes32 msgHash = bytes32(
            (uint256(publicInputs[5]) << 128) | uint256(publicInputs[6])
        );
        if (!P256.verify(msgHash, sigR, sigS, pubkeyX, pubkeyY)) {
            revert InvalidSignature();
        }

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
