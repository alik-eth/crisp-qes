// ABIs for the v2 contracts (`packages/v2-contracts/out/...`).
//
// Shapes are kept in sync with the deployed bytecode by hand-copying the
// strictly-typed minimal surface the web app uses. Full ABIs live in the
// contracts package; this file is intentionally small.

export const enrollmentRegistryAbi = [
    {
        type: "function",
        name: "enrollmentRoot",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "bytes32" }],
    },
    {
        type: "function",
        name: "oprfAttester",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "address" }],
    },
    {
        type: "function",
        name: "leafCount",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        type: "function",
        name: "isCommitmentUsed",
        stateMutability: "view",
        inputs: [{ name: "commitment", type: "bytes32" }],
        outputs: [{ name: "", type: "bool" }],
    },
    {
        type: "function",
        name: "previewDigest",
        stateMutability: "view",
        inputs: [
            { name: "newRoot", type: "bytes32" },
            { name: "newCommitments", type: "bytes32[]" },
        ],
        outputs: [
            { name: "inner", type: "bytes32" },
            { name: "ethSigned", type: "bytes32" },
        ],
    },
    {
        type: "function",
        name: "updateRoot",
        stateMutability: "nonpayable",
        inputs: [
            { name: "newRoot", type: "bytes32" },
            { name: "newCommitments", type: "bytes32[]" },
            { name: "signature", type: "bytes" },
        ],
        outputs: [],
    },
    { type: "error", name: "BadSignature", inputs: [] },
    { type: "error", name: "EmptyBatch", inputs: [] },
    { type: "error", name: "NotAdmin", inputs: [] },
    { type: "error", name: "ZeroAddress", inputs: [] },
] as const;

/** Mirrors `enum BallotMode { Signature, YesNo, YesNoAbstain }` in PetitionRegistryV2. */
export type BallotMode = 0 | 1 | 2;
export const BallotModeLabel: Record<BallotMode, "Signature" | "YesNo" | "YesNoAbstain"> = {
    0: "Signature",
    1: "YesNo",
    2: "YesNoAbstain",
};

/**
 * Vote encoding per the deployed contract (#31):
 *   Signature mode:    only `0` (= sign / yes) is allowed.
 *   YesNo mode:        0 = No, 1 = Yes.
 *   YesNoAbstain mode: 0 = No, 1 = Yes, 2 = Abstain.
 */
export const VotesForMode: Record<BallotMode, number[]> = {
    0: [0],
    1: [0, 1],
    2: [0, 1, 2],
};

export const petitionRegistryV2Abi = [
    {
        type: "function",
        name: "nextPetitionId",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        type: "function",
        name: "getPetition",
        stateMutability: "view",
        inputs: [{ name: "id", type: "uint256" }],
        outputs: [
            {
                name: "",
                type: "tuple",
                components: [
                    { name: "creator", type: "address" },
                    { name: "createdAt", type: "uint64" },
                    { name: "deadline", type: "uint64" },
                    { name: "threshold", type: "uint32" },
                    { name: "signatureCount", type: "uint32" },
                    { name: "thresholdReached", type: "bool" },
                    { name: "depositRefunded", type: "bool" },
                    { name: "mode", type: "uint8" },
                    { name: "yesCount", type: "uint32" },
                    { name: "noCount", type: "uint32" },
                    { name: "abstainCount", type: "uint32" },
                    { name: "textHash", type: "bytes32" },
                    { name: "fullText", type: "bytes" },
                ],
            },
        ],
    },
    {
        type: "function",
        name: "voteCounts",
        stateMutability: "view",
        inputs: [{ name: "id", type: "uint256" }],
        outputs: [
            { name: "yesCount", type: "uint32" },
            { name: "noCount", type: "uint32" },
            { name: "abstainCount", type: "uint32" },
        ],
    },
    {
        type: "function",
        name: "petitionStatus",
        stateMutability: "view",
        inputs: [{ name: "id", type: "uint256" }],
        outputs: [{ name: "", type: "uint8" }],
    },
    {
        type: "function",
        name: "createPetition",
        stateMutability: "payable",
        inputs: [
            { name: "fullText", type: "bytes" },
            { name: "deadline", type: "uint64" },
            { name: "threshold", type: "uint32" },
            { name: "mode", type: "uint8" },
        ],
        outputs: [{ name: "id", type: "uint256" }],
    },
    {
        type: "function",
        name: "signPetition",
        stateMutability: "nonpayable",
        inputs: [
            { name: "petitionId", type: "uint256" },
            { name: "vote", type: "uint8" },
            { name: "nullifier", type: "bytes32" },
            { name: "proof", type: "bytes" },
            { name: "publicInputs", type: "bytes32[]" },
        ],
        outputs: [],
    },
    {
        type: "function",
        name: "withdrawDeposit",
        stateMutability: "nonpayable",
        inputs: [{ name: "id", type: "uint256" }],
        outputs: [],
    },
    // Surfaced to decode reverts in the UI.
    { type: "error", name: "WrongDeposit", inputs: [] },
    { type: "error", name: "EmptyText", inputs: [] },
    { type: "error", name: "TextTooLarge", inputs: [] },
    { type: "error", name: "DeadlineInPast", inputs: [] },
    { type: "error", name: "NotCreator", inputs: [] },
    { type: "error", name: "PetitionStillOpen", inputs: [] },
    { type: "error", name: "DepositAlreadyRefunded", inputs: [] },
    { type: "error", name: "RefundTransferFailed", inputs: [] },
    { type: "error", name: "UnknownPetition", inputs: [] },
    { type: "error", name: "PetitionClosed", inputs: [] },
    { type: "error", name: "InvalidProof", inputs: [] },
    { type: "error", name: "InvalidEnrollmentRoot", inputs: [] },
    { type: "error", name: "NullifierAlreadyUsed", inputs: [] },
    { type: "error", name: "InvalidVote", inputs: [] },
] as const;

export type PetitionStatusCode = 0 | 1 | 2 | 3;
export const PetitionStatusLabel: Record<
    PetitionStatusCode,
    "Unknown" | "Open" | "Closed" | "ThresholdReached"
> = {
    0: "Unknown",
    1: "Open",
    2: "Closed",
    3: "ThresholdReached",
};
