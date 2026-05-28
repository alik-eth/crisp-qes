// v2 PetitionRegistryV2 + EnrollmentRegistry ABI surface.
//
// Hand-rolled subset of `packages/v2-contracts/src/PetitionRegistryV2.sol`
// and `EnrollmentRegistry.sol`. Mirrors only what the relayer touches:
// `signPetition` + the view reads + decoded events + custom-error decoder.
// Full ABIs live in `packages/v2-contracts/out/*.json` (foundry).

export const petitionRegistryV2Abi = [
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
        name: "signatureCount",
        stateMutability: "view",
        inputs: [{ name: "id", type: "uint256" }],
        outputs: [{ type: "uint32" }],
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
        name: "hasNullifier",
        stateMutability: "view",
        inputs: [
            { name: "", type: "uint256" },
            { name: "", type: "bytes32" },
        ],
        outputs: [{ type: "bool" }],
    },
    {
        type: "event",
        name: "PetitionSigned",
        inputs: [
            { name: "id", type: "uint256", indexed: true },
            { name: "nullifier", type: "bytes32", indexed: true },
            { name: "newCount", type: "uint32", indexed: false },
        ],
    },
    {
        type: "event",
        name: "PetitionVoted",
        inputs: [
            { name: "id", type: "uint256", indexed: true },
            { name: "vote", type: "uint8", indexed: false },
            { name: "nullifier", type: "bytes32", indexed: true },
            { name: "newCount", type: "uint32", indexed: false },
        ],
    },
    {
        type: "event",
        name: "ThresholdReached",
        inputs: [
            { name: "id", type: "uint256", indexed: true },
            { name: "threshold", type: "uint32", indexed: false },
            { name: "reachedAt", type: "uint64", indexed: false },
        ],
    },
    // Custom errors — match by selector in `mapContractError`.
    { type: "error", name: "UnknownPetition", inputs: [] },
    { type: "error", name: "PetitionClosed", inputs: [] },
    { type: "error", name: "NullifierAlreadyUsed", inputs: [] },
    { type: "error", name: "InvalidProof", inputs: [] },
    { type: "error", name: "InvalidEnrollmentRoot", inputs: [] },
    { type: "error", name: "InvalidVote", inputs: [] },
] as const;

export const enrollmentRegistryAbi = [
    {
        type: "function",
        name: "enrollmentRoot",
        stateMutability: "view",
        inputs: [],
        outputs: [{ type: "bytes32" }],
    },
    {
        type: "function",
        name: "leafCount",
        stateMutability: "view",
        inputs: [],
        outputs: [{ type: "uint256" }],
    },
] as const;
