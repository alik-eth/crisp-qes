// Minimal ABI for PetitionRegistry — view paths the web app uses.

export const petitionRegistryAbi = [
    {
        type: "function",
        name: "nextPetitionId",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
    },
    {
        type: "function",
        name: "trustRoot",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "bytes32" }],
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
                    { name: "textHash", type: "bytes32" },
                    { name: "fullText", type: "bytes" },
                ],
            },
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
        name: "signatureCount",
        stateMutability: "view",
        inputs: [{ name: "id", type: "uint256" }],
        outputs: [{ name: "", type: "uint32" }],
    },
] as const;

export type PetitionStatusCode = 0 | 1 | 2 | 3;
export const PetitionStatusLabel: Record<PetitionStatusCode, "Unknown" | "Open" | "Closed" | "ThresholdReached"> = {
    0: "Unknown",
    1: "Open",
    2: "Closed",
    3: "ThresholdReached",
};
