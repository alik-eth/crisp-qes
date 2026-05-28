// Hand-rolled minimal ABI for PetitionRegistry.
// Pinned against packages/contracts/src/PetitionRegistry.sol.
// Only includes what the relayer needs: signPetition, the errors it can
// surface, and the PetitionSigned event (so we can decode receipts).

export const petitionRegistryAbi = [
    {
        type: "function",
        name: "signPetition",
        stateMutability: "nonpayable",
        inputs: [
            { name: "petitionId", type: "uint256" },
            { name: "nullifier", type: "bytes32" },
            { name: "pubkeyX", type: "uint256" },
            { name: "pubkeyY", type: "uint256" },
            { name: "sigR", type: "uint256" },
            { name: "sigS", type: "uint256" },
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
        outputs: [{ name: "", type: "uint32" }],
    },
    {
        type: "event",
        name: "PetitionSigned",
        anonymous: false,
        inputs: [
            { name: "id", type: "uint256", indexed: true },
            { name: "nullifier", type: "bytes32", indexed: true },
            { name: "newCount", type: "uint32", indexed: false },
        ],
    },
    {
        type: "event",
        name: "ThresholdReached",
        anonymous: false,
        inputs: [
            { name: "id", type: "uint256", indexed: true },
            { name: "threshold", type: "uint32", indexed: false },
            { name: "reachedAt", type: "uint64", indexed: false },
        ],
    },
    // --- errors the signer path can revert with ---
    { type: "error", name: "UnknownPetition", inputs: [] },
    { type: "error", name: "PetitionClosed", inputs: [] },
    { type: "error", name: "NullifierAlreadyUsed", inputs: [] },
    { type: "error", name: "InvalidProof", inputs: [] },
    { type: "error", name: "InvalidTrustRoot", inputs: [] },
    { type: "error", name: "InvalidSignature", inputs: [] },
] as const;

// Pre-computed 4-byte selectors of every custom error above, so we can map
// raw revert data even when viem fails to decode (e.g. simulate errors that
// only ship raw bytes).
//
// keccak256("UnknownPetition()")[0..4]      = 0x0bbb0fd7
// keccak256("PetitionClosed()")[0..4]       = 0x09b25b3a
// keccak256("NullifierAlreadyUsed()")[0..4] = 0xed10b14a
// keccak256("InvalidProof()")[0..4]         = 0x09bde339
// keccak256("InvalidTrustRoot()")[0..4]     = 0x2f6940f4
// keccak256("InvalidSignature()")[0..4]     = 0x8baa579f
//
// These constants are derived at runtime via viem's `toFunctionSelector`
// helper so we never rely on hand-typed hex — see errors.ts.
