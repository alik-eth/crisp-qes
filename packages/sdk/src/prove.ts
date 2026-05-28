import type { WitnessInputs } from "./witness.js";

export interface Proof {
    proofBytes: Uint8Array;
    publicInputs: string[]; // bytes32-hex in registry order
}

/** Generate a proof via Barretenberg WASM. Implementation arrives with the circuit ABI. */
export async function prove(_witness: WitnessInputs, _circuitJson: unknown): Promise<Proof> {
    throw new Error("prove: not implemented");
}

/**
 * Compute the nullifier off-chain, matching the circuit's binding exactly:
 *   nullifier = Pedersen([pubkey.x, pubkey.y, petition_id, DOMAIN_PETITION_V1])
 * Used to preview the nullifier to the signer before they submit, and to
 * cross-check against the public input slot the circuit will emit.
 * Must use the same Pedersen-on-BN254 implementation `@aztec/bb.js` exposes.
 */
export async function computeNullifier(_args: {
    pubkey: { x: bigint; y: bigint };
    petitionId: bigint;
}): Promise<string> {
    throw new Error("computeNullifier: not implemented");
}
