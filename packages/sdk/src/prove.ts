import type { WitnessInputs } from "./witness.js";

export interface Proof {
    proofBytes: Uint8Array;
    publicInputs: string[]; // bytes32-hex in registry order
}

/** Generate a proof via Barretenberg WASM. Implementation arrives with the circuit ABI. */
export async function prove(_witness: WitnessInputs, _circuitJson: unknown): Promise<Proof> {
    throw new Error("prove: not implemented");
}
