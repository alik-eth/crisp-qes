import type { ParsedP7s } from "./p7s.js";

export interface WitnessInputs {
    // public
    petition_id: string;
    nullifier: string;
    trust_root: string;
    chain_bindings: string;
    // private
    p7s_bytes: number[];
    leaf_cert: number[];
    intermediate_cert: number[];
    pubkey_x: string;
    pubkey_y: string;
    subject_serial: number[];
    sig_r: string;
    sig_s: string;
    merkle_path: string[];
}

export interface BuildWitnessArgs {
    parsed: ParsedP7s;
    petitionId: bigint;
    petitionTextHash: Uint8Array;
    trustRoot: bigint;
    merklePath: bigint[];
    chainBindings?: bigint;
}

export function buildWitness(_args: BuildWitnessArgs): WitnessInputs {
    throw new Error("buildWitness: not implemented");
}
