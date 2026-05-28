// Prove wrapper + nullifier preview.
//
// Wraps `@noir-lang/noir_js` (witness execution) and `@aztec/bb.js`
// (UltraHonk ZK proof generation) into the two flows the rest of the SDK
// needs:
//
//   - `prove(witness, compiledCircuit)` — full eligibility proof, returning
//     the EVM-flavoured ZK Honk proof bytes plus the 7 public inputs as
//     bytes32 hex strings in the exact order `PetitionRegistry.signPetition`
//     consumes them.
//
//   - `computeNullifier({pubkey, petitionId})` — the same Pedersen-on-BN254
//     hash the circuit computes for slot [1]. The web flow surfaces this to
//     the signer ahead of submission so they see the nullifier they're
//     about to publish.

import type { CompiledCircuit } from "@noir-lang/noir_js";
import { Noir } from "@noir-lang/noir_js";
import { BarretenbergSync, Fr, UltraHonkBackend } from "@aztec/bb.js";

import type { FieldHex, WitnessInputs } from "./witness.js";
import { splitPubkey } from "./witness.js";

/**
 * 128-bit random tag pinning the nullifier domain for v1 of the protocol.
 * MUST match `DOMAIN_PETITION_V1` in `packages/circuit/src/main.nr`.
 */
export const DOMAIN_PETITION_V1: bigint =
    0x0c0915920b3d3ee18f1e4a2b00000000n;

export interface Proof {
    /** Raw ZK Honk proof bytes for the EVM verifier. */
    proofBytes: Uint8Array;
    /** Public inputs (length 11) as bytes32-hex strings in registry order. */
    publicInputs: string[];
}

export interface ProveArgs {
    witness: WitnessInputs;
    /** The output of `nargo compile` for `crisp_qes_circuit`. */
    circuit: CompiledCircuit;
}

/**
 * Generate a ZK Honk proof for the eligibility circuit. Uses the same
 * `keccakZK` Honk variant the regenerated Solidity verifier expects
 * (`bb write_solidity_verifier -t evm`).
 *
 * Returns the raw proof bytes plus the 11 public inputs already cast to
 * bytes32-hex in `PetitionRegistry.signPetition` order. The caller drops
 * those straight into the `publicInputs[]` calldata array.
 */
export async function prove(args: ProveArgs): Promise<Proof> {
    const { witness, circuit } = args;
    const noir = new Noir(circuit);
    const { witness: solvedWitness } = await noir.execute(
        witness as unknown as Parameters<Noir["execute"]>[0],
    );

    const backend = new UltraHonkBackend(circuit.bytecode);
    try {
        const { proof, publicInputs } = await backend.generateProof(
            solvedWitness,
            { keccakZK: true },
        );
        return { proofBytes: proof, publicInputs };
    } finally {
        await backend.destroy();
    }
}

export interface ComputeNullifierArgs {
    pubkey: { x: bigint; y: bigint };
    petitionId: bigint;
}

/**
 * Off-chain nullifier preview.
 *
 *   nullifier = std::hash::pedersen_hash([
 *       pubkey.x_hi, pubkey.x_lo, pubkey.y_hi, pubkey.y_lo,
 *       petition_id, DOMAIN_PETITION_V1,
 *   ])
 *
 * Each pubkey coordinate is split into two 128-bit limbs to mirror the
 * D-v2-fix public-input layout (the BN254 prime is below 2^254, so a
 * single Field cannot losslessly carry a 256-bit P-256 coordinate). The
 * circuit publishes this same value as public input slot [1]. Uses the
 * synchronous bb.js Pedersen API (hashIndex = 0, matching the circuit's
 * plain `pedersen_hash`, no separator).
 *
 * Returns `0x`-prefixed 64-char hex (BN254 field element, big-endian).
 */
export async function computeNullifier(
    args: ComputeNullifierArgs,
): Promise<FieldHex> {
    const api = await BarretenbergSync.initSingleton();
    const { xHi, xLo, yHi, yLo } = splitPubkey(args.pubkey);
    const inputs = [
        new Fr(xHi),
        new Fr(xLo),
        new Fr(yHi),
        new Fr(yLo),
        new Fr(args.petitionId),
        new Fr(DOMAIN_PETITION_V1),
    ];
    const out = api.pedersenHash(inputs, 0);
    const hex = out.toString();
    if (!hex.startsWith("0x")) {
        throw new Error(`computeNullifier: unexpected Fr.toString output: ${hex}`);
    }
    // bb.js Fr.toString omits leading zeros — pad to 32-byte width so the
    // value drops straight into a bytes32 calldata slot.
    return `0x${hex.slice(2).padStart(64, "0")}`;
}
