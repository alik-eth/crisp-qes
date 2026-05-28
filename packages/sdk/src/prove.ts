// Prove wrapper + nullifier preview.
//
// Wraps `@noir-lang/noir_js` (witness execution) and `@aztec/bb.js`
// (UltraHonk ZK proof generation) into the two flows the rest of the SDK
// needs:
//
//   - `prove(witness, compiledCircuit)` - full eligibility proof, returning
//     the EVM-flavoured ZK Honk proof bytes plus the 15 public inputs as
//     bytes32 hex strings in the exact order `PetitionRegistry.signPetition`
//     consumes them.
//
//   - `computeNullifier({pubkey, petitionId})` - the same Pedersen-on-BN254
//     hash the circuit computes for slot [1]. The web flow surfaces this to
//     the signer ahead of submission so they see the nullifier they're
//     about to publish.
//
// bb.js 4.x notes:
//   - `Fr` is no longer exported from the package root; production code
//     uses raw 32-byte big-endian `Uint8Array`s for field elements.
//   - `pedersenHash` takes a single object: `{ inputs: Uint8Array[], hashIndex }`
//     and returns `{ hash: Uint8Array }`.
//   - `UltraHonkBackend` constructor takes `(acirBytecode, api: Barretenberg)`
//     and `generateProof` consumes the *serialised* witness produced by
//     `Noir.execute` (already a `Uint8Array` in noir_js 1.0.0-beta.19).
//   - `keccakZK: true` is deprecated in favour of `verifierTarget: "evm"`.

import type { CompiledCircuit } from "@noir-lang/noir_js";
import { Noir } from "@noir-lang/noir_js";
import {
    Barretenberg,
    BarretenbergSync,
    UltraHonkBackend,
} from "@aztec/bb.js";

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
    /** Public inputs (length 15) as bytes32-hex strings in registry order. */
    publicInputs: string[];
}

export interface ProveArgs {
    witness: WitnessInputs;
    /** The output of `nargo compile` for `crisp_qes_circuit`. */
    circuit: CompiledCircuit;
}

/**
 * Generate a ZK Honk proof for the eligibility circuit. Uses the EVM
 * verifier target (replaces the bb.js 1.x `keccakZK: true` option), which
 * matches the regenerated Solidity verifier emitted by
 * `bb write_solidity_verifier -t evm`.
 *
 * Returns the raw proof bytes plus the 15 public inputs already cast to
 * bytes32-hex in `PetitionRegistry.signPetition` order. The caller drops
 * those straight into the `publicInputs[]` calldata array.
 */
export async function prove(args: ProveArgs): Promise<Proof> {
    const { witness, circuit } = args;
    const noir = new Noir(circuit);
    // noir_js 1.0.0-beta.19's `execute` returns `witness: Uint8Array` —
    // already the gzip-compressed witness format the backend expects.
    const { witness: compressedWitness } = await noir.execute(
        witness as unknown as Parameters<Noir["execute"]>[0],
    );

    const api = await Barretenberg.new();
    try {
        const backend = new UltraHonkBackend(circuit.bytecode, api);
        const { proof, publicInputs } = await backend.generateProof(
            compressedWitness,
            { verifierTarget: "evm" },
        );
        return { proofBytes: proof, publicInputs };
    } finally {
        await api.destroy();
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
    const inputs: Uint8Array[] = [
        bigintToBE32(xHi),
        bigintToBE32(xLo),
        bigintToBE32(yHi),
        bigintToBE32(yLo),
        bigintToBE32(args.petitionId),
        bigintToBE32(DOMAIN_PETITION_V1),
    ];
    const { hash } = api.pedersenHash({ inputs, hashIndex: 0 });
    return `0x${bytesToHex(hash)}`;
}

// ----------------------------------------------------------------------------
// Helpers (internal): big-endian encoding for BN254 field elements.
// ----------------------------------------------------------------------------

/**
 * Encode a non-negative bigint as a 32-byte big-endian buffer. bb.js 4.x
 * field-element inputs to `pedersenHash` are 32 BE bytes per Field; no
 * Fr wrapper exists at the package root.
 */
function bigintToBE32(v: bigint): Uint8Array {
    if (v < 0n) {
        throw new Error(`bigintToBE32: negative value ${v}`);
    }
    const out = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) {
        out[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    if (x !== 0n) {
        throw new Error(`bigintToBE32: value ${v} exceeds 32 bytes`);
    }
    return out;
}

function bytesToHex(b: Uint8Array): string {
    let s = "";
    for (let i = 0; i < b.length; i++) {
        s += b[i]!.toString(16).padStart(2, "0");
    }
    return s;
}
