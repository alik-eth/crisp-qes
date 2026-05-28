// Pedersen-on-BN254 wrapper.
//
// We re-use `@crisp-qes/lotl-flattener`'s primitive so the OPRF service,
// the SDK witness builder, the v2 circuit, and the EnrollmentRegistry
// Merkle commitment all agree on the same byte-for-byte hash. See
// `packages/lotl-flattener/src/ca/pedersen.ts` for the bb.js bindings.
//
// Commitment derivation (pinned by team-lead in the design discussion):
//
//   N      = 32-byte canonical ristretto255 encoding of the unblinded OPRF
//            output  N = k * H_to_curve(RNOKPP)
//   N_hi   = BigInt(N[0..16])      (BE, high 128 bits as a Field)
//   N_lo   = BigInt(N[16..32])     (BE, low  128 bits as a Field)
//   commitment        = pedersen_hash([N_hi, N_lo], hashIndex = 0)
//   enrollment_secret = pedersen_hash([N_hi, N_lo], hashIndex = 1)
//   merkle_leaf       = pedersen_hash([enrollment_secret], hashIndex = 0)
//
// `packages/v2-circuit` consumes the same formula for the witness.

import { pedersenHashFields } from "@crisp-qes/lotl-flattener";

export const COMMITMENT_HASH_INDEX = 0;
export const SECRET_HASH_INDEX = 1;
export const LEAF_HASH_INDEX = 0;

/** Split the 32-byte ristretto255 output into BN254-safe (hi, lo) limbs. */
export function splitOprfOutput(N: Uint8Array): { hi: bigint; lo: bigint } {
    if (N.length !== 32) {
        throw new Error(
            `splitOprfOutput: expected 32-byte OPRF output, got ${N.length}`,
        );
    }
    let hi = 0n;
    for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(N[i]!);
    let lo = 0n;
    for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(N[i]!);
    return { hi, lo };
}

/** Re-derive `commitment = pedersen_hash([N_hi, N_lo], 0)` from N. */
export async function commitmentFromOprfOutput(N: Uint8Array): Promise<bigint> {
    const { hi, lo } = splitOprfOutput(N);
    return pedersenHashFields([hi, lo], COMMITMENT_HASH_INDEX);
}

/**
 * Re-derive the Merkle leaf for the v2 circuit:
 *
 *   s    = pedersen([N_hi, N_lo], 1)
 *   leaf = pedersen([s], 0)
 *
 * Exposed so the test harness can verify path correctness end-to-end.
 */
export async function leafFromOprfOutput(N: Uint8Array): Promise<bigint> {
    const { hi, lo } = splitOprfOutput(N);
    const s = await pedersenHashFields([hi, lo], SECRET_HASH_INDEX);
    return pedersenHashFields([s], LEAF_HASH_INDEX);
}

export { pedersenHashFields };
