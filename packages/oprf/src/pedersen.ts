// Pedersen-on-BN254 wrapper.
//
// We re-use `@crisp-qes/lotl-flattener`'s primitive so the OPRF service,
// the SDK witness builder, the v2 circuit, and the EnrollmentRegistry
// Merkle commitment all agree on the same byte-for-byte hash. See
// `packages/lotl-flattener/src/ca/pedersen.ts` for the bb.js bindings.
//
// Derivation (re-pinned by team-lead 2026-05-29 — the *secret* and the
// *tree leaf* are now the same value, dropping the extra `pedersen([leaf])`
// wrapper that earlier drafts had):
//
//   N      = 32-byte canonical ristretto255 encoding of the unblinded OPRF
//            output, N = k * H_to_curve(RNOKPP)
//   N_hi   = BigInt(N[0..16])      (BE, high 128 bits as a Field)
//   N_lo   = BigInt(N[16..32])     (BE, low  128 bits as a Field)
//   s      = pedersen_hash([N_hi, N_lo], 0)   // the secret AND the tree leaf
//   nullifier = pedersen_hash([s, petition_id, DOMAIN_PETITION_V2], 0)   // client-side
//
// Domain-separator budget for v2.1:
//   hashIndex 0  — secret derivation, nullifier, Merkle node hash
//   hashIndex 1  — reserved for v2.2's JCJ "fake-credential" branch
//
// On the wire, /oprf/register accepts `commitment` (kept for backward
// compat with what web is already calling it); semantically the value
// IS `s`.
//
// `packages/circuit` (Noir) consumes the identical formula for the witness.

import { pedersenHashFields } from "@crisp-qes/lotl-flattener";

/** Sole hashIndex used by v2.1; hashIndex 1 reserved for JCJ in v2.2. */
export const SECRET_HASH_INDEX = 0;

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

/**
 * Re-derive `s = pedersen_hash([N_hi, N_lo], 0)` from N. This is both the
 * citizen's enrollment_secret and the Merkle leaf the EnrollmentRegistry
 * stores. (Earlier drafts used a separate `commitment` value derived under
 * a distinct hashIndex; team-lead collapsed the two on 2026-05-29.)
 */
export async function secretFromOprfOutput(N: Uint8Array): Promise<bigint> {
    const { hi, lo } = splitOprfOutput(N);
    return pedersenHashFields([hi, lo], SECRET_HASH_INDEX);
}

/**
 * Back-compat alias — earlier callers used the name `commitment`. The
 * value is identical to `s` (the enrollment_secret == the tree leaf).
 */
export const commitmentFromOprfOutput = secretFromOprfOutput;

export { pedersenHashFields };
