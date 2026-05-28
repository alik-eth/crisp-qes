// Pedersen commit helpers that match the v2 circuit (#30).
//
// The 32-byte ristretto-encoded OPRF output `N` is split into two
// 16-byte little-endian limbs (`N_lo`, `N_hi`) and folded through
// `bb.js` Pedersen with different hashIndex domain separators:
//
//   commitment        = pedersen_hash([N_hi, N_lo], 0)
//   enrollment_secret = pedersen_hash([N_hi, N_lo], 1)
//
// The circuit then folds the secret into the Merkle leaf:
//   enrollment_leaf  = pedersen_hash([enrollment_secret], 0)
//
// and uses the secret + petition id + DOMAIN_PETITION_V2 for the
// nullifier. We expose helpers for all four so the Enroll and Sign
// flows can pin these constructions in one place.
//
// `Fr` is no longer exported from @aztec/bb.js@4.x; the bb.js API is
// `{ inputs: Uint8Array[], hashIndex } → { hash: Uint8Array }` with
// inputs/outputs as 32-byte big-endian BN254 field elements. This file
// hands the raw buffers to bb.js and converts at the edges.

import { BarretenbergSync } from "@aztec/bb.js";

const DOMAIN_PETITION_V2 =
    0x76322d70656e2d6e6f31n; // ASCII "v2-pen-no1" packed into a Field

let _bb: Promise<BarretenbergSync> | null = null;
async function bb(): Promise<BarretenbergSync> {
    if (!_bb) _bb = BarretenbergSync.initSingleton();
    return _bb;
}

const FR_MAX = 1n << 254n;

function bigintToBE32(v: bigint): Uint8Array {
    if (v < 0n) throw new Error("pedersen: negative field elements unsupported");
    if (v >= FR_MAX) throw new Error("pedersen: input exceeds Fr range");
    const out = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) {
        out[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return out;
}

function be32ToBigInt(b: Uint8Array): bigint {
    let acc = 0n;
    for (let i = 0; i < b.length; i++) acc = (acc << 8n) | BigInt(b[i]!);
    return acc;
}

function bigintToHex32(v: bigint): `0x${string}` {
    return `0x${v.toString(16).padStart(64, "0")}` as `0x${string}`;
}

function hexToBigInt(h: `0x${string}`): bigint {
    return BigInt(h);
}

async function pedersenFields(
    inputs: readonly bigint[],
    hashIndex: number,
): Promise<bigint> {
    const api = await bb();
    const buffers = inputs.map(bigintToBE32);
    const { hash } = api.pedersenHash({ inputs: buffers, hashIndex });
    return be32ToBigInt(hash);
}

/** Split a 32-byte little-endian buffer into two 16-byte limbs (lo, hi). */
export function splitLE32(buf: Uint8Array): { lo: bigint; hi: bigint } {
    if (buf.length !== 32) throw new Error("splitLE32: expected 32 bytes");
    let lo = 0n;
    let hi = 0n;
    for (let i = 15; i >= 0; i--) lo = (lo << 8n) | BigInt(buf[i]!);
    for (let i = 31; i >= 16; i--) hi = (hi << 8n) | BigInt(buf[i]!);
    return { lo, hi };
}

/**
 * Commit the OPRF output for on-chain storage.
 * Matches the v2 spec: `commitment = pedersen_hash([N_hi, N_lo], 0)`.
 */
export async function pedersenCommit(N: Uint8Array): Promise<`0x${string}`> {
    const { lo, hi } = splitLE32(N);
    return bigintToHex32(await pedersenFields([hi, lo], 0));
}

/**
 * Derive the enrollment secret `s = pedersen_hash([N_hi, N_lo], 1)`.
 * This is the scalar the circuit hashes into the Merkle leaf and folds
 * into the nullifier.
 */
export async function pedersenSecret(N: Uint8Array): Promise<`0x${string}`> {
    const { lo, hi } = splitLE32(N);
    return bigintToHex32(await pedersenFields([hi, lo], 1));
}

/**
 * Compute `enrollment_leaf = pedersen_hash([s], 0)` — same construction the
 * circuit uses to verify the Merkle path.
 */
export async function pedersenLeaf(
    secretHex: `0x${string}`,
): Promise<`0x${string}`> {
    return bigintToHex32(await pedersenFields([hexToBigInt(secretHex)], 0));
}

/**
 * Compute the nullifier for a `(secret, petition_id)` pair.
 *   nullifier = pedersen_hash([s, petition_id, DOMAIN_PETITION_V2], 0)
 */
export async function pedersenNullifier(
    secretHex: `0x${string}`,
    petitionId: bigint,
): Promise<`0x${string}`> {
    return bigintToHex32(
        await pedersenFields(
            [hexToBigInt(secretHex), petitionId, DOMAIN_PETITION_V2],
            0,
        ),
    );
}

export const internal = {
    bigintToBE32,
    be32ToBigInt,
    bigintToHex32,
    DOMAIN_PETITION_V2,
};
