// Pedersen helpers that match the v2 circuit (#30) and OPRF server (#32).
//
// Team-lead re-pin (2026-05-29):
//   • Single value `s = pedersen_hash([N_hi, N_lo], hashIndex=0)`.
//   • `s` IS the enrollment secret AND the on-chain Merkle leaf AND the
//     value the OPRF server stores as `commitment`. No extra wrapping hash.
//   • Domain separators are all `hashIndex=0` in v2.1; `hashIndex=1` is
//     reserved for the v2.2 JCJ branch — do not use it yet.
//   • Nullifier (public): `pedersen_hash([s, petition_id, DOMAIN_PETITION_V2], 0)`.
//
// `Fr` is no longer exported from @aztec/bb.js@4.x; bb.js expects raw
// 32-byte big-endian BN254 field elements. We convert at the edges.

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

/** Split a 32-byte big-endian buffer into two 128-bit limbs (hi, lo). */
export function splitBE32(buf: Uint8Array): { hi: bigint; lo: bigint } {
    if (buf.length !== 32) throw new Error("splitBE32: expected 32 bytes");
    let hi = 0n;
    let lo = 0n;
    for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(buf[i]!);
    for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(buf[i]!);
    return { hi, lo };
}

/**
 * Derive `s = pedersen_hash([N_hi, N_lo], 0)` — the single value the rest
 * of v2.1 uses as enrollment secret, on-chain commitment, and Merkle
 * leaf. `N` is the 32-byte unblinded ristretto255 OPRF output.
 *
 * Note: ristretto255 encodes 32-byte points as canonical *little-endian*
 * encodings of the (x, y) compressed representation. The OPRF server
 * (#32) also limbifies via BE on the 32-byte ristretto encoding — both
 * sides treat the OPRF output as an opaque 32-byte buffer when feeding
 * pedersen. We follow suit.
 */
export async function pedersenS(N: Uint8Array): Promise<`0x${string}`> {
    const { hi, lo } = splitBE32(N);
    return bigintToHex32(await pedersenFields([hi, lo], 0));
}

/**
 * Compute the nullifier for a `(s, petition_id)` pair.
 *   nullifier = pedersen_hash([s, petition_id, DOMAIN_PETITION_V2], 0)
 */
export async function pedersenNullifier(
    sHex: `0x${string}`,
    petitionId: bigint,
): Promise<`0x${string}`> {
    return bigintToHex32(
        await pedersenFields(
            [hexToBigInt(sHex), petitionId, DOMAIN_PETITION_V2],
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
