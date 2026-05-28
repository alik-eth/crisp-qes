// RFC 9497 VOPRF client over ristretto255 (`VOPRF-ristretto255-SHA512`).
//
// Wire-compatible with the server in `packages/oprf/src/oprf.ts`:
//
//   contextString = "OPRFV1-" || 0x01 || "-ristretto255-SHA512"
//   DST_HashToGroup  = "HashToGroup-"  || contextString
//   DST_HashToScalar = "HashToScalar-" || contextString
//
//   Client (this file):
//     1. r ← RandomScalar()
//     2. T = HashToGroup(input, DST_HashToGroup)
//     3. M = r·T               (send hex(M) as `blindedInput`)
//
//   Server (BlindEvaluate):
//     4. Y = k·M               (returns hex(Y))
//     5. proof = (c, s) — DLEQ via Chaum-Pedersen, RFC 9497 § 3.3.2:
//          r' ← random; t2 = r'·G; t3 = r'·M
//          c  = HashToScalar(
//                  "Challenge" ||
//                  i2osp2(|Kpub|) || Kpub ||
//                  i2osp2(|M|)    || M    ||
//                  i2osp2(|Y|)    || Y    ||
//                  i2osp2(|t2|)   || t2   ||
//                  i2osp2(|t3|)   || t3
//               )
//          s  = r' - c·k  (mod n)
//          wire encoding = ss(c) (32 LE) || ss(s) (32 LE)
//
//   Client (VerifyProof):
//     6. (c, s) ← deserialise
//     7. t2' = s·G + c·Kpub
//        t3' = s·M + c·Y
//        c'  = HashToScalar(transcript with t2', t3')
//        verify c == c'.
//
//   Client (Unblind):
//     8. N = r⁻¹·Y             (32-byte ristretto255 encoding)

import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519";

// Ristretto255 group order n (ed25519 scalar field prime):
const N_ORDER =
    7237005577332262213973186563042994240857116359379907606001950938285454250989n;

// — RFC 9497 § 3.0 contextString ----------------------------------------

const TE = new TextEncoder();
const CONTEXT_STRING = (() => {
    // "OPRFV1-" || I2OSP(mode=0x01, 1) || "-ristretto255-SHA512"
    const prefix = TE.encode("OPRFV1-");
    const suffix = TE.encode("-ristretto255-SHA512");
    const out = new Uint8Array(prefix.length + 1 + suffix.length);
    out.set(prefix, 0);
    out[prefix.length] = 0x01;
    out.set(suffix, prefix.length + 1);
    return out;
})();

function concat(...parts: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    return out;
}

const DST_HASH_TO_GROUP = concat(TE.encode("HashToGroup-"), CONTEXT_STRING);
const DST_HASH_TO_SCALAR = concat(TE.encode("HashToScalar-"), CONTEXT_STRING);

// I2OSP(n, 2): two-byte big-endian length prefix.
function i2osp2(n: number): Uint8Array {
    if (n < 0 || n > 0xffff) throw new RangeError("i2osp2 out of range");
    return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

// — Scalar helpers (LE encoding per RFC 9497) ---------------------------

function ds(bytes: Uint8Array): bigint {
    if (bytes.length !== 32) throw new Error("scalar must be 32 bytes");
    let acc = 0n;
    for (let i = 31; i >= 0; i--) acc = (acc << 8n) | BigInt(bytes[i]!);
    return mod(acc, N_ORDER);
}

function mod(n: bigint, m: bigint): bigint {
    const r = n % m;
    return r >= 0n ? r : r + m;
}

function invertMod(a: bigint, m: bigint): bigint {
    let [oldR, r] = [mod(a, m), m];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
        const q = oldR / r;
        [oldR, r] = [r, oldR - q * r];
        [oldS, s] = [s, oldS - q * s];
    }
    return mod(oldS, m);
}

// noble's RFC-9380 hashToScalar with the OPRF DST.
function hashToScalar(msg: Uint8Array): bigint {
    return ristretto255_hasher.hashToScalar(msg, { DST: DST_HASH_TO_SCALAR });
}

function hashToGroupPoint(msg: Uint8Array) {
    return ristretto255_hasher.hashToCurve(msg, {
        DST: DST_HASH_TO_GROUP,
    }) as unknown as InstanceType<typeof ristretto255.Point>;
}

function randomScalar(): bigint {
    // Mirrors the server's RandomScalar: expand 64 fresh random bytes
    // through the suite hashToScalar (RFC 9497 § 3.2.1).
    const seed = new Uint8Array(64);
    crypto.getRandomValues(seed);
    const r = hashToScalar(seed);
    return r === 0n ? 1n : r;
}

// — Public API ----------------------------------------------------------

export interface BlindResult {
    /** Blinding factor `r`. Keep until unblind. */
    blind: bigint;
    /** 32-byte ristretto encoding of `M = r * H(input)` to send to server. */
    blindedElement: Uint8Array;
}

/** Step 1+2+3: hash input to ristretto, blind, encode. */
export function blind(input: Uint8Array): BlindResult {
    const T = hashToGroupPoint(input);
    const r = randomScalar();
    const M = T.multiply(r);
    return { blind: r, blindedElement: M.toBytes() };
}

export interface BlindEvalProof {
    /** Server pubkey `K = k*G` (32-byte ristretto encoding). */
    serverPubkey: Uint8Array;
    /** Evaluated point `Y = k*M`. */
    evaluatedElement: Uint8Array;
    /** DLEQ proof concatenated as `c (32 LE) || s (32 LE)` = 64 bytes total. */
    proof: Uint8Array;
}

/**
 * Verify the server's RFC 9497 § 3.3.2 Chaum-Pedersen DLEQ proof.
 * Returns true iff valid.
 */
export function verifyBlindEval(
    blindedElement: Uint8Array,
    p: BlindEvalProof,
): boolean {
    if (p.proof.length !== 64) return false;
    let Kp, Mp, Yp;
    try {
        Kp = ristretto255.Point.fromBytes(p.serverPubkey);
        Mp = ristretto255.Point.fromBytes(blindedElement);
        Yp = ristretto255.Point.fromBytes(p.evaluatedElement);
    } catch {
        return false;
    }
    const c = ds(p.proof.subarray(0, 32));
    const s = ds(p.proof.subarray(32, 64));

    const G = ristretto255.Point.BASE;
    const t2 = G.multiply(s).add(Kp.multiply(c));
    const t3 = Mp.multiply(s).add(Yp.multiply(c));

    const transcript = concat(
        TE.encode("Challenge"),
        i2osp2(p.serverPubkey.length),
        p.serverPubkey,
        i2osp2(blindedElement.length),
        blindedElement,
        i2osp2(p.evaluatedElement.length),
        p.evaluatedElement,
        i2osp2(32),
        t2.toBytes(),
        i2osp2(32),
        t3.toBytes(),
    );
    const cExpected = hashToScalar(transcript);
    return c === cExpected;
}

/** Unblind `Y` to recover `N = r⁻¹ · Y = k * H(input)`. */
export function unblind(
    evaluatedElement: Uint8Array,
    blindingFactor: bigint,
): Uint8Array {
    const Y = ristretto255.Point.fromBytes(evaluatedElement);
    const rInv = invertMod(blindingFactor, N_ORDER);
    return Y.multiply(rInv).toBytes();
}

export const internal = {
    N_ORDER,
    invertMod,
    hashToScalar,
    hashToGroupPoint,
    randomScalar,
    ds,
};
