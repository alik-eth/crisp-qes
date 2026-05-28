// RFC 9497 VOPRF client over ristretto255 (`VOPRF-ristretto255-SHA512`).
//
// This is the client side of the OPRF protocol used at enrollment.
//
// Flow:
//   1. Client picks random scalar `r ∈ Z_l*`, where `l` is the ristretto255
//      group order.
//   2. Computes input point `T = H(input)` via the ristretto255 hash-to-curve
//      (suite "ristretto255_XMD:SHA-512_R255MAP_RO_").
//   3. Sends `M = r * T` (32-byte ristretto encoding) to the server.
//   4. Server replies with `Y = k * M` and a Chaum-Pedersen DLEQ proof
//      `(c, s)` showing `Y = k*M ∧ K = k*G` for the same `k`.
//   5. Client verifies the proof, then unblinds: `N = r⁻¹ * Y = k * T`.
//
// DLEQ verification (single-share form — server is "the prover"):
//   Given commitment `K = k*G` (server pubkey), `M`, `Y = k*M`:
//   - Server picks random `t`; sends:
//        a = t*G,  b = t*M
//        c = H(K || M || Y || a || b)
//        s = t - c*k    (mod l)
//   - Client reconstructs:
//        a' = s*G + c*K
//        b' = s*M + c*Y
//        c' = H(K || M || Y || a' || b')
//        verifies c == c'.
//
// The hash for `c` is SHA-512 truncated to a scalar mod l — that's what
// RFC 9497 § 2.2.2 specifies. We construct it via the standard
// `hashToScalar`-style reduction.

import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";

// Ristretto255 group order (= ed25519 scalar field prime `l`):
// 2^252 + 27742317777372353535851937790883648493
const L =
    7237005577332262213973186563042994240857116359379907606001950938285454250989n;

// Helpers ---------------------------------------------------------------

function bytesToBigIntLE(b: Uint8Array): bigint {
    let n = 0n;
    for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
    return n;
}

function bigintToBytesLE(n: bigint, len: number): Uint8Array {
    const out = new Uint8Array(len);
    let v = n;
    for (let i = 0; i < len; i++) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return out;
}

function mod(n: bigint, m: bigint): bigint {
    const r = n % m;
    return r >= 0n ? r : r + m;
}

function invertMod(a: bigint, m: bigint): bigint {
    // Extended Euclidean. Assumes gcd(a, m) == 1.
    let [oldR, r] = [mod(a, m), m];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
        const q = oldR / r;
        [oldR, r] = [r, oldR - q * r];
        [oldS, s] = [s, oldS - q * s];
    }
    return mod(oldS, m);
}

/** SHA-512 → scalar mod l (wide reduction). */
function hashToScalar(...chunks: Uint8Array[]): bigint {
    let total = 0;
    for (const c of chunks) total += c.length;
    const buf = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
        buf.set(c, off);
        off += c.length;
    }
    const h = sha512(buf); // 64 bytes
    return mod(bytesToBigIntLE(h), L);
}

/** Sample a non-zero scalar uniformly mod l using rejection sampling. */
function randomScalar(): bigint {
    const buf = new Uint8Array(64);
    for (;;) {
        crypto.getRandomValues(buf);
        const r = mod(bytesToBigIntLE(buf), L);
        if (r !== 0n) return r;
    }
}

// Public API ------------------------------------------------------------

export interface BlindResult {
    /** Blinding factor `r`. Keep until unblind. */
    blind: bigint;
    /** 32-byte ristretto encoding of `M = r * H(input)` to send to server. */
    blindedElement: Uint8Array;
}

/** Step 1 + 2: hash input to ristretto, blind, encode. */
export function blind(input: Uint8Array): BlindResult {
    const T = ristretto255_hasher.hashToCurve(input, {
        DST: new TextEncoder().encode("OPRF-V01-CS04-"),
    });
    const r = randomScalar();
    const M = (T as unknown as InstanceType<
        typeof ristretto255.Point
    >).multiply(r);
    return { blind: r, blindedElement: M.toBytes() };
}

export interface BlindEvalProof {
    /** Server pubkey `K = k*G` (32-byte ristretto encoding). */
    serverPubkey: Uint8Array;
    /** Evaluated point `Y = k*M`. */
    evaluatedElement: Uint8Array;
    /** DLEQ proof `(c, s)` — each a 32-byte little-endian scalar. */
    proofC: Uint8Array;
    proofS: Uint8Array;
}

/** Verify the server's DLEQ proof. Returns true iff valid. */
export function verifyBlindEval(
    blindedElement: Uint8Array,
    p: BlindEvalProof,
): boolean {
    const G = ristretto255.Point.BASE;
    const K = ristretto255.Point.fromBytes(p.serverPubkey);
    const M = ristretto255.Point.fromBytes(blindedElement);
    const Y = ristretto255.Point.fromBytes(p.evaluatedElement);

    const c = mod(bytesToBigIntLE(p.proofC), L);
    const s = mod(bytesToBigIntLE(p.proofS), L);

    // a' = s*G + c*K, b' = s*M + c*Y
    const aPrime = G.multiply(s).add(K.multiply(c));
    const bPrime = M.multiply(s).add(Y.multiply(c));

    const cPrime = hashToScalar(
        p.serverPubkey,
        blindedElement,
        p.evaluatedElement,
        aPrime.toBytes(),
        bPrime.toBytes(),
        new TextEncoder().encode("OPRF-V01-CS04-DLEQ"),
    );

    return cPrime === c;
}

/** Step 5: unblind `Y` to obtain the OPRF output `N = k * H(input)`. */
export function unblind(
    evaluatedElement: Uint8Array,
    blindingFactor: bigint,
): Uint8Array {
    const Y = ristretto255.Point.fromBytes(evaluatedElement);
    const rInv = invertMod(blindingFactor, L);
    const N = Y.multiply(rInv);
    return N.toBytes();
}

export const internal = {
    bigintToBytesLE,
    bytesToBigIntLE,
    invertMod,
    hashToScalar,
    L,
};
