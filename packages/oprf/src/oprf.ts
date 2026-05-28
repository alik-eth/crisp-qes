// RFC 9497 §3.3 "Verifiable OPRF" (VOPRF) over the ristretto255-SHA512 suite.
//
// Suite identifier: "ristretto255-SHA512"   (RFC 9497 § 4.1)
// Mode byte:        0x01                    (Verifiable OPRF; § 3.0)
// contextString = "OPRFV1-" || 0x01 || "-ristretto255-SHA512"
//
// We implement only the server side here: BlindEvaluate (compute the OPRF
// share + the Chaum-Pedersen DLEQ proof that the share is correct under the
// server's published public key). Client side lives in `@crisp-qes/web` and
// follows § 3.3.3 (Blind / Finalize) verbatim.
//
// v2.1-prod note: in the threshold deploy each ciphernode runs *exactly* this
// BlindEvaluate over its Shamir share k_i; the client Lagrange-combines the
// per-share evaluations and verifies a combined DLEQ. The single-node demo
// keeps the wire format identical so the web client doesn't change.

import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";

/** Curve order n (ristretto255 prime subgroup, == 2^252 + 27742...493). */
const FN = ristretto255.Point.Fn;
type Point = InstanceType<typeof ristretto255.Point>;

const MODE_VOPRF = 0x01;
const SUITE_ID = "ristretto255-SHA512";

/** contextString = "OPRFV1-" || I2OSP(mode, 1) || "-" || SUITE_ID  (§ 3.0) */
const CONTEXT_STRING = new Uint8Array([
    ...new TextEncoder().encode("OPRFV1-"),
    MODE_VOPRF,
    ...new TextEncoder().encode(`-${SUITE_ID}`),
]);

const DST_HASH_TO_GROUP = concatBytes(
    new TextEncoder().encode("HashToGroup-"),
    CONTEXT_STRING,
);
const DST_HASH_TO_SCALAR = concatBytes(
    new TextEncoder().encode("HashToScalar-"),
    CONTEXT_STRING,
);

const TE = new TextEncoder();

// I2OSP(n, 2): two-byte big-endian length prefix used in RFC 9497 transcripts.
function i2osp2(n: number): Uint8Array {
    if (n < 0 || n > 0xffff) throw new RangeError("i2osp2 out of range");
    return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

/** SerializeElement: 32-byte canonical ristretto255 encoding. */
function se(p: Point): Uint8Array {
    return p.toBytes();
}

/** SerializeScalar: 32-byte little-endian encoding of a mod-n scalar. */
function ss(s: bigint): Uint8Array {
    const out = new Uint8Array(32);
    let x = s % FN.ORDER;
    if (x < 0n) x += FN.ORDER;
    for (let i = 0; i < 32; i++) {
        out[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return out;
}

/** DeserializeScalar: inverse of `ss`, reduces mod n. */
function ds(bytes: Uint8Array): bigint {
    if (bytes.length !== 32) throw new Error("scalar must be 32 bytes");
    let acc = 0n;
    for (let i = 31; i >= 0; i--) acc = (acc << 8n) | BigInt(bytes[i]!);
    return FN.create(acc);
}

/** RFC 9380 hash_to_curve over ristretto255 with the VOPRF DST. */
export function hashToGroup(msg: Uint8Array): Point {
    // `ristretto255_hasher.hashToCurve` returns the abstract H2CPoint type;
    // at runtime it is always a `ristretto255.Point` (see the hasher
    // definition in @noble/curves/ed25519). Cast to the concrete type so
    // downstream callers get `.toBytes` / `.multiply`.
    return ristretto255_hasher.hashToCurve(msg, {
        DST: DST_HASH_TO_GROUP,
    }) as unknown as Point;
}

/** RFC 9380 hash_to_field with the VOPRF DST, output reduced mod n. */
function hashToScalar(msg: Uint8Array): bigint {
    return ristretto255_hasher.hashToScalar(msg, { DST: DST_HASH_TO_SCALAR });
}

/**
 * Sample a uniformly-random non-zero scalar mod n.
 * (RFC 9497 § 3.2.1 `RandomScalar`.)
 */
export function randomScalar(): bigint {
    // Reject sampling — SHA-512 expand of 32 random bytes folded mod n gives
    // negligible bias. For demo simplicity we use the standard hash_to_scalar
    // primitive on fresh randomness; for v2.1-prod, switch to a true CSPRNG
    // + reject-sample loop matching the threshold-OPRF spec.
    const seed = crypto.getRandomValues(new Uint8Array(64));
    return hashToScalar(seed) || 1n;
}

/** Derive the OPRF public key K_pub = k * G from a secret scalar. */
export function derivePublicKey(k: bigint): Uint8Array {
    return se(ristretto255.Point.BASE.multiply(k));
}

export interface BlindEvaluateOutput {
    /** Y = k * blindedInput (32-byte ristretto255 encoding). */
    Y: Uint8Array;
    /**
     * DLEQ proof (c, s) showing `Y = k*M ∧ K_pub = k*G` under the same k.
     * Encoded as `c (32) || s (32)` little-endian scalars.
     */
    proof: Uint8Array;
}

/**
 * Server-side BlindEvaluate (RFC 9497 § 3.3.2, single element batch).
 *
 * `blindedInput`: M = r*X provided by the client (32 bytes).
 * `secretKey`:    k, the server's OPRF secret scalar.
 * `pubKey`:       precomputed K_pub = k*G, supplied so we don't recompute.
 *
 * Returns `(Y, π)` where π is a Chaum-Pedersen DLEQ proof. Verifier (client)
 * recomputes the challenge transcript using `K_pub, M, Y` and accepts iff
 * `c == HashToScalar(transcript)`.
 */
export function blindEvaluate(
    blindedInput: Uint8Array,
    secretKey: bigint,
    pubKey: Uint8Array,
): BlindEvaluateOutput {
    const M = ristretto255.Point.fromBytes(blindedInput);
    const Y = M.multiply(secretKey);
    const proof = generateProof(secretKey, pubKey, blindedInput, se(Y));
    return { Y: se(Y), proof };
}

/**
 * Chaum-Pedersen DLEQ proof generator. Matches RFC 9497 § 3.3.2
 * `GenerateProof` for batch size 1. Public inputs A = G, B = K_pub, C = M,
 * D = Y. We prove the dlog of B w.r.t. A equals the dlog of D w.r.t. C.
 *
 *   r ← random
 *   t2 = r*G, t3 = r*M
 *   c  = HashToScalar("Challenge" || len|B || B || len|C || C || len|D || D
 *                                  || len|t2|| t2|| len|t3|| t3)
 *   s  = r - c*k   mod n
 *   proof = (c, s)
 */
function generateProof(
    k: bigint,
    Kpub: Uint8Array,
    M: Uint8Array,
    Y: Uint8Array,
): Uint8Array {
    const r = randomScalar();
    const t2 = se(ristretto255.Point.BASE.multiply(r));
    const Mp = ristretto255.Point.fromBytes(M);
    const t3 = se(Mp.multiply(r));

    const transcript = concatBytes(
        TE.encode("Challenge"),
        i2osp2(Kpub.length), Kpub,
        i2osp2(M.length), M,
        i2osp2(Y.length), Y,
        i2osp2(t2.length), t2,
        i2osp2(t3.length), t3,
    );
    const c = hashToScalar(transcript);
    const s = FN.sub(r, FN.mul(c, k));
    return concatBytes(ss(c), ss(s));
}

/**
 * Client-side DLEQ verifier — only used by our own tests today; the real
 * client lives in `packages/web`. Mirrors RFC 9497 § 3.3.2 `VerifyProof`.
 */
export function verifyProof(
    Kpub: Uint8Array,
    M: Uint8Array,
    Y: Uint8Array,
    proof: Uint8Array,
): boolean {
    if (proof.length !== 64) return false;
    const c = ds(proof.slice(0, 32));
    const s = ds(proof.slice(32, 64));
    // Any decode failure (invalid ristretto255 encoding for K_pub, M, or Y)
    // counts as proof rejection — never throw out of a verifier.
    let Kp: Point, Mp: Point, Yp: Point;
    try {
        Kp = ristretto255.Point.fromBytes(Kpub);
        Mp = ristretto255.Point.fromBytes(M);
        Yp = ristretto255.Point.fromBytes(Y);
    } catch {
        return false;
    }
    // t2' = s*G + c*K_pub, t3' = s*M + c*Y
    const t2p = ristretto255.Point.BASE.multiply(s).add(Kp.multiply(c));
    const t3p = Mp.multiply(s).add(Yp.multiply(c));
    const transcript = concatBytes(
        TE.encode("Challenge"),
        i2osp2(Kpub.length), Kpub,
        i2osp2(M.length), M,
        i2osp2(Y.length), Y,
        i2osp2(32), se(t2p),
        i2osp2(32), se(t3p),
    );
    const cExpected = hashToScalar(transcript);
    return FN.eql(c, cExpected);
}

/**
 * Test-only client helper: blind an input by sampling r and returning
 * (r, M = r*H_to_curve(input)). Lives here so the OPRF round-trip test
 * doesn't have to duplicate the wire format.
 */
export function blind(input: Uint8Array): { r: bigint; M: Uint8Array } {
    const r = randomScalar();
    const X = hashToGroup(input);
    return { r, M: se(X.multiply(r)) };
}

/**
 * Test-only client helper: unblind Y by multiplying by r⁻¹ to recover
 * N = k * H_to_curve(input).
 */
export function unblind(r: bigint, Y: Uint8Array): Uint8Array {
    const rInv = FN.inv(r);
    return se(ristretto255.Point.fromBytes(Y).multiply(rInv));
}

/** Hex helpers used by the API layer. */
export const toHex = (b: Uint8Array): `0x${string}` => `0x${bytesToHex(b)}`;
export const fromHex = (h: string): Uint8Array =>
    hexToBytes(h.startsWith("0x") ? h.slice(2) : h);

/** Re-export for the app layer + tests. */
export { ristretto255, sha512 };
