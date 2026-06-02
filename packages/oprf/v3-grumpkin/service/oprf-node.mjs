// v3 Grumpkin VOPRF node (build, unaudited — does NOT touch the live v2 service).
//
// This is the v3 analogue of the v2 `blindEvaluate` server primitive, but over
// Grumpkin (Noir's embedded curve) instead of ristretto255. It REUSES
// ../lib.mjs for all curve / OPRF / DLEQ math so the JS node stays bit-for-bit
// consistent with the oprf_nullifier Noir circuit — we never reimplement the
// curve here.
//
// Role in the protocol (mirrors gen-nullifier-witness.mjs):
//   client: M = r*H2C(input)              (blinded element)
//   node :  Y = k*M, DLEQ proof (c, z)    (THIS module; Kpub = k*G published)
//   client: verify DLEQ, N = rinv*Y, commitment = pedersen(N)
//
// Wire encoding for Grumpkin points — see `pointToHex` / `pointFromHex` below.

import { Point, G, Fn, N, oprfEval, dleqProve, dleqProveShare } from "../lib.mjs";
import { dkgKeygen } from "../threshold/threshold-oprf.mjs";

// — Wire format ──────────────────────────────────────────────────────────────
//
// A Grumpkin point is sent as its affine (x, y) coordinates, each a base-field
// element (< P, ~254 bits) serialized as fixed-width 32-byte big-endian hex,
// concatenated and 0x-prefixed:  0x{x:64 hex}{y:64 hex}  (130 chars incl. 0x).
//
// We chose uncompressed affine x||y rather than a compressed encoding because:
//   * the Noir circuit witnesses points as (x, y) affine pairs (see the
//     gen-*-witness.mjs TOMLs: gx/gy, kpx/kpy, mx/my, yx/yy) — keeping the wire
//     in the same coordinates means the server response maps 1:1 onto circuit
//     inputs with no decompression step that would have to be re-proven;
//   * it is trivially round-trippable via @noble's Point.fromAffine /
//     toAffine, which lib.mjs already uses everywhere;
//   * point validity (on-curve) is enforced by Point.fromAffine on decode.
//
// The point at infinity is not a valid OPRF wire value and is rejected.

const FIELD_HEX_LEN = 64; // 32 bytes

function feToHex(v) {
    if (v < 0n) throw new Error("feToHex: negative field element");
    const hex = v.toString(16);
    if (hex.length > FIELD_HEX_LEN) {
        throw new Error("feToHex: field element exceeds 32 bytes");
    }
    return hex.padStart(FIELD_HEX_LEN, "0");
}

/** Serialize a Grumpkin point to `0x{x}{y}` fixed-width big-endian hex. */
export function pointToHex(point) {
    if (point.is0?.() || point.equals?.(Point.ZERO)) {
        throw new Error("pointToHex: refusing to serialize point at infinity");
    }
    const aff = point.toAffine();
    return `0x${feToHex(aff.x)}${feToHex(aff.y)}`;
}

/** Parse `0x{x}{y}` hex back into an on-curve Grumpkin point (validates). */
export function pointFromHex(hex) {
    if (typeof hex !== "string" || !/^0x[0-9a-fA-F]{128}$/.test(hex)) {
        throw new Error(
            "pointFromHex: expected 0x-prefixed 64-byte (x||y) hex",
        );
    }
    const body = hex.slice(2);
    const x = BigInt(`0x${body.slice(0, FIELD_HEX_LEN)}`);
    const y = BigInt(`0x${body.slice(FIELD_HEX_LEN)}`);
    // fromAffine throws if (x, y) is not on the Grumpkin curve.
    const point = Point.fromAffine({ x, y });
    point.assertValidity?.();
    return point;
}

// — Node ─────────────────────────────────────────────────────────────────────

/**
 * A single Grumpkin VOPRF node. Holds the secret scalar k and publishes
 * Kpub = k*G. Stateless beyond k — one instance per node key.
 */
export class OprfNode {
    /** @param {bigint} k secret scalar in [1, N). */
    constructor(k) {
        if (typeof k !== "bigint") throw new Error("OprfNode: k must be a bigint");
        const kk = Fn.create(k);
        if (kk === 0n) throw new Error("OprfNode: k must be non-zero mod N");
        this.k = kk;
        this.Kpub = G.multiply(this.k); // node public key, k*G
    }

    /** Node public key Kpub = k*G, as wire hex. */
    publicKeyHex() {
        return pointToHex(this.Kpub);
    }

    /**
     * BlindEvaluate: given the client's blinded element M (wire hex), compute
     * Y = k*M and an honest Chaum-Pedersen DLEQ proof that Y and Kpub share k.
     *
     * @param {string} Mhex blinded point `0x{x}{y}`.
     * @param {bigint} [t]  optional DLEQ nonce override (tests); else derived.
     * @returns {{ Y: string, dleq: { c: bigint, z: bigint }, Kpub: string }}
     */
    async evaluate(Mhex, t) {
        const M = pointFromHex(Mhex);
        const Y = oprfEval(this.k, M); // Y = k*M (via lib.mjs)
        const { c, z } = await dleqProve(this.k, this.Kpub, M, Y, t);
        return {
            Y: pointToHex(Y),
            dleq: { c, z },
            Kpub: this.publicKeyHex(),
        };
    }
}

// — Threshold share node ──────────────────────────────────────────────────────

/**
 * A single THRESHOLD (t-of-n) OPRF share node. Holds ONLY its Shamir share k_i
 * (never the group key k) and publishes Kpub_i = k_i*G as a verifiable commitment
 * to its share. On evaluate() it returns its partial B_i = k_i*M plus a per-share
 * epoch-bound Chaum-Pedersen DLEQ proving log_G(Kpub_i) == log_M(B_i) -- so the
 * combiner/circuit can reject a faulty/malicious node and a stale (wrong-epoch)
 * partial. The group key k is never assembled at any single node (the F4 design).
 */
export class ShareNode {
    /** @param {{ i: bigint, k_i: bigint }} args node index i (>=1) + Shamir share. */
    constructor({ i, k_i }) {
        if (typeof i !== "bigint") throw new Error("ShareNode: i must be a bigint");
        if (typeof k_i !== "bigint") throw new Error("ShareNode: k_i must be a bigint");
        const kk = Fn.create(k_i);
        if (kk === 0n) throw new Error("ShareNode: k_i must be non-zero mod N");
        this.i = i;
        this.k_i = kk;
        this.Kpub_i = G.multiply(this.k_i); // published share public key, k_i*G
    }

    /** This node's published share public key Kpub_i = k_i*G, as wire hex. */
    publicKeyHexShare() {
        return pointToHex(this.Kpub_i);
    }

    /** The node's published commitment { i, Kpub_i: hex } for the published set. */
    publicShare() {
        return { i: this.i, Kpub_i: this.publicKeyHexShare() };
    }

    /**
     * Partial blind-evaluate: given M (wire hex) and the session `epoch`, compute
     * B_i = k_i*M and a per-share epoch-bound DLEQ. `epoch` is REQUIRED (session
     * binding) -- a partial is only valid for the epoch it was issued under.
     *
     * @param {string} Mhex  blinded point `0x{x}{y}`.
     * @param {bigint} epoch session tag (bound into the DLEQ transcript).
     * @param {bigint} [t]   optional DLEQ nonce override (tests); else derived.
     * @returns {{ i: bigint, B_i: string, dleq: { c: bigint, z: bigint }, Kpub_i: string }}
     */
    async evaluate(Mhex, epoch, t) {
        if (typeof epoch !== "bigint") {
            throw new Error("ShareNode.evaluate: epoch (bigint) is required (session binding)");
        }
        const M = pointFromHex(Mhex);
        const B_i = oprfEval(this.k_i, M); // B_i = k_i*M (via lib.mjs)
        const { c, z } = await dleqProveShare(this.Kpub_i, this.k_i, M, B_i, epoch, t);
        return {
            i: this.i,
            B_i: pointToHex(B_i),
            dleq: { c, z },
            Kpub_i: this.publicKeyHexShare(),
        };
    }
}

/**
 * Spin up an n-node t-of-n share set via the prototype DKG-lite keygen. Returns:
 *   nodes:     ShareNode[] (one per share, i = 1..n)
 *   published: [{ i, Kpub_i: hex }] -- the published Kpub set (verifiable
 *              commitments; the service pins these as the canonical set)
 *   kImplied:  the effective group key k' -- TEST-ONLY (for cross-checking the
 *              canonical nullifier == single-key pedersen(k'*H2C(id))). In
 *              production NO party knows k'; a live DKG never reveals it.
 *
 * This is the helper the 3-node demo (Tasks 5/7) uses. epoch is carried by each
 * evaluate() call, not stored on the node (a node serves multiple sessions).
 *
 * @param {number} n number of nodes.
 * @param {number} t threshold (any t of n can evaluate).
 * @param {bigint} [epoch] accepted for call-site symmetry; UNUSED at keygen
 *        (epoch is a per-session value carried by each ShareNode.evaluate call,
 *        not a property of the share set).
 * @returns {{ nodes: ShareNode[], published: Array<{i: bigint, Kpub_i: string}>, kImplied: bigint }}
 */
export function makeNodes(n, t, _epoch) {
    const { shares, kImplied } = dkgKeygen(n, t);
    const nodes = shares.map((s) => new ShareNode({ i: BigInt(s.i), k_i: s.k_i }));
    const published = nodes.map((node) => node.publicShare());
    return { nodes, published, kImplied };
}

// Re-export curve order so callers can size scalars without reaching into lib.
export { N };
