// v3 Grumpkin VOPRF library (build, not yet production / unaudited).
// Promoted from the validated PoCs. Curve == Noir's embedded curve exactly
// (Grumpkin y^2=x^3-17, generator x=1, y=sqrt(-16)), so JS points and Noir
// embedded_curve_ops interoperate. Adds SvdW *hint* generation so we can feed
// a real witness to the oprf_commitment Noir circuit.

import { weierstrassPoints } from "@noble/curves/abstract/weierstrass";
import { Field } from "@noble/curves/abstract/modular";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes } from "@noble/hashes/utils";
import { bytesToNumberBE } from "@noble/curves/utils";

export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n; // base field (= BN254 scalar)
export const N = 21888242871839275222246405745257275088696311157297823662689037894645226208583n; // group order (= BN254 base)
export const Fp = Field(P);
export const Fn = Field(N);
const A = 0n;
export const B = Fp.create(-17n);
export const ZETA = 5n;            // least quadratic non-residue mod P
export const SVDW_Z = 1n;

export const g = (x) => Fp.add(Fp.mul(Fp.mul(x, x), x), B);
export const isSq = (v) => { if (v === 0n) return true; try { Fp.sqrt(v); return true; } catch { return false; } };

// Generator pinned to Noir's embedded-curve generator (verified identical).
const GEN_X = 1n;
const GEN_Y = 17631683881184975370165255887551781615748388533673675138860n;

export const { Point } = weierstrassPoints({ a: A, b: B, Fp, n: N, h: 1n, Gx: GEN_X, Gy: GEN_Y });
export const G = Point.BASE;

// ---- SvdW constants (RFC 9380 6.6.1) ----
const c1 = g(SVDW_Z);
const c2 = Fp.div(Fp.neg(SVDW_Z), 2n);
const c3 = Fp.sqrt(Fp.mul(Fp.neg(c1), Fp.add(Fp.mul(3n, Fp.mul(SVDW_Z, SVDW_Z)), Fp.mul(4n, A))));
const c4 = Fp.div(Fp.mul(-4n, c1), Fp.add(Fp.mul(3n, Fp.mul(SVDW_Z, SVDW_Z)), Fp.mul(4n, A)));
export const SVDW_CONSTS = { c1, c2, c3, c4 };

const sgn0 = (x) => x & 1n;

// map_to_curve_svdw + the exact hints the Noir circuit witnesses.
export function mapToCurveSvdW(u) {
    let tv1 = Fp.mul(Fp.mul(u, u), c1);
    const tv2 = Fp.add(1n, tv1);
    tv1 = Fp.sub(1n, tv1);
    const inv_t = Fp.inv(Fp.mul(tv1, tv2));
    const tv4 = Fp.mul(Fp.mul(Fp.mul(u, tv1), inv_t), c3);

    const x1 = Fp.sub(c2, tv4);
    const gx1 = g(x1);
    const e1 = isSq(gx1) ? 1n : 0n;
    const w1 = e1 === 1n ? Fp.sqrt(gx1) : Fp.sqrt(Fp.mul(gx1, ZETA));

    const x2 = Fp.add(c2, tv4);
    const gx2 = g(x2);
    const e2 = isSq(gx2) ? 1n : 0n;
    const w2 = e2 === 1n ? Fp.sqrt(gx2) : Fp.sqrt(Fp.mul(gx2, ZETA));

    const t = Fp.mul(Fp.mul(tv2, tv2), inv_t);
    const x3 = Fp.add(Fp.mul(Fp.mul(t, t), c4), SVDW_Z);

    let x = e1 === 1n ? x1 : x3;          // cmov(x3, x1, e1)
    const e2sel = (e2 === 1n && e1 === 0n) ? 1n : 0n;
    x = e2sel === 1n ? x2 : x;            // cmov(x, x2, e2sel)

    const gx = g(x);
    const sqrt_x = Fp.sqrt(gx);
    let y = sqrt_x;
    if (sgn0(u) !== sgn0(y)) y = Fp.neg(y);

    return { point: Point.fromAffine({ x, y }), hints: { inv_t, e1, w1, e2, w2, sqrt_x } };
}

// expand_message_xmd (SHA-256) + hash_to_field(count=2)
const DST = new TextEncoder().encode("CRISP-QES-V3-Grumpkin_XMD:SHA-256_SVDW_RO_");
const i2osp = (v, len) => { const o = new Uint8Array(len); for (let i = len - 1; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
function expandXmd(msg, lenInBytes) {
    const ell = Math.ceil(lenInBytes / 32);
    const dstPrime = concatBytes(DST, i2osp(BigInt(DST.length), 1));
    const b0 = sha256(concatBytes(new Uint8Array(64), msg, i2osp(BigInt(lenInBytes), 2), i2osp(0n, 1), dstPrime));
    let bi = sha256(concatBytes(b0, i2osp(1n, 1), dstPrime));
    let out = bi;
    for (let i = 2; i <= ell; i++) { const x = b0.map((v, j) => v ^ bi[j]); bi = sha256(concatBytes(x, i2osp(BigInt(i), 1), dstPrime)); out = concatBytes(out, bi); }
    return out.slice(0, lenInBytes);
}
const L = 48;
export function hashToField2(msg) {
    const bytes = expandXmd(msg, L * 2);
    return [Fp.create(bytesToNumberBE(bytes.slice(0, L))), Fp.create(bytesToNumberBE(bytes.slice(L, 2 * L)))];
}
export function hashToCurve(msg) {
    const [u0, u1] = hashToField2(msg);
    return mapToCurveSvdW(u0).point.add(mapToCurveSvdW(u1).point);
}

// scalar -> 128-bit (lo, hi) limbs for Noir EmbeddedCurveScalar
export const scalarLimbs = (s) => ({ lo: s & ((1n << 128n) - 1n), hi: s >> 128n });

// ---- VOPRF evaluation + Chaum-Pedersen DLEQ proof ----
// These mirror the oprf_nullifier Noir circuit so a JS-generated witness verifies.

// OPRF node evaluation: Y = k*M (k = node secret scalar, M = blinded element).
export function oprfEval(k, Mpoint) {
    return Mpoint.multiply(Fn.create(k));
}

// 32-byte big-endian encoding for bb.js pedersenHash inputs (mirrors aztec Fr).
const toBE32 = (v) => {
    const o = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
    return o;
};

// Pedersen hash matching Noir's std::hash::pedersen_hash exactly.
// Verified empirically: bb.js pedersenHash({inputs:[...32B BE], hashIndex:0})
// == Noir pedersen_hash([...]) (e.g. [4,8] -> 0x035d11...260504).
let _bbSync = null;
async function pedersenHashFields(fields) {
    if (!_bbSync) {
        const { BarretenbergSync } = await import("@aztec/bb.js");
        _bbSync = await BarretenbergSync.initSingleton();
    }
    const res = _bbSync.pedersenHash({ inputs: fields.map((f) => toBE32(Fp.create(f))), hashIndex: 0 });
    return bytesToNumberBE(res.hash);
}

// Honest Chaum-Pedersen DLEQ proof that Y = k*M and Kpub = k*G share the same k.
// Transcript field order MUST equal the circuit's:
//   [Gx,Gy, Kpx,Kpy, Mx,My, Yx,Yy, a1x,a1y, a2x,a2y]
// where a1 = t*G, a2 = t*M, c = pedersen(transcript), z = t + c*k mod N.
// c is the pedersen output (a base-field element < P < N) used directly as the
// challenge scalar -- identical value feeds both z and the circuit's MSM.
export async function dleqProve(k, Kpub, Mpoint, Ypoint, t) {
    // t: random nonce in [1, N). Caller may pass one (tests); else generated here.
    if (t === undefined) {
        t = (bytesToNumberBE(sha256(concatBytes(
            i2osp(Fn.create(k), 32),
            Mpoint.toRawBytes(true),
            Ypoint.toRawBytes(true),
        ))) % (N - 1n)) + 1n;
    }
    const a1 = G.multiply(Fn.create(t));
    const a2 = Mpoint.multiply(Fn.create(t));
    const Ga = G.toAffine();
    const Ka = Kpub.toAffine();
    const Ma = Mpoint.toAffine();
    const Ya = Ypoint.toAffine();
    const a1a = a1.toAffine();
    const a2a = a2.toAffine();
    const c = await pedersenHashFields([
        Ga.x, Ga.y, Ka.x, Ka.y, Ma.x, Ma.y, Ya.x, Ya.y, a1a.x, a1a.y, a2a.x, a2a.y,
    ]);
    // z = t + c*k mod N.
    const z = Fn.add(Fn.create(t), Fn.mul(Fn.create(c), Fn.create(k)));
    return { c, z };
}
