// Phase-0 (task #39): RFC-9380 hash-to-curve for Grumpkin via the
// Shallue-van de Woestijne (SvdW) map. Grumpkin has a=0, so simplified-SWU
// doesn't apply directly; SvdW works for any short-Weierstrass curve and is
// the clean choice. Cofactor 1 => no clear_cofactor step.
//
// This validates correctness (on-curve, deterministic, distinct inputs ->
// distinct points) and is structured to mirror an in-circuit implementation
// (count the field ops: ~1 sqrt + 2 inv0 + ~20 muls + CMOVs per map).
//
// Still feasibility-grade: constants/DST not finalized, no test vectors
// cross-checked against an independent impl yet -- that's the security-review
// item. But this is a real RFC-9380 SvdW, not try-and-increment.

import { weierstrassPoints } from "@noble/curves/abstract/weierstrass";
import { Field } from "@noble/curves/abstract/modular";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes } from "@noble/hashes/utils";
import { bytesToNumberBE } from "@noble/curves/utils";

const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const n = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Fp = Field(p);
const A = 0n;
const B = Fp.create(-17n);

const g = (x) => Fp.add(Fp.add(Fp.mul(Fp.mul(x, x), x), Fp.mul(A, x)), B); // x^3+Ax+B
const isSq = (v) => { if (v === 0n) return true; try { Fp.sqrt(v); return true; } catch { return false; } };

// --- find_z_svdw (RFC 9380 H.1) ---
function findZ() {
    const candidates = [];
    for (let i = 1n; i < 1000n; i++) { candidates.push(i); candidates.push(Fp.neg(i)); }
    for (const Z of candidates) {
        const gZ = g(Z);
        if (gZ === 0n) continue;
        const denom = Fp.mul(4n, gZ);
        const hZ = Fp.mul(Fp.neg(Fp.add(Fp.mul(3n, Fp.mul(Z, Z)), Fp.mul(4n, A))), Fp.inv(denom));
        if (hZ === 0n || !isSq(hZ)) continue;
        if (isSq(gZ) || isSq(g(Fp.div(Fp.neg(Z), 2n)))) return Z;
    }
    throw new Error("no SvdW Z found");
}

const Z = findZ();
// SvdW constants
const c1 = g(Z);                                              // g(Z)
const c2 = Fp.div(Fp.neg(Z), 2n);                             // -Z/2
const c3 = Fp.sqrt(Fp.mul(Fp.neg(c1), Fp.add(Fp.mul(3n, Fp.mul(Z, Z)), Fp.mul(4n, A)))); // sqrt(-g(Z)(3Z^2+4A))
const c4 = Fp.div(Fp.mul(-4n, c1), Fp.add(Fp.mul(3n, Fp.mul(Z, Z)), Fp.mul(4n, A)));      // -4g(Z)/(3Z^2+4A)

const inv0 = (x) => (x === 0n ? 0n : Fp.inv(x));
const sgn0 = (x) => x & 1n;
const cmov = (a, b, c) => (c ? b : a);

// RFC 9380 6.6.1 map_to_curve_svdw
function mapToCurveSvdW(u) {
    let tv1 = Fp.mul(Fp.mul(u, u), c1);
    const tv2 = Fp.add(1n, tv1);
    tv1 = Fp.sub(1n, tv1);
    let tv3 = inv0(Fp.mul(tv1, tv2));
    let tv4 = Fp.mul(Fp.mul(Fp.mul(u, tv1), tv3), c3);
    const x1 = Fp.sub(c2, tv4);
    const gx1 = g(x1);
    const e1 = isSq(gx1);
    const x2 = Fp.add(c2, tv4);
    const gx2 = g(x2);
    const e2 = isSq(gx2) && !e1;
    let x3 = Fp.mul(Fp.mul(tv2, tv2), tv3);
    x3 = Fp.add(Fp.mul(Fp.mul(x3, x3), c4), Z);
    let x = cmov(x3, x1, e1);
    x = cmov(x, x2, e2);
    const gx = g(x);
    let y = Fp.sqrt(gx);
    const e3 = sgn0(u) === sgn0(y);
    y = cmov(Fp.neg(y), y, e3);
    return { x, y };
}

// expand_message_xmd (RFC 9380 5.3.1) with SHA-256
const DST = new TextEncoder().encode("CRISP-QES-V3-Grumpkin_XMD:SHA-256_SVDW_RO_");
function i2osp(v, len) { const o = new Uint8Array(len); for (let i = len - 1; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; }
function expandXmd(msg, lenInBytes) {
    const bInBytes = 32, ell = Math.ceil(lenInBytes / bInBytes);
    const dstPrime = concatBytes(DST, i2osp(BigInt(DST.length), 1));
    const b0 = sha256(concatBytes(new Uint8Array(64), msg, i2osp(BigInt(lenInBytes), 2), i2osp(0n, 1), dstPrime));
    let bi = sha256(concatBytes(b0, i2osp(1n, 1), dstPrime));
    let out = bi;
    for (let i = 2; i <= ell; i++) {
        const xored = b0.map((x, j) => x ^ bi[j]);
        bi = sha256(concatBytes(xored, i2osp(BigInt(i), 1), dstPrime));
        out = concatBytes(out, bi);
    }
    return out.slice(0, lenInBytes);
}
const L = 48; // ceil((254 + 128)/8)
function hashToField(msg, count) {
    const bytes = expandXmd(msg, L * count);
    const out = [];
    for (let i = 0; i < count; i++) out.push(Fp.create(bytesToNumberBE(bytes.slice(i * L, (i + 1) * L))));
    return out;
}

const { Point } = (() => {
    // generator (cofactor 1)
    let Gx = 0n, Gy = 0n;
    for (let x = 1n; x < 50n; x++) { const xx = Fp.create(x); if (isSq(g(xx)) && g(xx) !== 0n) { Gx = xx; Gy = Fp.sqrt(g(xx)); break; } }
    return weierstrassPoints({ a: A, b: B, Fp, n, h: 1n, Gx, Gy });
})();

// Shared curve handles so the OPRF PoC uses the same instance.
export { Point, Fp, n };
export const G = Point.BASE;

export function hashToCurveGrumpkin(msg) {
    const [u0, u1] = hashToField(msg, 2);
    const q0 = mapToCurveSvdW(u0), q1 = mapToCurveSvdW(u1);
    const P0 = Point.fromAffine({ x: q0.x, y: q0.y });
    const P1 = Point.fromAffine({ x: q1.x, y: q1.y });
    return P0.add(P1); // clear_cofactor = identity (h=1)
}

// === validation (run directly) ===
if (import.meta.url === `file://${process.argv[1]}`) {
    let pass = true;
    const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); pass &&= ok; };
    console.log(`SvdW Z = ${Z}`);

    const onCurve = (q) => Fp.mul(q.y, q.y) === g(q.x);
    check("map_to_curve_svdw output is on-curve (sample u)", onCurve(mapToCurveSvdW(123456789n)));
    check("map_to_curve_svdw on-curve (u=0)", onCurve(mapToCurveSvdW(0n)));
    check("map_to_curve_svdw on-curve (random-ish)", onCurve(mapToCurveSvdW(Fp.create(0xdeadbeefn))));

    const m = new TextEncoder().encode("1234567890");
    const P = hashToCurveGrumpkin(m);
    const Paff = P.toAffine();
    check("hash_to_curve point is on the curve", onCurve(Paff));
    check("hash_to_curve is deterministic", hashToCurveGrumpkin(m).equals(hashToCurveGrumpkin(m)));
    check("distinct inputs -> distinct points",
        !hashToCurveGrumpkin(new TextEncoder().encode("9999999999")).equals(P));
    // h=1: every on-curve point is already in the prime-order group, so the
    // multiply-by-n identity check is trivially implied by on-curve above.

    console.log(`\n${pass ? "ALL PASS - RFC-9380 SvdW hash-to-curve works on Grumpkin" : "FAILURES"}`);
    process.exit(pass ? 0 : 1);
}
