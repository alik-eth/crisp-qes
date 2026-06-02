// F3 FORGERY helper: SvdW map parameterized by ATTACKER-CHOSEN constants
// (c1,c2,c3,c4), emitting the exact hints [inv_t,e1,w1,e2,w2,sqrt_x] the Noir
// svdw_map asserts. Mirrors the circuit's selection + sgn0 logic so the produced
// witness satisfies every in-circuit assert with NON-canonical constants.
//
// Demonstration suite: c3 = 0 => tv4 = 0 => x1 = x2 = c2. Choose c2 = the
// x-coordinate of an on-curve point P (so g(c2) is square => e1 = 1 => selected
// x = x1 = c2). c1 is any value keeping tv1*tv2 != 0; c4 is unused (x3 not
// selected). Both u0,u1 then map to +/-P, landing a DIFFERENT H2C' than the
// canonical suite => a DIFFERENT (and unbounded) M for the same identity.

import { Fp, ZETA, SVDW_Z, g, isSq, Point } from "./lib.mjs";

const sgn0 = (x) => x & 1n;

// Map u with arbitrary (c1,c2,c3,c4); returns { point, hints } where hints are
// exactly what the circuit's svdw_map expects. Throws if the chosen constants
// don't yield an in-circuit-valid witness for this u (so callers fail loudly).
export function forgedMap(u, c1, c2, c3, c4) {
    let tv1 = Fp.mul(Fp.mul(u, u), c1);
    const tv2 = Fp.add(1n, tv1);
    tv1 = Fp.sub(1n, tv1);
    const prod = Fp.mul(tv1, tv2);
    if (prod === 0n) throw new Error("tv1*tv2 == 0 (inv_t undefined)");
    const inv_t = Fp.inv(prod);
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

    let x = e1 === 1n ? x1 : x3;
    const e2sel = (e2 === 1n && e1 === 0n) ? 1n : 0n;
    x = e2sel === 1n ? x2 : x;

    const gx = g(x);
    if (!isSq(gx)) throw new Error("selected x not on curve (no sqrt)");
    const sqrt_x = Fp.sqrt(gx);
    let y = sqrt_x;
    if (sgn0(u) !== sgn0(y)) y = Fp.neg(y);

    return {
        point: Point.fromAffine({ x, y }),
        hints: { inv_t, e1, w1, e2, w2, sqrt_x },
    };
}

// A concrete non-canonical suite that selects the x3 branch for both u0,u1 and
// lands them on DISTINCT on-curve points (so the forged H2C' and thus M are
// genuinely different & nonzero, not the degenerate identity).
//   c3 = 0  => tv4 = 0 => x1 = x2 = c2; choose c2 with g(c2) NON-square => e1=e2=0
//   => selected x = x3 = t^2*c4 + Z; c4 = 3 lands both u0,u1 on the curve.
export function forgedSuite() {
    // c2 = 3: smallest value with g(c2)=c2^3-17 a non-residue (verified empirically).
    return { c1: 7n, c2: 3n, c3: 0n, c4: 3n };
}
