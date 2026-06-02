// grumpkin_voprf::h2c -- RFC-9380 SvdW hash-to-curve for Grumpkin.
//
// Ported VERBATIM from oprf_commitment's svdw_map (same hint-verification:
// assert_is_square, sqrt, cmov, sgn0), except the suite constants are now read
// from `params` globals (F3 pinning) instead of being passed in. The caller
// supplies only the identity field elements u0,u1 and the per-map hints
// h = [inv_t, e1, w1, e2, w2, sqrt_x].
//
// hash_to_field(expand_message_xmd) stays app-side: the app produces u0,u1 and
// the hints; this module proves the SvdW map onto the curve and sums the two
// points to H2C(id) = map(u0) + map(u1).

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, multi_scalar_mul, EmbeddedCurveScalar as Scalar};
use crate::params::{BCURVE, SVDW_C1, SVDW_C2, SVDW_C3, SVDW_C4, SVDW_Z, ZETA};

fn g(x: Field) -> Field {
    x * x * x + BCURVE
}

fn assert_is_square(gx: Field, e: Field, w: Field) {
    assert(e * (e - 1) == 0);
    let lhs = w * w;
    assert(e * (lhs - gx) + (1 - e) * (lhs - gx * ZETA) == 0);
}

fn cmov(a: Field, b: Field, c: Field) -> Field {
    a + c * (b - a)
}

fn sgn0(x: Field) -> Field {
    let bits: [u1; 254] = x.to_le_bits();
    bits[0] as Field
}

// map_to_curve_svdw(u) with PINNED suite constants (params). `h` carries the
// witness hints [inv_t, e1, w1, e2, w2, sqrt_x] the gadget verifies.
fn svdw_map(u: Field, h: [Field; 6]) -> Pt {
    let inv_t = h[0];
    let e1 = h[1];
    let w1 = h[2];
    let e2 = h[3];
    let w2 = h[4];
    let sqrt_x = h[5];

    let mut tv1 = u * u * SVDW_C1;
    let tv2 = 1 + tv1;
    tv1 = 1 - tv1;
    assert(tv1 * tv2 * inv_t == 1);
    let tv4 = u * tv1 * inv_t * SVDW_C3;
    let x1 = SVDW_C2 - tv4;
    assert_is_square(g(x1), e1, w1);
    let x2 = SVDW_C2 + tv4;
    assert_is_square(g(x2), e2, w2);
    let t = tv2 * tv2 * inv_t;
    let x3 = t * t * SVDW_C4 + SVDW_Z;
    let mut x = cmov(x3, x1, e1);
    x = cmov(x, x2, e2 * (1 - e1));
    let gx = g(x);
    assert(sqrt_x * sqrt_x == gx);
    let y = sqrt_x;
    let eq = 1 - (sgn0(u) - sgn0(y)) * (sgn0(u) - sgn0(y));
    let y_final = cmov(-y, y, eq);
    Pt { x, y: y_final, is_infinite: false }
}

// H2C(id) = map(u0) + map(u1). Returns the curve point; the app blinds it.
// The point add is done via a blackbox MSM with scalar 1 (avoids an explicit
// point-add gadget, matching the original oprf_commitment which folded the add
// into multi_scalar_mul).
pub fn h2c_grumpkin(u0: Field, u1: Field, h0: [Field; 6], h1: [Field; 6]) -> Pt {
    let p0 = svdw_map(u0, h0);
    let p1 = svdw_map(u1, h1);
    let one = Scalar { lo: 1, hi: 0 };
    multi_scalar_mul([p0, p1], [one, one])
}
