// oprf_commitment circuit (v3 Grumpkin OPRF, build/unaudited).
// Proves M = r * H2C(input) where H2C = map(u0) + map(u1) (RFC-9380 SvdW).
// u0,u1 are the hash_to_field outputs (expand_message_xmd is the SHA term,
// proven separately / in the QES front-end). Outputs M so we can cross-check
// against the JS lib, then bb prove/verify.

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar, multi_scalar_mul};

global ZETA: Field = 5;
global BCURVE: Field = -17;
global SVDW_Z: Field = 1;

// Canonical RFC-9380 SvdW suite constants for Grumpkin (== lib.mjs SVDW_CONSTS).
// F3 SECURITY FIX: c1..c4 remain public inputs (ABI-preserving) but are now
// PINNED to these canonical values. Without this, a prover supplies a different
// valid (c1..c4 + matching hints) to redefine hash-to-curve, mapping one
// identity to arbitrarily many on-curve points => unbounded distinct
// commitments/nullifiers per identity.
global SVDW_C1: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495601;
global SVDW_C2: Field = 10944121435919637611123202872628637544274182200208017171849102093287904247808;
global SVDW_C3: Field = 17631683881184975371348829942606096167675058198229016842588;
global SVDW_C4: Field = 14592161914559516814830937163504850059032242933610689562465469457717205663766;

fn g(x: Field) -> Field { x * x * x + BCURVE }

fn assert_is_square(gx: Field, e: Field, w: Field) {
    assert(e * (e - 1) == 0);
    let lhs = w * w;
    assert(e * (lhs - gx) + (1 - e) * (lhs - gx * ZETA) == 0);
}
fn cmov(a: Field, b: Field, c: Field) -> Field { a + c * (b - a) }
fn sgn0(x: Field) -> Field { let bits: [u1; 254] = x.to_le_bits(); bits[0] as Field }

fn svdw_map(
    u: Field, c1: Field, c2: Field, c3: Field, c4: Field,
    inv_t: Field, e1: Field, w1: Field, e2: Field, w2: Field, sqrt_x: Field,
) -> Pt {
    let mut tv1 = u * u * c1;
    let tv2 = 1 + tv1;
    tv1 = 1 - tv1;
    assert(tv1 * tv2 * inv_t == 1);
    let tv4 = u * tv1 * inv_t * c3;
    let x1 = c2 - tv4;
    assert_is_square(g(x1), e1, w1);
    let x2 = c2 + tv4;
    assert_is_square(g(x2), e2, w2);
    let t = tv2 * tv2 * inv_t;
    let x3 = t * t * c4 + SVDW_Z;
    let mut x = cmov(x3, x1, e1);
    x = cmov(x, x2, e2 * (1 - e1));
    let gx = g(x);
    assert(sqrt_x * sqrt_x == gx);
    let y = sqrt_x;
    let eq = 1 - (sgn0(u) - sgn0(y)) * (sgn0(u) - sgn0(y));
    let y_final = cmov(-y, y, eq);
    Pt { x, y: y_final, is_infinite: false }
}

fn main(
    // hash_to_field outputs (private input identity material)
    u0: Field, u1: Field,
    // SvdW constants (suite params)
    c1: pub Field, c2: pub Field, c3: pub Field, c4: pub Field,
    // per-map hints
    h0: [Field; 6], h1: [Field; 6], // [inv_t, e1, w1, e2, w2, sqrt_x]
    // blinding scalar r (private)
    r_lo: Field, r_hi: Field,
    // public blinded commitment M = r*H2C(input)
    mx: pub Field, my: pub Field,
) {
    // F3 SECURITY FIX: pin the SvdW suite constants to the canonical values.
    assert(c1 == SVDW_C1);
    assert(c2 == SVDW_C2);
    assert(c3 == SVDW_C3);
    assert(c4 == SVDW_C4);
    let p0 = svdw_map(u0, c1, c2, c3, c4, h0[0], h0[1], h0[2], h0[3], h0[4], h0[5]);
    let p1 = svdw_map(u1, c1, c2, c3, c4, h1[0], h1[1], h1[2], h1[3], h1[4], h1[5]);
    // M = r*(P0+P1) = r*P0 + r*P1 via blackbox MSM (avoids explicit point add)
    let r = Scalar { lo: r_lo, hi: r_hi };
    let m = multi_scalar_mul([p0, p1], [r, r]);
    assert(m.x == mx);
    assert(m.y == my);
}
