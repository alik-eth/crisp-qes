// Phase-0 step 1b: FAITHFUL map_to_curve_svdw for Grumpkin, in-circuit
// (the oprf_commitment circuit's hash-to-curve core). Native field (Grumpkin
// base field == Noir field). Measures ONE map; hash_to_curve = 2 maps + a
// cheap point add + expand_message_xmd (SHA, counted in the SHA line).
//
// SOUND is_square is the subtle part: a prover must NOT be able to pick which
// candidate root is "the square one" (that would make H2C non-deterministic ->
// multiple commitments per RNOKPP -> Sybil break). We bind it: witness bit e
// and field w with  e? w^2==gx : w^2==gx*ZETA  (ZETA = least non-residue = 5),
// which forces e == is_square(gx). Plus sound CMOV selection and sgn0 via
// constrained bit-decomposition.

global ZETA: Field = 5;     // least quadratic non-residue mod Grumpkin base field
global BCURVE: Field = -17; // Grumpkin b
global SVDW_Z: Field = 1;   // found via find_z_svdw

fn g(x: Field) -> Field {
    x * x * x + BCURVE
}

// Binds e == is_square(gx): if e then w is sqrt(gx); else w is sqrt(gx*ZETA)
// (which exists iff gx is a non-residue, since ZETA is a non-residue).
fn assert_is_square(gx: Field, e: Field, w: Field) {
    assert(e * (e - 1) == 0);
    let lhs = w * w;
    assert(e * (lhs - gx) + (1 - e) * (lhs - gx * ZETA) == 0);
}

// c in {0,1}: returns c ? b : a
fn cmov(a: Field, b: Field, c: Field) -> Field {
    a + c * (b - a)
}

// sgn0 = least-significant bit of the canonical integer rep (constrained).
fn sgn0(x: Field) -> Field {
    let bits: [u1; 254] = x.to_le_bits();
    bits[0] as Field
}

fn map_to_curve_svdw(
    u: Field,
    c1: Field, c2: Field, c3: Field, c4: Field,
    inv_t: Field, e1: Field, w1: Field, e2: Field, w2: Field, sqrt_x: Field,
) -> (Field, Field) {
    let mut tv1 = u * u * c1;
    let tv2 = 1 + tv1;
    tv1 = 1 - tv1;
    assert(tv1 * tv2 * inv_t == 1); // inv_t = (tv1*tv2)^-1
    let tv3 = inv_t;
    let tv4 = u * tv1 * tv3 * c3;

    let x1 = c2 - tv4;
    let gx1 = g(x1);
    assert_is_square(gx1, e1, w1);

    let x2 = c2 + tv4;
    let gx2 = g(x2);
    assert_is_square(gx2, e2, w2);

    let t = tv2 * tv2 * tv3;
    let x3 = t * t * c4 + SVDW_Z;

    // x = e1 ? x1 : (e2 && !e1 ? x2 : x3)
    let mut x = cmov(x3, x1, e1);
    let e2_sel = e2 * (1 - e1);
    x = cmov(x, x2, e2_sel);

    let gx = g(x);
    assert(sqrt_x * sqrt_x == gx);
    let y = sqrt_x;

    // sgn0(u) == sgn0(y) ? y : -y
    let su = sgn0(u);
    let sy = sgn0(y);
    let d = su - sy;
    let eq = 1 - d * d; // 1 if equal, 0 if differ
    let y_final = cmov(-y, y, eq);

    (x, y_final)
}

fn main(
    u: Field,
    c1: pub Field, c2: pub Field, c3: pub Field, c4: pub Field,
    inv_t: Field, e1: Field, w1: Field, e2: Field, w2: Field, sqrt_x: Field,
) -> pub Field {
    let (x, y) = map_to_curve_svdw(u, c1, c2, c3, c4, inv_t, e1, w1, e2, w2, sqrt_x);
    x + y
}
