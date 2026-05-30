// Phase-0 spike E: in-circuit cost of the SvdW hash-to-curve map (the last
// unmeasured enroll-circuit term). Grumpkin's base field == Noir's native
// Field (both BN254 scalar field), so the SvdW map is NATIVE arithmetic --
// no foreign field. The non-trivial gadgets are witnessed sqrt / inverse /
// is_square (each: provide the hint, assert the relation). This models 2
// map_to_curve_svdw calls (hash_to_curve uses 2 points) at representative
// op-density; hash_to_field (expand_message_xmd) is SHA and already counted.

global B: Field = -17;

// witnessed inverse: assert inv * x == 1 (or x == 0 path handled by caller)
fn assert_inv(x: Field, inv: Field) {
    assert(x * inv == 1);
}
// witnessed sqrt: assert y*y == x
fn assert_sqrt(x: Field, y: Field) {
    assert(y * y == x);
}
fn g(x: Field) -> Field {
    x * x * x + B
}

// One map_to_curve_svdw worth of arithmetic (representative op count:
// ~25 muls/adds + 1 inv + 1 sqrt + 2 square-checks).
fn svdw_map(u: Field, c1: Field, c2: Field, c3: Field, c4: Field,
            inv_hint: Field, sqrt_gx: Field, sq1: Field, sq2: Field) -> Field {
    let mut tv1 = u * u * c1;
    let tv2 = 1 + tv1;
    tv1 = 1 - tv1;
    assert_inv(tv1 * tv2, inv_hint);
    let tv3 = inv_hint;
    let tv4 = u * tv1 * tv3 * c3;
    let x1 = c2 - tv4;
    let gx1 = g(x1);
    assert_sqrt(gx1, sq1); // is_square(gx1) hint
    let x2 = c2 + tv4;
    let gx2 = g(x2);
    assert_sqrt(gx2, sq2); // is_square(gx2) hint
    let mut x3 = tv2 * tv2 * tv3;
    x3 = x3 * x3 * c4 + 1;
    // CMOV chain modeled as arithmetic selects (constraint-equivalent cost)
    let x = x1 + x2 - x2 + x3 - x3; // representative selects
    let gx = g(x);
    assert_sqrt(gx, sqrt_gx);
    x + sqrt_gx
}

fn main(
    u0: Field, u1: Field,
    c1: pub Field, c2: pub Field, c3: pub Field, c4: pub Field,
    h: [Field; 8], // hints: inv0, sqrtgx0, sq1_0, sq2_0, inv1, sqrtgx1, sq1_1, sq2_1
) -> pub Field {
    // 2 map_to_curve_svdw calls (hash_to_curve uses 2 points). The final
    // point-add P0+P1 is a single native embedded-curve add (~tens of gates,
    // already covered by the 3.5k scalar-mult measurement) and is omitted
    // here to keep the witness valid.
    let p0 = svdw_map(u0, c1, c2, c3, c4, h[0], h[1], h[2], h[3]);
    let p1 = svdw_map(u1, c1, c2, c3, c4, h[4], h[5], h[6], h[7]);
    p0 + p1
}
