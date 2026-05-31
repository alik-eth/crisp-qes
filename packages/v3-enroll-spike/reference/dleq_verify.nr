// Reference circuit (measured 28,688 gates): in-circuit Chaum-Pedersen DLEQ
// verify + unblind + commitment over Grumpkin -- the oprf_nullifier core.
// Not part of the bin build (src/main.nr); preserved for the v3 build.
use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar, multi_scalar_mul};

fn neg(p: Pt) -> Pt {
    Pt { x: p.x, y: -p.y, is_infinite: p.is_infinite }
}

fn main(
    gx: pub Field, gy: pub Field,
    kpx: pub Field, kpy: pub Field,
    mx: pub Field, my: pub Field,
    yx: pub Field, yy: pub Field,
    c_lo: Field, c_hi: Field,
    z_lo: Field, z_hi: Field,
    rinv_lo: Field, rinv_hi: Field,
    r_lo: Field, r_hi: Field,
    c_expected: pub Field,
) -> pub Field {
    let g = Pt { x: gx, y: gy, is_infinite: false };
    let kpub = Pt { x: kpx, y: kpy, is_infinite: false };
    let m = Pt { x: mx, y: my, is_infinite: false };
    let y = Pt { x: yx, y: yy, is_infinite: false };
    let c = Scalar { lo: c_lo, hi: c_hi };
    let z = Scalar { lo: z_lo, hi: z_hi };

    let a1 = multi_scalar_mul([g, neg(kpub)], [z, c]);    // z*G - c*Kpub
    let a2 = multi_scalar_mul([m, neg(y)], [z, c]);       // z*M - c*Y

    let ch = std::hash::pedersen_hash([gx, gy, kpx, kpy, mx, my, yx, yy, a1.x, a1.y, a2.x, a2.y]);
    assert(ch == c_expected);

    let rinv = Scalar { lo: rinv_lo, hi: rinv_hi };
    let r = Scalar { lo: r_lo, hi: r_hi };
    let n = multi_scalar_mul([y], [rinv]);                // N = rinv*Y
    let ycheck = multi_scalar_mul([n], [r]);              // bind: r*N == Y
    assert((ycheck.x == y.x) & (ycheck.y == y.y));

    std::hash::pedersen_hash([n.x, n.y])                  // commitment = pedersen(N)
}
