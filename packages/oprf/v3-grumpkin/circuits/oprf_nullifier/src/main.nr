// oprf_nullifier circuit (v3 Grumpkin OPRF, build/unaudited).
// Given the OPRF node response Y and its Chaum-Pedersen DLEQ proof (c, z):
//   (1) verify the DLEQ in-circuit (proves Y = k*M for the same k as Kpub=k*G),
//   (2) unblind N = rinv*Y (bound to r via the GROUP equation r*N == Y),
//   (3) derive nullifier commitment = pedersen(N).
//
// Adapted from packages/v3-enroll-spike/reference/dleq_verify.nr (28,688 gates).
// Uses std::embedded_curve_ops (Grumpkin == Noir native embedded curve),
// multi_scalar_mul, and point-negation for "-c" so we never do non-native
// scalar negation. The unblind avoids non-native mod-N arithmetic by binding
// rinv via the group equation r*(rinv*Y) == Y instead of checking r*rinv==1.
//
// Fiat-Shamir challenge transcript (field order MUST match the JS dleqProve):
//   pedersen_hash([gx,gy, kpx,kpy, mx,my, yx,yy, a1.x,a1.y, a2.x,a2.y])
// where a1 = z*G - c*Kpub and a2 = z*M - c*Y (recomputed in-circuit).
// c is supplied as 128-bit limbs (c_lo,c_hi) for the MSM scalar; c_expected is
// the same value as a single Field and is asserted == pedersen(transcript).
// A pedersen output is a Field < P < N, hence a valid embedded-curve scalar.

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

    // Recompute the DLEQ announcements: a1 = z*G - c*Kpub, a2 = z*M - c*Y.
    let a1 = multi_scalar_mul([g, neg(kpub)], [z, c]);
    let a2 = multi_scalar_mul([m, neg(y)], [z, c]);

    // Fiat-Shamir: challenge must equal the supplied c_expected (== the JS hash).
    let ch = std::hash::pedersen_hash([gx, gy, kpx, kpy, mx, my, yx, yy, a1.x, a1.y, a2.x, a2.y]);
    assert(ch == c_expected);

    // Unblind: N = rinv*Y, bound to r via the group equation r*N == Y.
    let rinv = Scalar { lo: rinv_lo, hi: rinv_hi };
    let r = Scalar { lo: r_lo, hi: r_hi };
    let n = multi_scalar_mul([y], [rinv]);
    let ycheck = multi_scalar_mul([n], [r]);
    assert((ycheck.x == y.x) & (ycheck.y == y.y));

    // Nullifier commitment.
    std::hash::pedersen_hash([n.x, n.y])
}
