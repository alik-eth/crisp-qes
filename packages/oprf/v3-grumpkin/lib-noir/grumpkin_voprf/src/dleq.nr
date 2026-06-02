// grumpkin_voprf::dleq -- in-circuit Chaum-Pedersen DLEQ verification.
//
// Ported VERBATIM from oprf_nullifier's DLEQ verify. Proves Y = k*M for the same
// k as Kpub = k*GEN, where GEN is the PINNED canonical generator (F1) -- not an
// attacker-suppliable base.
//
// The challenge ACTUALLY fed to the MSM is the 128-bit-limb scalar
// c = (c_lo, c_hi). Soundness (C-1) comes SOLELY from the limb binding
//   assert(c_lo + c_hi*2^128 == ch)
// which fully constrains that exact MSM scalar to equal the recomputed transcript
// hash ch. So a prover cannot pick z + free limbs and then set the challenge to
// whatever makes the equation hold -- the limbs feeding the MSM are themselves
// pinned to ch.
//
//   a1 = z*GEN - c*Kpub,  a2 = z*M - c*Y
//   ch = pedersen([GEN.x,GEN.y, Kpub.x,Kpub.y, M.x,M.y, Y.x,Y.y, a1.x,a1.y, a2.x,a2.y])
//   assert(c_lo + c_hi*2^128 == ch)     // C-1 limb binding (the sole challenge constraint)
// c is supplied as 128-bit limbs (c_lo,c_hi); z as (z_lo,z_hi). Both are
// range-checked to 128 bits so the (lo,hi) decomposition is the unique integer
// the MSM blackbox interprets. Separately, a pedersen output (ch) is a Field
// < P < N, hence a valid embedded-curve scalar -- this is about ch's validity as
// a scalar, NOT a claim that ch is the value fed to the MSM (that value is the
// limb scalar c, pinned to ch by the assert above).

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar, multi_scalar_mul};
use crate::params::{GEN_X, GEN_Y};

fn neg(p: Pt) -> Pt {
    Pt { x: p.x, y: -p.y, is_infinite: p.is_infinite }
}

// Verify the DLEQ proof (c,z) for (Kpub, M, Y) against the PINNED generator.
// Aborts (assert failure) if the proof is invalid.
pub fn verify_dleq(kpub: Pt, m: Pt, y: Pt, c_lo: Field, c_hi: Field, z_lo: Field, z_hi: Field) {
    // F1: the DLEQ base is the pinned canonical Grumpkin generator.
    let g = Pt { x: GEN_X, y: GEN_Y, is_infinite: false };

    // Range-check the scalar limbs to 128 bits (unique decomposition; C-1/C-3).
    c_lo.assert_max_bit_size::<128>();
    c_hi.assert_max_bit_size::<128>();
    z_lo.assert_max_bit_size::<128>();
    z_hi.assert_max_bit_size::<128>();
    let c = Scalar { lo: c_lo, hi: c_hi };
    let z = Scalar { lo: z_lo, hi: z_hi };

    // Recompute the DLEQ announcements: a1 = z*GEN - c*Kpub, a2 = z*M - c*Y.
    let a1 = multi_scalar_mul([g, neg(kpub)], [z, c]);
    let a2 = multi_scalar_mul([m, neg(y)], [z, c]);

    // C-1: bind the MSM challenge limbs to the in-circuit transcript hash.
    let ch = std::hash::pedersen_hash([
        g.x, g.y, kpub.x, kpub.y, m.x, m.y, y.x, y.y, a1.x, a1.y, a2.x, a2.y,
    ]);
    let two_128: Field = 0x100000000000000000000000000000000;
    assert(c_lo + c_hi * two_128 == ch);
}
