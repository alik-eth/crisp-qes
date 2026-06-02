// grumpkin_voprf::oprf -- the single-`r` VOPRF entry point (F2 binding).
//
// This is the application-agnostic core. It takes the blinding scalar `r` EXACTLY
// ONCE and uses it for BOTH the blind (M = r*H2C(id)) and the unblind binding
// (the group equation r*N == Y). A caller therefore CANNOT supply two different
// blind/unblind scalars -- the same-`r` binding is a property of the signature.
//
// F2 fix (the bug this closes): in the standalone oprf_nullifier, `rinv` was a
// free witness tied only by r*N==Y with an UNRELATED r, so any invertible s gave
// N = s*Y => unbounded distinct nullifiers per identity (Sybil). Here `r` is the
// SAME witness that blinds H2C(id), so the group equation r*N==Y forces
// rinv = r^-1 (Y is prime-order), hence N = r^-1 * (k * r * H2C(id)) = k*H2C(id):
// the canonical, deterministic OPRF output. The binding is done via the group
// equation (NOT a non-native r*rinv == 1 mod n) -- matching the original design,
// which deliberately avoids non-native scalar-order arithmetic in the Noir field.
//
// Inherits: F1 (pinned GEN in verify_dleq), F3 (pinned SvdW in h2c), C-1
// (limb-bound challenge in verify_dleq), and C-3 (128-bit range-checked r/rinv
// limbs here).

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar, multi_scalar_mul};
use crate::dleq;

// Verify the node's DLEQ response and derive the OPRF nullifier, with the F2
// single-`r` blind<->unblind binding.
//
// Returns (nullifier, m) where:
//   nullifier = pedersen([N.x, N.y]),  N = k*H2C(id)  (deterministic per identity)
//   m         = r*H2C(id)              (the blinded element; app exposes it as M
//                                       for the node / its public output)
//
// CALLER RESPONSIBILITY: the library CANNOT enforce that the supplied `h2c`/`r`
// are the genuine enrollment ones for the claimed identity -- it only enforces
// the blind<->unblind single-`r` binding (rinv = r^-1) and the DLEQ. The caller
// MUST bind `m`/`h2c` to the committed identity upstream (e.g. derive h2c from an
// authenticated identity in-circuit and reuse the SAME `r` that formed the
// committed/signed M). Otherwise a prover could run the OPRF on an arbitrary h2c.
//
// Arguments:
//   h2c        H2C(identity) point (from h2c::h2c_grumpkin or the app's H2C)
//   r          blinding scalar (the SAME witness used to derive M upstream)
//   rinv       claimed r^-1 (mod n); the group equation forces it to be exact
//   kpub, y    node public key Kpub = k*GEN and response Y = k*M
//   c_lo..z_hi DLEQ proof (c,z) as 128-bit limbs
pub fn oprf_verify_and_nullify(
    h2c: Pt,
    r: Scalar,
    rinv: Scalar,
    kpub: Pt,
    y: Pt,
    c_lo: Field,
    c_hi: Field,
    z_lo: Field,
    z_hi: Field,
) -> (Field, Pt) {
    // C-3: range-check the r/rinv limbs so each (lo,hi) is the unique integer the
    // MSM blackbox interprets.
    r.lo.assert_max_bit_size::<128>();
    r.hi.assert_max_bit_size::<128>();
    rinv.lo.assert_max_bit_size::<128>();
    rinv.hi.assert_max_bit_size::<128>();

    // Defense-in-depth: make the degenerate-point exclusion EXPLICIT. The F2
    // group equation below compares only affine (x,y), not is_infinite, so a
    // degenerate y could in principle collapse the unblind to a single fixed
    // pedersen([0,0]). Reject the point at infinity as an unblind input here,
    // BEFORE verify_dleq, so this guard is what rejects a degenerate y (not an
    // incidental transcript mismatch) and the property is robust to future Noir
    // codegen changes in how multi_scalar_mul normalizes infinity.
    assert(!y.is_infinite, "y is the point at infinity");

    // Blind: M = r * H2C(id). The SAME r is reused for the unblind binding below.
    let m = multi_scalar_mul([h2c], [r]);

    // F1 + C-1: verify the node's DLEQ against the pinned generator.
    dleq::verify_dleq(kpub, m, y, c_lo, c_hi, z_lo, z_hi);

    // Unblind: N = rinv * Y.
    let n = multi_scalar_mul([y], [rinv]);
    // Defense-in-depth: N must not be the point at infinity either (explicit
    // degenerate-nullifier exclusion; the F2 group-eq compares only affine coords).
    assert(!n.is_infinite, "n is the point at infinity");

    // F2 binding: r * N == Y with the SAME r that blinded H2C(id). Forces
    // rinv = r^-1 (Y prime-order) => N = k*H2C(id). Without this (or with an
    // unrelated r), `rinv` is free and the nullifier is attacker-chosen.
    let ycheck = multi_scalar_mul([n], [r]);
    assert((ycheck.x == y.x) & (ycheck.y == y.y));

    let nullifier = std::hash::pedersen_hash([n.x, n.y]);
    (nullifier, m)
}
