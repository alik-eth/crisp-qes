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
    assert((ycheck.x == y.x) & (ycheck.y == y.y), "F2: r*N != Y");

    let nullifier = std::hash::pedersen_hash([n.x, n.y]);
    (nullifier, m)
}

// ===========================================================================
// Two-proof variant (the DEPLOYED v3 path).
//
// We do NOT ship the fused single proof above for the deployed enrollment flow:
// the fused proof needs the node response Y (built AFTER /v3/blind-eval), so it
// cannot gate blind-eval, which would turn the OPRF into an OPEN oracle (anyone
// guessing a 10-digit RNOKPP could unblind k*H2C(id) and membership-test the
// registry => deanonymization). Instead the deployed path keeps TWO proofs:
//   (1) enroll proof  -- gates blind-eval; commits to its blind r as
//                        C_r = commit_r(r) and exposes it publicly.
//   (2) register proof -- takes C_r as a PUBLIC input and re-asserts
//                        commit_r(r) == C_r for ITS r, so Pedersen binding ties
//                        the two proofs to the SAME r.
// The fused oprf_verify_and_nullify stays for consumers without a gated-oracle
// stage (CRISP/Interfold).
// ===========================================================================

// Domain-separation tag for commit_r: ASCII "CRISP-QES-V3-Cr".
// MIRRORING REQUIREMENT: this tag must be reproduced BYTE-FOR-BYTE by every
// committer of C_r -- the JS lib.mjs commitR (Task 4) and the enroll_commit_v2
// circuit -- or the register proof's commit_r(r) will not match the enroll
// proof's published C_r and the cross-proof binding will (correctly) reject.
pub global CR_DOMAIN: Field = 0x43524953502d5145532d56332d4372;

// commit_r -- the cross-proof binding commitment over the blind scalar r.
// C_r = pedersen([CR_DOMAIN, r.lo, r.hi]). Pedersen is binding, so two proofs
// that both assert commit_r(r) == C_r for the SAME public C_r necessarily used
// the SAME r. The CR_DOMAIN prefix domain-separates C_r so it cannot collide
// with any other 2-element Pedersen commitment in the protocol (e.g. the
// enrollment leaf pedersen([N.x,N.y])). Range-checks the limbs so (lo,hi) is the
// unique integer (C-3) and the commitment is well-defined.
pub fn commit_r(r: Scalar) -> Field {
    r.lo.assert_max_bit_size::<128>();
    r.hi.assert_max_bit_size::<128>();
    std::hash::pedersen_hash([CR_DOMAIN, r.lo, r.hi])
}

// oprf_nullify_bound -- the two-proof REGISTER entry point.
//
// Unlike the fused entry point, `m` is a PUBLIC INPUT here (NOT recomputed from
// r*H2C): the register proof never sees H2C(id) (that lives in the separate
// enroll proof). In-circuit we bind THIS proof's r to the shared C_r and verify
// the node's DLEQ over the public (m, y, kpub).
//
// SERVICE FAILURE MODE (non-skippable cross-check): the service MUST hard-check
// m == the enroll proof's M (identity binding). c_r binds r but NOT the identity:
// if the m cross-check is omitted, a prover holding the honest r could submit
// m' = r*H2C(id') for an ARBITRARY identity id' and -- if it could obtain
// Y' = k*m' -- mint a nullifier for id'. In the deployed flow the gated
// blind-eval (only evaluates a cert-proven M) plus the in-circuit DLEQ already
// prevent obtaining Y', so this is defense-in-depth; but the m == M check is
// non-skippable. Likewise the service binds c_r == the enroll proof's C_r.
//
// Math (why this yields the canonical nullifier):
//   commit_r(r) == c_r  =>  r == r_enroll  (Pedersen binding; same r as enroll)
//   verify_dleq         =>  Y == k*M  (for Kpub's k; M = r_enroll*H2C(id))
//   n = rinv*Y, and r*n == Y with r == r_enroll  =>  rinv == r_enroll^-1
//   => N = r_enroll^-1 * Y = r_enroll^-1 * k * r_enroll * H2C(id) = k*H2C(id)
// the canonical, deterministic OPRF output -- no Sybil leverage (F2 closed).
//
// Threshold-compatible: `kpub` may be a single node key k*GEN OR the
// Lagrange-combined Kpub of a threshold set; verify_dleq is identical either way.
//
// Arguments:
//   m, y, kpub   PUBLIC blinded element M = r*H2C(id), node response Y = k*M,
//                and node/threshold public key Kpub.
//   r, rinv      PRIVATE blind scalar (bound to enroll via c_r) and its claimed
//                inverse (forced exact by the group equation r*N == Y).
//   c_r          PUBLIC cross-proof binding commitment from the enroll proof.
//   c_lo..z_hi   DLEQ proof (c, z) as 128-bit limbs.
// Returns the nullifier = pedersen([N.x, N.y]).
pub fn oprf_nullify_bound(
    m: Pt,
    y: Pt,
    kpub: Pt,
    r: Scalar,
    rinv: Scalar,
    c_r: Field,
    c_lo: Field,
    c_hi: Field,
    z_lo: Field,
    z_hi: Field,
) -> Field {
    // C-3: range-check the rinv limbs (commit_r below range-checks r's limbs).
    rinv.lo.assert_max_bit_size::<128>();
    rinv.hi.assert_max_bit_size::<128>();

    // F2 cross-proof binding: THIS proof's r must commit to the SAME C_r the
    // enroll proof published => r == r_enroll (Pedersen binding). Also range-
    // checks r's limbs.
    assert(commit_r(r) == c_r, "c_r mismatch (r != enroll r)");

    // Defense-in-depth: reject the point at infinity as an unblind input, before
    // verify_dleq (the F2 group equation below compares only affine coords).
    assert(!y.is_infinite, "y is the point at infinity");

    // F1 + C-1: verify the node's DLEQ against the pinned generator over (m, y).
    dleq::verify_dleq(kpub, m, y, c_lo, c_hi, z_lo, z_hi);

    // Unblind: N = rinv * Y.
    let n = multi_scalar_mul([y], [rinv]);
    assert(!n.is_infinite, "n is the point at infinity");

    // F2 binding: r * N == Y with r bound to enroll (via c_r) forces
    // rinv = r_enroll^-1 => N = k*H2C(id). Without this, rinv is free.
    let ycheck = multi_scalar_mul([n], [r]);
    assert((ycheck.x == y.x) & (ycheck.y == y.y), "F2: r*N != Y");

    std::hash::pedersen_hash([n.x, n.y])
}
