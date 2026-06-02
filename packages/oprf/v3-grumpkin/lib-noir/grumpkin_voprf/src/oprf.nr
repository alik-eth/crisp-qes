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

// ===========================================================================
// Threshold (t-of-n) variant -- the 2-of-3 register entry point.
//
// Replaces the single node's Y with an IN-CIRCUIT Lagrange combine of t=2
// verified partials B_i = k_i*M, so no single party ever holds/assembles the
// OPRF key k (the F4 mitigation). The nullifier self-attests the t-of-n eval:
// there is no free Y input -- Y is computed here from the per-share DLEQs +
// Lagrange weights.
//
// Lagrange coefficients lambda_i are SCALARS mod the Grumpkin group order N --
// NOT Noir's native field (which is the BN254 scalar field = Grumpkin BASE field,
// a DIFFERENT modulus). Computing lambda_i by native-field division would feed
// the MSM a value reduced mod the wrong modulus (e.g. native -1 = P-1, but the
// MSM scalar must be N-1, and P != N). So we PIN the canonical mod-N coefficient
// pairs for each 2-of-3 responder set as EmbeddedCurveScalar limb constants and
// select the matching pair in-circuit. (Computed off-circuit with lib.mjs Fn +
// scalarLimbs; the subset-invariance test cross-checks them.)
// ===========================================================================

// Pinned mod-N Lagrange coefficient limbs for the three 2-of-3 responder sets,
// in canonical (idx1 < idx2) order. lambda values:
//   {1,2}: (2, N-1)        {1,3}: (3*inv2, N-inv2)        {2,3}: (3, N-2)
// where inv2 = 2^-1 mod N. (lambda_LO/HI are the 128-bit limbs of lambda mod N.)
global LAMBDA_12_1_LO: Field = 2;
global LAMBDA_12_1_HI: Field = 0;
global LAMBDA_12_2_LO: Field = 201385395114098847380338600778089168198;
global LAMBDA_12_2_HI: Field = 64323764613183177041862057485226039389;
global LAMBDA_13_1_LO: Field = 270833881017518655421856604104928689829;
global LAMBDA_13_1_HI: Field = 32161882306591588520931028742613019694;
global LAMBDA_13_2_LO: Field = 270833881017518655421856604104928689827;
global LAMBDA_13_2_HI: Field = 32161882306591588520931028742613019694;
global LAMBDA_23_1_LO: Field = 3;
global LAMBDA_23_1_HI: Field = 0;
global LAMBDA_23_2_LO: Field = 201385395114098847380338600778089168197;
global LAMBDA_23_2_HI: Field = 64323764613183177041862057485226039389;

// select_lagrange_2of3 -- return the pinned mod-N Lagrange Scalar pair for the
// responder set {idx1, idx2}. Indices MUST be distinct and a canonical
// (idx1 < idx2) pair drawn from {1,2,3}: exactly one of {1,2},{1,3},{2,3}.
// A duplicate, out-of-range, or non-canonical (e.g. (2,1)) pair is rejected
// (combine() dedup + valid-responder check, review #7).
pub fn select_lagrange_2of3(idx1: Field, idx2: Field) -> (Scalar, Scalar) {
    let is12 = (idx1 == 1) & (idx2 == 2);
    let is13 = (idx1 == 1) & (idx2 == 3);
    let is23 = (idx1 == 2) & (idx2 == 3);
    // Exactly one canonical pair must match (also enforces idx1 != idx2 and the
    // {1,2,3} canonical-order domain).
    assert((is12 as Field) + (is13 as Field) + (is23 as Field) == 1, "invalid 2-of-3 responder set");

    // cmov-select the limbs for the matching pair (booleans are mutually exclusive).
    let s12 = is12 as Field;
    let s13 = is13 as Field;
    let s23 = is23 as Field;
    let l1_lo = s12 * LAMBDA_12_1_LO + s13 * LAMBDA_13_1_LO + s23 * LAMBDA_23_1_LO;
    let l1_hi = s12 * LAMBDA_12_1_HI + s13 * LAMBDA_13_1_HI + s23 * LAMBDA_23_1_HI;
    let l2_lo = s12 * LAMBDA_12_2_LO + s13 * LAMBDA_13_2_LO + s23 * LAMBDA_23_2_LO;
    let l2_hi = s12 * LAMBDA_12_2_HI + s13 * LAMBDA_13_2_HI + s23 * LAMBDA_23_2_HI;
    (Scalar { lo: l1_lo, hi: l1_hi }, Scalar { lo: l2_lo, hi: l2_hi })
}

// select_kpub_3 -- bind a responder index to its PUBLISHED Kpub by selecting
// from the full 3-node set {k1, k2, k3} for idx in {1,2,3} (in-circuit cmov).
// This closes the idx<->kpub decoupling: a responder's partial B is verified
// against published[idx], so a prover cannot mislabel (e.g. submit node 3's
// Kpub/B under idx=1) to land an off-canonical (still-deterministic) nullifier.
fn select_kpub_3(idx: Field, k1: Pt, k2: Pt, k3: Pt) -> Pt {
    let is1 = (idx == 1);
    let is2 = (idx == 2);
    let is3 = (idx == 3);
    assert((is1 as Field) + (is2 as Field) + (is3 as Field) == 1, "responder index not in {1,2,3}");
    let s1 = is1 as Field;
    let s2 = is2 as Field;
    let s3 = is3 as Field;
    Pt {
        x: s1 * k1.x + s2 * k2.x + s3 * k3.x,
        y: s1 * k1.y + s2 * k2.y + s3 * k3.y,
        is_infinite: false,
    }
}

// oprf_nullify_threshold -- the t-of-n (t=2) register entry point.
//
// Verifies t per-share epoch-bound DLEQs, asserts a valid distinct responder set,
// Lagrange-combines Y = l1*B_a + l2*B_b IN-CIRCUIT (pinned mod-N coefficients),
// then applies the F2 tail (C_r binding + r*N==Y + is_infinite guards) exactly
// like oprf_nullify_bound. For the SAME effective group key k (= f(0) of the
// sharing polynomial) the resulting nullifier == the single-key path's
// pedersen(k*H2C(id)) for that epoch -- and is identical across responder
// subsets (determinism/recovery preserved within the threshold epoch).
//
// idx -> kpub is BOUND IN-CIRCUIT: each responder's Kpub is selected from the
// FULL published 3-node set by its index (select_kpub_3), and its partial B is
// verified against that published[idx] via verify_dleq_share. So a mislabeled
// (kpub, idx, B) triple cannot pass -- a prover cannot mix node j's partial under
// index i. The SERVICE's only Kpub duty is to check the 3 published Kpub publics
// equal the canonical set BY VALUE.
//
// Arguments:
//   m                    PUBLIC blinded element M = r*H2C(id) (service: == enroll's M)
//   kpub1, kpub2, kpub3  the PUBLISHED 3-node key set (service: == canonical set)
//   idx1, idx2           PUBLIC responder indices (the t distinct responders, a<b)
//   b_a, b_b             PRIVATE partials B_a = k_{idx1}*M, B_b = k_{idx2}*M
//   epoch                PUBLIC session tag (service: == current enrollEpoch)
//   ca_*/cb_*            per-share DLEQ for responder a / b (c,z) limbs (PRIVATE)
//   r, rinv, c_r         blind scalar bound to enroll via c_r (F2), its inverse,
//                        the enroll proof's cross-proof commitment (PUBLIC c_r)
// Returns the nullifier = pedersen([N.x, N.y]).
pub fn oprf_nullify_threshold(
    m: Pt,
    kpub1: Pt,
    kpub2: Pt,
    kpub3: Pt,
    idx1: Field,
    idx2: Field,
    b_a: Pt,
    b_b: Pt,
    epoch: Field,
    ca_lo: Field,
    ca_hi: Field,
    za_lo: Field,
    za_hi: Field,
    cb_lo: Field,
    cb_hi: Field,
    zb_lo: Field,
    zb_hi: Field,
    r: Scalar,
    rinv: Scalar,
    c_r: Field,
) -> Field {
    // 1. Bind each responder index to its PUBLISHED Kpub (in-circuit), then
    //    verify the responder's partial against THAT key. A cheating/faulty node
    //    (B != k_idx*M) OR a mislabeled (kpub,idx,B) triple fails the DLEQ here.
    let kpub_a = select_kpub_3(idx1, kpub1, kpub2, kpub3);
    let kpub_b = select_kpub_3(idx2, kpub1, kpub2, kpub3);
    dleq::verify_dleq_share(kpub_a, m, b_a, epoch, ca_lo, ca_hi, za_lo, za_hi);
    dleq::verify_dleq_share(kpub_b, m, b_b, epoch, cb_lo, cb_hi, zb_lo, zb_hi);

    // 2. Lagrange combine IN-CIRCUIT with pinned mod-N coefficients (no free Y).
    //    select_lagrange_2of3 also enforces distinct, valid, canonical indices.
    let (l1, l2) = select_lagrange_2of3(idx1, idx2);
    let y = multi_scalar_mul([b_a, b_b], [l1, l2]);

    // 3. F2 tail (same as oprf_nullify_bound, with the in-circuit-combined Y).
    rinv.lo.assert_max_bit_size::<128>();
    rinv.hi.assert_max_bit_size::<128>();
    assert(commit_r(r) == c_r, "c_r mismatch (r != enroll r)");
    assert(!y.is_infinite, "y is the point at infinity");
    let n = multi_scalar_mul([y], [rinv]);
    assert(!n.is_infinite, "n is the point at infinity");
    let ycheck = multi_scalar_mul([n], [r]);
    assert((ycheck.x == y.x) & (ycheck.y == y.y), "F2: r*N != Y");
    std::hash::pedersen_hash([n.x, n.y])
}
