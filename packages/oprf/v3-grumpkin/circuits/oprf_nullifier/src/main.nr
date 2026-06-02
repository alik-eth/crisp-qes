// oprf_nullifier circuit (v3 Grumpkin OPRF, build/unaudited).
//
// THE /v3/register PROOF (two-proof deployed path). Given the OPRF node response
// Y and its Chaum-Pedersen DLEQ proof (c, z), this circuit composes the
// grumpkin_voprf library to:
//   (1) verify the DLEQ in-circuit (proves Y = k*M for the same k as Kpub=k*GEN)
//       against the lib's PINNED generator GEN -- F1 closed: there is NO
//       attacker-suppliable base G anymore (the old free gx,gy inputs are gone),
//       so the G-substitution forgery (pick k', set G'=(k')^-1*Kpub) is
//       impossible by construction;
//   (2) unblind N = rinv*Y, binding rinv to the ENROLL proof's blind r via the
//       cross-proof commitment c_r = commit_r(r) -- F2 closed: r is the SAME
//       scalar that formed M in enroll_commit_v2, so r*N==Y forces
//       rinv = r_enroll^-1 and N = k*H2C(id) (no Sybil leverage);
//   (3) derive nullifier commitment = pedersen(N).
//
// All of the OPRF math (DLEQ verify, unblind, F2/C-1/C-3 checks, is_infinite
// guards) lives in grumpkin_voprf::oprf::oprf_nullify_bound; this main() only
// wires the public/private inputs into points/scalars.
//
// PUBLIC-INPUT LAYOUT (8 words; service Task 5 + client Task 6 depend on it):
//   kpx[0] kpy[1] yx[2] yy[3] mx[4] my[5] c_r[6], then RETURN nullifier[7].
//
// REMOVED vs the old standalone ABI:
//   * the free DLEQ base G.x/G.y public inputs -- the F1 attack surface; GEN is
//     now the lib's pinned global, never an input.
//   * the redundant c_expected public input -- C-1 is enforced by the lib's
//     limb binding c_lo + c_hi*2^128 == pedersen(transcript), so no separate
//     public challenge value is needed.
//
// SERVICE CROSS-CHECKS (enforced off-circuit by proof-gate.mjs / server.mjs):
//   (a) m == the enroll proof's M  -- HARD identity binding (c_r binds r, NOT
//       identity; this check is non-skippable);
//   (b) kpub == this node's Kpub;
//   (c) nullifier == the submitted commitment;
//   (d) c_r == the enroll proof's C_r -- the cross-proof shared-r binding (F2).

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar};

fn main(
    // --- node Kpub (single k*GEN OR Lagrange-combined; threshold-ready) ---
    kpx: pub Field,
    kpy: pub Field,
    // --- node response Y = k*M ---
    yx: pub Field,
    yy: pub Field,
    // --- blinded element M (service hard-binds == enroll's M; identity binding) ---
    mx: pub Field,
    my: pub Field,
    // --- shared-r commitment (service binds == enroll's C_r) -> F2 ---
    c_r: pub Field,
    // --- blind scalar r (PRIVATE), bound to enroll via c_r ---
    r_lo: Field,
    r_hi: Field,
    // --- claimed r^-1 (mod n) (PRIVATE); forced exact by the group eq r*N==Y ---
    rinv_lo: Field,
    rinv_hi: Field,
    // --- DLEQ proof (c, z) as 128-bit limbs (PRIVATE) ---
    c_lo: Field,
    c_hi: Field,
    z_lo: Field,
    z_hi: Field,
) -> pub Field {
    let kpub = Pt { x: kpx, y: kpy, is_infinite: false };
    let y = Pt { x: yx, y: yy, is_infinite: false };
    let m = Pt { x: mx, y: my, is_infinite: false };
    let r = Scalar { lo: r_lo, hi: r_hi };
    let rinv = Scalar { lo: rinv_lo, hi: rinv_hi };
    grumpkin_voprf::oprf::oprf_nullify_bound(m, y, kpub, r, rinv, c_r, c_lo, c_hi, z_lo, z_hi)
}

// ===========================================================================
// REGISTER-PROOF TESTS.
//
// Honest vectors are the SAME pinned vectors as grumpkin_voprf/src/lib.nr's test
// module (RNOKPP "1234567890", deterministic test scalars r/k/t). The honest c_r
// is EXPECTED_CR = commit_r(test r) (same r as enroll, so the commitments match).
// main() is unreachable via `nargo execute` here (the deployed flow feeds it a
// real node Y + DLEQ), so the register path is validated at unit level.
// ===========================================================================

global KPX: Field = 21680878153996627047110511594586198142933615436402392951634841094838394348705;
global KPY: Field = 5768854927033753403597579346491882648290914816448378003742355327237200160587;
global YX: Field = 12476345395656711642620992735293567367458070599056337257466417650972388164663;
global YY: Field = 2972811910358636669511417461429708565479143375845348032697173680828780266467;
global MX: Field = 12740386612938090927079547681734239410028477805108087007172264989097450666954;
global MY: Field = 7157360252618170453902251378396272710129452917231230593436182484546167046936;
global C_LO: Field = 264488188236066331469174082695995530682;
global C_HI: Field = 8829401345798501564672955112299690931;
global Z_LO: Field = 193985113630717420977077115755925976670;
global Z_HI: Field = 42596797190570500466227565250490620432;
global R_LO: Field = 132187632223543972593629152660226846067;
global R_HI: Field = 0;
global RINV_LO: Field = 35339424528658019477618635888122168264;
global RINV_HI: Field = 46782793592175440837056950131961871837;
// rinv*2 mod n -- a valid invertible scalar that is NOT r^-1 (F2 forgery).
global RINV2_LO: Field = 209575820864155655038273278429923379785;
global RINV2_HI: Field = 29241822571167704632251842778697704284;
global EXPECTED_NULLIFIER: Field =
    0x06f310b1dbbcdbb45604e11517493552d7577117ced0985984078cf754fab227;
// EXPECTED_CR = commit_r(test r) = pedersen([CR_DOMAIN, R_LO, R_HI]) (lib Task 1).
global EXPECTED_CR: Field =
    0x2dc4e70bdf48c031a3cc6cd54a75361de20ced244c10b98c824ab6a5d659c2ac;

fn kpub() -> Pt {
    Pt { x: KPX, y: KPY, is_infinite: false }
}
fn y_pt() -> Pt {
    Pt { x: YX, y: YY, is_infinite: false }
}
fn m_pt() -> Pt {
    Pt { x: MX, y: MY, is_infinite: false }
}
fn r() -> Scalar {
    Scalar { lo: R_LO, hi: R_HI }
}
fn rinv() -> Scalar {
    Scalar { lo: RINV_LO, hi: RINV_HI }
}

// HONEST: with the shared-r commitment c_r == EXPECTED_CR (same r as enroll),
// the register proof yields the canonical nullifier == the recovery anchor.
#[test]
fn test_nullifier_honest() {
    let nullifier = grumpkin_voprf::oprf::oprf_nullify_bound(
        m_pt(), y_pt(), kpub(), r(), rinv(), EXPECTED_CR, C_LO, C_HI, Z_LO, Z_HI,
    );
    assert(nullifier == EXPECTED_NULLIFIER);
}

// F2 forgery: honest c_r/r but rinv = 2*r^-1 != r^-1. RINV2 limbs are < 2^128
// (range check passes) and c_r matches honest r, so the ONLY rejecter is the F2
// group equation r*N == Y. Pinned to that assert (non-vacuous).
#[test(should_fail_with = "F2: r*N != Y")]
fn test_nullifier_f2_wrong_rinv() {
    let bad_rinv = Scalar { lo: RINV2_LO, hi: RINV2_HI };
    let _ = grumpkin_voprf::oprf::oprf_nullify_bound(
        m_pt(), y_pt(), kpub(), r(), bad_rinv, EXPECTED_CR, C_LO, C_HI, Z_LO, Z_HI,
    );
}

// CROSS-PROOF binding: a c_r that does not match commit_r(r) (i.e. r != enroll's
// r) is rejected by the commit_r(r)==c_r assert inside the lib.
#[test(should_fail_with = "c_r mismatch (r != enroll r)")]
fn test_nullifier_wrong_cr() {
    let bad_cr = EXPECTED_CR + 1;
    let _ = grumpkin_voprf::oprf::oprf_nullify_bound(
        m_pt(), y_pt(), kpub(), r(), rinv(), bad_cr, C_LO, C_HI, Z_LO, Z_HI,
    );
}

// DLEQ-inconsistent: a wrong Y (use M as a stand-in) with honest c_r/r/rinv =>
// the recomputed transcript hash differs from the supplied challenge limbs =>
// the C-1 limb binding (inside verify_dleq) fails.
#[test(should_fail)]
fn test_nullifier_dleq_inconsistent() {
    let wrong_y = m_pt();
    let _ = grumpkin_voprf::oprf::oprf_nullify_bound(
        m_pt(), wrong_y, kpub(), r(), rinv(), EXPECTED_CR, C_LO, C_HI, Z_LO, Z_HI,
    );
}
