// grumpkin_voprf -- reusable Grumpkin VOPRF Noir library (build/unaudited).
//
// Packages the v3 Grumpkin VOPRF so every consumer (CRISP enrollment, Interfold,
// ...) inherits the same hardened primitives with no way to opt out:
//   F1  pinned DLEQ generator        (params::GEN_X/GEN_Y, dleq)
//   F3  pinned RFC-9380 SvdW suite    (params::SVDW_C1..C4, h2c)
//   C-1 limb-bound Fiat-Shamir         (dleq)
//   F2  single-`r` blind<->unblind     (oprf::oprf_verify_and_nullify)
//   C-3 range-checked scalar limbs      (dleq, oprf)
//
// Entry points:
//   * Fused (single proof): oprf::oprf_verify_and_nullify(h2c, r, rinv, kpub, y,
//     dleq...) -- for consumers WITHOUT a gated-oracle stage (CRISP/Interfold).
//   * Two-proof (DEPLOYED v3): oprf::commit_r(r) in the ENROLL proof (publishes
//     C_r) + oprf::oprf_nullify_bound(m, y, kpub, r, rinv, c_r, dleq...) in the
//     REGISTER proof -- the two-proof shared-`r` binding. Used because the
//     deployed enroll proof must GATE blind-eval (keeping the OPRF a closed
//     oracle), which the fused proof cannot do.

pub mod params;
pub mod h2c;
pub mod dleq;
pub mod oprf;

// ===========================================================================
// Unit tests (the TDD core of the F2 fix). Honest vectors are generated from
// lib.mjs (gen-nullifier-witness flow: RNOKPP "1234567890", deterministic test
// scalars r/k/t) and hardcoded here. The expected nullifier
// 0x06f310b1dbbcdbb45604e11517493552d7577117ced0985984078cf754fab227 matches the
// audited standalone oprf_nullifier output for the same identity (regression).
// ===========================================================================
mod tests {
    use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar};
    use crate::h2c::h2c_grumpkin;
    use crate::dleq::verify_dleq;
    use crate::oprf::oprf_verify_and_nullify;
    use crate::oprf::{commit_r, oprf_nullify_bound};

    // ---- honest vectors (from lib.mjs, RNOKPP "1234567890") ----
    global U0: Field = 5600281009168003126016872261719506870450933036194097358717167907313473038919;
    global U1: Field = 4178060642807948022213458403913812830759150891595299840591361559216108877686;
    global H0: [Field; 6] = [
        3502187239350298074426797392697268140910155110563023374154277681408828951967,
        0,
        6538104241053687948117038613344214156245774722392658032865076824465823914421,
        1,
        21074868467531733279055525030244639744255650171394108809251482097292547778710,
        21074868467531733279055525030244639744255650171394108809251482097292547778710,
    ];
    global H1: [Field; 6] = [
        13952733417910081095236915071869166746590225851240974238426567512947024460131,
        1,
        5484262196703451433300045926697966699254169342921434423093178362243843012552,
        1,
        11555461321848564535481899765865468450189896547703463923274924881012285701717,
        5484262196703451433300045926697966699254169342921434423093178362243843012552,
    ];
    global HX: Field = 13747040007719704587958750323172344571410258964879304218815782328582055142419;
    global HY: Field = 3133480305695854986508965991291826257120757369676082608748316892506274801180;
    global KPX: Field = 21680878153996627047110511594586198142933615436402392951634841094838394348705;
    global KPY: Field = 5768854927033753403597579346491882648290914816448378003742355327237200160587;
    global YX: Field = 12476345395656711642620992735293567367458070599056337257466417650972388164663;
    global YY: Field = 2972811910358636669511417461429708565479143375845348032697173680828780266467;
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

    // M = r*H2C(id) coords (the SAME M asserted in test_honest_accept); the
    // two-proof register entry point takes M as a PUBLIC input.
    global MX: Field = 12740386612938090927079547681734239410028477805108087007172264989097450666954;
    global MY: Field = 7157360252618170453902251378396272710129452917231230593436182484546167046936;

    // C_r = commit_r(r()) = pedersen([CR_DOMAIN, R_LO, R_HI]). Pinned (captured
    // on first compile from the test_commit_r_deterministic failure, hardcoded).
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

    // h2c_grumpkin reproduces the canonical H2C(id) from u0,u1 + hints.
    #[test]
    fn test_h2c_matches_lib() {
        let h = h2c_grumpkin(U0, U1, H0, H1);
        assert(h.x == HX);
        assert(h.y == HY);
    }

    // HONEST: full verify+nullify succeeds and returns the expected nullifier
    // (== the audited standalone oprf_nullifier output) and M.
    #[test]
    fn test_honest_accept() {
        let h = h2c_grumpkin(U0, U1, H0, H1);
        let (nullifier, m) = oprf_verify_and_nullify(
            h, r(), rinv(), kpub(), y_pt(), C_LO, C_HI, Z_LO, Z_HI,
        );
        assert(nullifier == EXPECTED_NULLIFIER);
        // M = r*H2C(id) -- cross-check against lib.mjs M.
        assert(m.x == 12740386612938090927079547681734239410028477805108087007172264989097450666954);
        assert(m.y == 7157360252618170453902251378396272710129452917231230593436182484546167046936);
    }

    // F2 FORGERY (the bug F2 closes): same honest inputs but rinv = 2*r^-1 != r^-1.
    // The standalone oprf_nullifier ACCEPTS this (free rinv); here the single-`r`
    // group equation r*N == Y must FAIL. Pinned to the F2 assert (non-vacuous):
    // RINV2 limbs are < 2^128 so the range checks pass, leaving r*N==Y the sole
    // rejecter.
    #[test(should_fail_with = "F2: r*N != Y")]
    fn test_f2_wrong_rinv_rejected() {
        let h = h2c_grumpkin(U0, U1, H0, H1);
        let bad_rinv = Scalar { lo: RINV2_LO, hi: RINV2_HI };
        let _ = oprf_verify_and_nullify(
            h, r(), bad_rinv, kpub(), y_pt(), C_LO, C_HI, Z_LO, Z_HI,
        );
    }

    // C-1 FORGERY: free-z / unbound challenge. Tamper the z limbs so the
    // recomputed announcements (and thus pedersen(transcript)) no longer match
    // the supplied challenge limbs => the C-1 limb binding fails.
    #[test(should_fail)]
    fn test_c1_free_z_rejected() {
        verify_dleq(kpub(), Pt { x: HX, y: HY, is_infinite: false }, y_pt(), C_LO, C_HI, Z_LO + 1, Z_HI);
    }

    // DLEQ-INCONSISTENT: a Y that is not k*M for Kpub's k. We feed an honest DLEQ
    // (c,z) but a Y point that does not satisfy it (use H2C as a stand-in wrong
    // Y). a2 = z*M - c*Y then differs => transcript hash differs => C-1 fails.
    #[test(should_fail)]
    fn test_dleq_inconsistent_y_rejected() {
        let wrong_y = Pt { x: HX, y: HY, is_infinite: false };
        let h = h2c_grumpkin(U0, U1, H0, H1);
        let m = std::embedded_curve_ops::multi_scalar_mul([h], [r()]);
        verify_dleq(kpub(), m, wrong_y, C_LO, C_HI, Z_LO, Z_HI);
    }

    // DEGENERATE-Y guard (defense-in-depth): the point at infinity must be
    // rejected as an unblind input BEFORE anything else runs. Non-vacuous: the
    // y-guard `assert(!y.is_infinite)` is the FIRST assert in
    // oprf_verify_and_nullify (placed ahead of verify_dleq precisely so a
    // degenerate y trips this guard, not an incidental DLEQ/transcript mismatch).
    // The pinned `should_fail_with` message confirms it is THIS assert that fires.
    #[test(should_fail_with = "y is the point at infinity")]
    fn test_degenerate_y_infinity_rejected() {
        let inf = Pt { x: 0, y: 0, is_infinite: true };
        // rinv chosen so that, WITHOUT the guard, the affine group-eq
        // (ycheck.x==y.x)&(ycheck.y==y.y) would compare (0,0)==(0,0) and pass;
        // the ONLY rejecter is the explicit is_infinite guard.
        let _ = oprf_verify_and_nullify(
            h2c_grumpkin(U0, U1, H0, H1), r(), rinv(), kpub(), inf, C_LO, C_HI, Z_LO, Z_HI,
        );
    }

    // ===== two-proof variant (commit_r + oprf_nullify_bound) =====

    // commit_r is deterministic and matches the pinned EXPECTED_CR.
    #[test]
    fn test_commit_r_deterministic() {
        assert(commit_r(r()) == commit_r(r()));
        assert(commit_r(r()) == EXPECTED_CR);
    }

    // HONEST two-proof register: with the shared-r commitment c_r = commit_r(r),
    // oprf_nullify_bound yields the SAME nullifier as the fused path => the
    // deployed two-proof path preserves the deterministic nullifier (recovery
    // intact, no on-chain migration).
    #[test]
    fn test_nullify_bound_honest() {
        let cr = commit_r(r());
        let nullifier = oprf_nullify_bound(
            m_pt(), y_pt(), kpub(), r(), rinv(), cr, C_LO, C_HI, Z_LO, Z_HI,
        );
        assert(nullifier == EXPECTED_NULLIFIER);
    }

    // CROSS-PROOF binding: a register proof whose c_r does not match commit_r(r)
    // (i.e. r != enroll's r) is rejected by the commit_r(r)==c_r assert.
    #[test(should_fail_with = "c_r mismatch (r != enroll r)")]
    fn test_nullify_bound_wrong_cr() {
        let bad_cr = commit_r(r()) + 1;
        let _ = oprf_nullify_bound(
            m_pt(), y_pt(), kpub(), r(), rinv(), bad_cr, C_LO, C_HI, Z_LO, Z_HI,
        );
    }

    // F2 forgery in the two-proof path: honest c_r + r (so commit_r passes), but
    // rinv = 2*r^-1 != r^-1. RINV2 limbs are < 2^128 (range check passes) and c_r
    // matches honest r, so the ONLY rejecter is the F2 group equation r*N == Y.
    // should_fail_with pins it to that assert (non-vacuous).
    #[test(should_fail_with = "F2: r*N != Y")]
    fn test_nullify_bound_f2_wrong_rinv() {
        let cr = commit_r(r());
        let bad_rinv = Scalar { lo: RINV2_LO, hi: RINV2_HI };
        let _ = oprf_nullify_bound(
            m_pt(), y_pt(), kpub(), r(), bad_rinv, cr, C_LO, C_HI, Z_LO, Z_HI,
        );
    }

    // DLEQ-inconsistent: honest c_r/r/rinv but a wrong y (not k*M) => the DLEQ
    // transcript hash differs from the supplied challenge limbs => C-1 fails.
    #[test(should_fail)]
    fn test_nullify_bound_dleq_inconsistent() {
        let cr = commit_r(r());
        let wrong_y = Pt { x: HX, y: HY, is_infinite: false };
        let _ = oprf_nullify_bound(
            m_pt(), wrong_y, kpub(), r(), rinv(), cr, C_LO, C_HI, Z_LO, Z_HI,
        );
    }
}
