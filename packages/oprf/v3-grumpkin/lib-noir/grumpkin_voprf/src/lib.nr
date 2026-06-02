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
    use crate::oprf::{select_lagrange_2of3, oprf_nullify_threshold};
    use crate::dleq::verify_dleq_share;

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

    // ===== threshold (2-of-3) variant =====
    // 3-share honest vector (degree-1 poly f(x)=k'+a*x; shares f(1),f(2),f(3))
    // over the SAME identity M = r*H2C("1234567890") and r as the single-key
    // tests, generated via lib.mjs. epoch is the session tag bound into each
    // per-share DLEQ. The combined Y = k'*M for ANY 2-subset, so the nullifier
    // is the SAME across responder subsets (the determinism property).
    global THR_EPOCH: Field = 40910090656963856243247878701719173671483007054788362974932774194;

    global KP1X: Field = 1300773079976865615374422193436422178757196213922244895988312348073491553096;
    global KP1Y: Field = 15863751897456978492324492985036923550873218614342423235844821733821446970511;
    global B1X: Field = 18464513144175189460020706322996166911019243795136153399436865451409848222982;
    global B1Y: Field = 20744006627659222864352970887986039392482726452176153524960146753711188602496;
    global C1_LO: Field = 4663667518715029932151845635974345243;
    global C1_HI: Field = 57410839322477302215911436133323531437;
    global Z1_LO: Field = 180421693623783396830395719829025102667;
    global Z1_HI: Field = 19388978379009812048912877033214604302;

    global KP2X: Field = 19489493224869241172851597111830873890925109881566144638029341587804238897584;
    global KP2Y: Field = 17345074639877754555214387893542892078133174957587265992146793274294716445592;
    global B2X: Field = 7872268825558125680991080043458275427058915319837565158130137745754842866286;
    global B2Y: Field = 19784478187670577844412053340302787412100973789722903230222777050211819902179;
    global C2_LO: Field = 338385840906444421518174896052385447927;
    global C2_HI: Field = 15301488582665266596685669347027346589;
    global Z2_LO: Field = 168861251188786448730990063194980898974;
    global Z2_HI: Field = 24695171529057576271641186325888896417;

    global KP3X: Field = 1829942668752649341918597284748339402438500396765082764114228051597956675409;
    global KP3Y: Field = 15894338081301998477041379188385682907426818171702689442128382427841723263000;
    global B3X: Field = 7035367941204660746296788055938469858011679795841579488891350393170643471231;
    global B3Y: Field = 8520999158688967813714497594244656185095355059965065914339966253782234491985;
    global C3_LO: Field = 216466597765188210863263130663053237231;
    global C3_HI: Field = 41155382934402573474760731085769893057;
    global Z3_LO: Field = 42528784054966123187488382424578868013;
    global Z3_HI: Field = 62605005698345674649121664499461838944;

    // nullifier = pedersen(rinv*Y) = pedersen(k'*H2C(id)) for the threshold epoch.
    global THR_NULLIFIER: Field =
        0x15f45ee3ae19caac1503058be2fd8108e26b93b2a943efd45ed9dfd0b7fbfc58;

    fn kp1() -> Pt { Pt { x: KP1X, y: KP1Y, is_infinite: false } }
    fn b1() -> Pt { Pt { x: B1X, y: B1Y, is_infinite: false } }
    fn kp2() -> Pt { Pt { x: KP2X, y: KP2Y, is_infinite: false } }
    fn b2() -> Pt { Pt { x: B2X, y: B2Y, is_infinite: false } }
    fn kp3() -> Pt { Pt { x: KP3X, y: KP3Y, is_infinite: false } }
    fn b3() -> Pt { Pt { x: B3X, y: B3Y, is_infinite: false } }

    // lagrange2(1,2) = (2, -1): l1 == 2 and l2 == field/scalar -1 (= N-1).
    // select_lagrange_2of3 returns the pinned mod-N Scalar limbs; check {1,2}.
    #[test]
    fn test_lagrange2_idx_1_2() {
        let (l1, l2) = select_lagrange_2of3(1, 2);
        // l1 == 2
        assert(l1.lo == 2);
        assert(l1.hi == 0);
        // l2 == N-1 (the pinned mod-N representation of -1)
        assert(l2.lo == 201385395114098847380338600778089168198);
        assert(l2.hi == 64323764613183177041862057485226039389);
    }

    // HONEST threshold register, responder set {1,2}: yields the threshold-epoch
    // nullifier (the recovery anchor for this epoch).
    #[test]
    fn test_nullify_threshold_honest() {
        let nullifier = oprf_nullify_threshold(
            m_pt(), kp1(), b1(), kp2(), b2(), 1, 2, THR_EPOCH,
            C1_LO, C1_HI, Z1_LO, Z1_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
            r(), rinv(), EXPECTED_CR,
        );
        assert(nullifier == THR_NULLIFIER);
    }

    // DETERMINISM / subset invariance (THE key correctness check for the pinned
    // constants): responder set {1,3} must yield the SAME nullifier as {1,2}.
    #[test]
    fn test_nullify_threshold_subset_invariance() {
        let nullifier = oprf_nullify_threshold(
            m_pt(), kp1(), b1(), kp3(), b3(), 1, 3, THR_EPOCH,
            C1_LO, C1_HI, Z1_LO, Z1_HI, C3_LO, C3_HI, Z3_LO, Z3_HI,
            r(), rinv(), EXPECTED_CR,
        );
        assert(nullifier == THR_NULLIFIER);
    }

    // Also confirm the third subset {2,3} reconstructs to the SAME leaf.
    #[test]
    fn test_nullify_threshold_subset_2_3() {
        let nullifier = oprf_nullify_threshold(
            m_pt(), kp2(), b2(), kp3(), b3(), 2, 3, THR_EPOCH,
            C2_LO, C2_HI, Z2_LO, Z2_HI, C3_LO, C3_HI, Z3_LO, Z3_HI,
            r(), rinv(), EXPECTED_CR,
        );
        assert(nullifier == THR_NULLIFIER);
    }

    // verify_dleq_share standalone: honest share-1 DLEQ accepts.
    #[test]
    fn test_verify_dleq_share_honest() {
        verify_dleq_share(kp1(), m_pt(), b1(), THR_EPOCH, C1_LO, C1_HI, Z1_LO, Z1_HI);
    }

    // REJECT: tampered B_1 -> the per-share DLEQ C-1 limb binding fails.
    #[test(should_fail)]
    fn test_threshold_tampered_b1_rejected() {
        let bad_b1 = Pt { x: B1X + 1, y: B1Y, is_infinite: false };
        let _ = oprf_nullify_threshold(
            m_pt(), kp1(), bad_b1, kp2(), b2(), 1, 2, THR_EPOCH,
            C1_LO, C1_HI, Z1_LO, Z1_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
            r(), rinv(), EXPECTED_CR,
        );
    }

    // REJECT: duplicate index (1,1) -> the responder-set selector assert.
    #[test(should_fail_with = "invalid 2-of-3 responder set")]
    fn test_threshold_dup_index_rejected() {
        let _ = oprf_nullify_threshold(
            m_pt(), kp1(), b1(), kp1(), b1(), 1, 1, THR_EPOCH,
            C1_LO, C1_HI, Z1_LO, Z1_HI, C1_LO, C1_HI, Z1_LO, Z1_HI,
            r(), rinv(), EXPECTED_CR,
        );
    }

    // REJECT: non-canonical / out-of-range index (2,1) -> selector assert.
    #[test(should_fail_with = "invalid 2-of-3 responder set")]
    fn test_threshold_noncanonical_index_rejected() {
        let _ = oprf_nullify_threshold(
            m_pt(), kp2(), b2(), kp1(), b1(), 2, 1, THR_EPOCH,
            C2_LO, C2_HI, Z2_LO, Z2_HI, C1_LO, C1_HI, Z1_LO, Z1_HI,
            r(), rinv(), EXPECTED_CR,
        );
    }

    // REJECT: wrong c_r -> the F2 cross-proof binding.
    #[test(should_fail_with = "c_r mismatch (r != enroll r)")]
    fn test_threshold_wrong_cr_rejected() {
        let _ = oprf_nullify_threshold(
            m_pt(), kp1(), b1(), kp2(), b2(), 1, 2, THR_EPOCH,
            C1_LO, C1_HI, Z1_LO, Z1_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
            r(), rinv(), EXPECTED_CR + 1,
        );
    }

    // REJECT: wrong rinv (2*r^-1) -> the F2 group equation r*N == Y.
    #[test(should_fail_with = "F2: r*N != Y")]
    fn test_threshold_wrong_rinv_rejected() {
        let bad_rinv = Scalar { lo: RINV2_LO, hi: RINV2_HI };
        let _ = oprf_nullify_threshold(
            m_pt(), kp1(), b1(), kp2(), b2(), 1, 2, THR_EPOCH,
            C1_LO, C1_HI, Z1_LO, Z1_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
            r(), bad_rinv, EXPECTED_CR,
        );
    }

    // REJECT: stale epoch (DLEQs built for THR_EPOCH, verified at THR_EPOCH+1)
    // -> the epoch-extended transcript hash differs -> C-1 limb binding fails.
    #[test(should_fail)]
    fn test_threshold_wrong_epoch_rejected() {
        let _ = oprf_nullify_threshold(
            m_pt(), kp1(), b1(), kp2(), b2(), 1, 2, THR_EPOCH + 1,
            C1_LO, C1_HI, Z1_LO, Z1_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
            r(), rinv(), EXPECTED_CR,
        );
    }
}
