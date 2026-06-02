// oprf_nullifier circuit (v3 Grumpkin THRESHOLD OPRF, build/unaudited).
//
// THE /v3/register PROOF (threshold two-proof deployed path), compiled for a
// 2-of-3 threshold. It composes grumpkin_voprf::oprf::oprf_nullify_threshold,
// which self-attests that the OPRF output Y is a valid 2-of-3 evaluation:
//   (1) for each of the t=2 responders, verify a per-share epoch-bound
//       Chaum-Pedersen DLEQ B_i = k_i*M vs the PUBLISHED Kpub_i = k_i*GEN, against
//       the lib's PINNED generator GEN (F1), with the epoch in the transcript
//       (session binding, review #7) and the C-1 limb binding + C-3 range checks;
//   (2) bind idx -> Kpub IN-CIRCUIT: each responder's Kpub is selected from the
//       PUBLISHED 3-node set by its index (select_kpub_3), so a mislabeled
//       (Kpub, idx, B) triple cannot pass (no determinism/recovery hazard);
//   (3) Lagrange-combine Y = l1*B_a + l2*B_b IN-CIRCUIT with PINNED mod-N
//       coefficients selected by the responder set (no free Y input);
//   (4) unblind N = rinv*Y, binding rinv to the ENROLL proof's blind r via the
//       cross-proof commitment c_r = commit_r(r) -- F2: r is the SAME scalar that
//       formed M in enroll_commit_v2, so r*N==Y forces rinv = r_enroll^-1 and
//       N = k'*H2C(id) (k' = the threshold group key for this epoch);
//   (5) derive nullifier commitment = pedersen(N).
//
// k' is NEVER assembled at any party: each node only computes B_i = k_i*M on the
// blinded M, and Y is the in-circuit linear combination of the B_i (the F4
// mitigation, real under an honest-majority-of-keyholders, i.e. >= 2 of 3).
//
// All OPRF math lives in grumpkin_voprf::oprf::oprf_nullify_threshold; this main()
// only wires the public/private inputs into points/scalars.
//
// PUBLIC-INPUT LAYOUT (13 words; service + client depend on it):
//   mx[0] my[1] kp1x[2] kp1y[3] kp2x[4] kp2y[5] kp3x[6] kp3y[7]
//   idx1[8] idx2[9] epoch[10] c_r[11], then RETURN nullifier[12].
// PRIVATE witness: the two responder partials (b_a, b_b), the two per-share DLEQ
// limb sets (ca/za, cb/zb), and the blind scalar limbs (r, rinv). Y is NOT an
// input (computed in-circuit), and the free DLEQ base G is gone (pinned GEN, F1).
//
// SERVICE CROSS-CHECKS (enforced off-circuit by proof-gate.mjs / server.mjs):
//   (a) mx,my == the enroll proof's M  -- HARD identity binding (non-skippable);
//   (c) nullifier == the submitted commitment;
//   (d) c_r == the enroll proof's C_r -- the cross-proof shared-r binding (F2);
//   (e) the 3 published Kpub publics (kp1..kp3) == the canonical published set
//       (the in-circuit idx->Kpub selection then makes mislabeling impossible);
//   (f) epoch == the current enrollEpoch (the in-circuit binding rejects a stale
//       DLEQ; the service pins which epoch is live).

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar};

fn main(
    // --- blinded element M (service hard-binds == enroll's M; identity binding) ---
    mx: pub Field,
    my: pub Field,
    // --- the PUBLISHED 3-node key set (service: == canonical set) ---
    kp1x: pub Field,
    kp1y: pub Field,
    kp2x: pub Field,
    kp2y: pub Field,
    kp3x: pub Field,
    kp3y: pub Field,
    // --- the t=2 responder indices (distinct, canonical idx1 < idx2 in {1,2,3}) ---
    idx1: pub Field,
    idx2: pub Field,
    // --- session tag (service: == current enrollEpoch) ---
    epoch: pub Field,
    // --- shared-r commitment (service binds == enroll's C_r) -> F2 ---
    c_r: pub Field,
    // --- responder partials B_a = k_{idx1}*M, B_b = k_{idx2}*M (PRIVATE) ---
    bax: Field,
    bay: Field,
    bbx: Field,
    bby: Field,
    // --- per-share DLEQ for responder a (c,z) as 128-bit limbs (PRIVATE) ---
    ca_lo: Field,
    ca_hi: Field,
    za_lo: Field,
    za_hi: Field,
    // --- per-share DLEQ for responder b (c,z) as 128-bit limbs (PRIVATE) ---
    cb_lo: Field,
    cb_hi: Field,
    zb_lo: Field,
    zb_hi: Field,
    // --- blind scalar r (bound to enroll via c_r) and its inverse (PRIVATE) ---
    r_lo: Field,
    r_hi: Field,
    rinv_lo: Field,
    rinv_hi: Field,
) -> pub Field {
    let m = Pt { x: mx, y: my, is_infinite: false };
    let kpub1 = Pt { x: kp1x, y: kp1y, is_infinite: false };
    let kpub2 = Pt { x: kp2x, y: kp2y, is_infinite: false };
    let kpub3 = Pt { x: kp3x, y: kp3y, is_infinite: false };
    let b_a = Pt { x: bax, y: bay, is_infinite: false };
    let b_b = Pt { x: bbx, y: bby, is_infinite: false };
    let r = Scalar { lo: r_lo, hi: r_hi };
    let rinv = Scalar { lo: rinv_lo, hi: rinv_hi };
    grumpkin_voprf::oprf::oprf_nullify_threshold(
        m, kpub1, kpub2, kpub3, idx1, idx2, b_a, b_b, epoch,
        ca_lo, ca_hi, za_lo, za_hi, cb_lo, cb_hi, zb_lo, zb_hi, r, rinv, c_r,
    )
}

// ===========================================================================
// THRESHOLD REGISTER-PROOF TESTS.
//
// Honest vectors are the SAME pinned 2-of-3 vectors as grumpkin_voprf/src/lib.nr's
// threshold test module (RNOKPP "1234567890", same blind r and threshold-epoch
// key k'). main() is unreachable via `nargo execute` here (the deployed flow
// feeds it real node partials + DLEQs), so the path is validated at unit level.
// ===========================================================================

global MX: Field = 12740386612938090927079547681734239410028477805108087007172264989097450666954;
global MY: Field = 7157360252618170453902251378396272710129452917231230593436182484546167046936;

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

global R_LO: Field = 132187632223543972593629152660226846067;
global R_HI: Field = 0;
global RINV_LO: Field = 35339424528658019477618635888122168264;
global RINV_HI: Field = 46782793592175440837056950131961871837;
// rinv*2 mod n -- a valid invertible scalar that is NOT r^-1 (F2 forgery).
global RINV2_LO: Field = 209575820864155655038273278429923379785;
global RINV2_HI: Field = 29241822571167704632251842778697704284;

global THR_EPOCH: Field = 40910090656963856243247878701719173671483007054788362974932774194;
global EXPECTED_CR: Field =
    0x2dc4e70bdf48c031a3cc6cd54a75361de20ced244c10b98c824ab6a5d659c2ac;
global THR_NULLIFIER: Field =
    0x15f45ee3ae19caac1503058be2fd8108e26b93b2a943efd45ed9dfd0b7fbfc58;

fn m_pt() -> Pt {
    Pt { x: MX, y: MY, is_infinite: false }
}
fn kp1() -> Pt {
    Pt { x: KP1X, y: KP1Y, is_infinite: false }
}
fn b1() -> Pt {
    Pt { x: B1X, y: B1Y, is_infinite: false }
}
fn kp2() -> Pt {
    Pt { x: KP2X, y: KP2Y, is_infinite: false }
}
fn b2() -> Pt {
    Pt { x: B2X, y: B2Y, is_infinite: false }
}
fn kp3() -> Pt {
    Pt { x: KP3X, y: KP3Y, is_infinite: false }
}
fn b3() -> Pt {
    Pt { x: B3X, y: B3Y, is_infinite: false }
}
fn r() -> Scalar {
    Scalar { lo: R_LO, hi: R_HI }
}
fn rinv() -> Scalar {
    Scalar { lo: RINV_LO, hi: RINV_HI }
}

// HONEST: responders {1,2} + the full published 3-Kpub set yield the canonical
// threshold-epoch nullifier (the recovery anchor for this epoch).
#[test]
fn test_threshold_honest() {
    let nullifier = grumpkin_voprf::oprf::oprf_nullify_threshold(
        m_pt(), kp1(), kp2(), kp3(), 1, 2, b1(), b2(), THR_EPOCH,
        C1_LO, C1_HI, Z1_LO, Z1_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
        r(), rinv(), EXPECTED_CR,
    );
    assert(nullifier == THR_NULLIFIER);
}

// REJECT (mislabel hazard, closed in-circuit): b_a is node-3's partial (k_3*M)
// under idx1=1, so select_kpub_3(1) picks Kpub_1 and the per-share DLEQ checks
// (Kpub_1, M, k_3*M) -> B != k_1*M -> the C-1 limb binding fails.
#[test(should_fail)]
fn test_threshold_mislabeled_rejected() {
    let _ = grumpkin_voprf::oprf::oprf_nullify_threshold(
        m_pt(), kp1(), kp2(), kp3(), 1, 2, b3(), b2(), THR_EPOCH,
        C3_LO, C3_HI, Z3_LO, Z3_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
        r(), rinv(), EXPECTED_CR,
    );
}

// REJECT: wrong c_r -> the F2 cross-proof binding.
#[test(should_fail_with = "c_r mismatch (r != enroll r)")]
fn test_threshold_wrong_cr() {
    let _ = grumpkin_voprf::oprf::oprf_nullify_threshold(
        m_pt(), kp1(), kp2(), kp3(), 1, 2, b1(), b2(), THR_EPOCH,
        C1_LO, C1_HI, Z1_LO, Z1_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
        r(), rinv(), EXPECTED_CR + 1,
    );
}

// REJECT: wrong rinv (2*r^-1) -> the F2 group equation r*N == Y.
#[test(should_fail_with = "F2: r*N != Y")]
fn test_threshold_wrong_rinv() {
    let bad_rinv = Scalar { lo: RINV2_LO, hi: RINV2_HI };
    let _ = grumpkin_voprf::oprf::oprf_nullify_threshold(
        m_pt(), kp1(), kp2(), kp3(), 1, 2, b1(), b2(), THR_EPOCH,
        C1_LO, C1_HI, Z1_LO, Z1_HI, C2_LO, C2_HI, Z2_LO, Z2_HI,
        r(), bad_rinv, EXPECTED_CR,
    );
}

// REJECT: duplicate index (idx1 == idx2) -> the responder-set selector assert.
#[test(should_fail)]
fn test_threshold_dup_index() {
    let _ = grumpkin_voprf::oprf::oprf_nullify_threshold(
        m_pt(), kp1(), kp2(), kp3(), 1, 1, b1(), b1(), THR_EPOCH,
        C1_LO, C1_HI, Z1_LO, Z1_HI, C1_LO, C1_HI, Z1_LO, Z1_HI,
        r(), rinv(), EXPECTED_CR,
    );
}
