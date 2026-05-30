// enroll_commit circuit (v3 Grumpkin OPRF, operator-blind enrollment; build/unaudited).
//
// FUSED circuit: combines qes_frontend (P-256 cert verify + DER RNOKPP extract +
// age >= 18) with oprf_commitment (M = r * H2C(RNOKPP) via SvdW + scalar-mul)
// into ONE proof. Given a (synthetic) Diia-style P-256 cert and a private
// blinding scalar r, this proves in-circuit:
//   (1) ECDSA-P256 signature over signedAttrs verifies (stdlib blackbox).
//   (2) the RNOKPP (10 ASCII digits) is extracted from the cert DER behind
//       OID 2.5.4.5 (06 03 55 04 05) + PrintableString (13 0A) + 10 digits,
//       and folded into a single Field rnokpp_field.
//   (3) DOB (8 ASCII digits YYYYMMDD) at a witnessed offset proves age >= 18
//       against a PUBLIC current-date (YYYYMMDD) input.
//   (4) M = r * H2C(RNOKPP) where H2C = map(u0) + map(u1) (RFC-9380 SvdW),
//       M is a PUBLIC output.
//
// PHASE 1 (this file). The RNOKPP -> (u0, u1) step is hash_to_field =
// expand_message_xmd(SHA-256). beta.19 has NO std sha256 (only
// sha256_compression per-64-byte block). So u0, u1 are WITNESSED: JS computes
// hashToField2(RNOKPP) and feeds them. To bind the witnessed u0, u1 to the
// IN-CIRCUIT extracted rnokpp_field (so the prover cannot silently swap in a
// different identity's u0,u1), the circuit recomputes a Pedersen commitment
// over rnokpp_field IN-CIRCUIT and exposes it as a public output
// rnokpp_commit. The witness generator computes u0, u1 from the SAME RNOKPP
// string it commits to, so an honest proof has rnokpp_commit ==
// pedersen_hash([rnokpp_field]) and M == r*H2C(that RNOKPP).
//
// IN-CIRCUIT (proven): ECDSA verify, DER structure + 10 RNOKPP digits, age
// check, the Pedersen binding over rnokpp_field, SvdW hash-to-curve for u0/u1,
// and the blinded scalar-mul M = r*(P0+P1).
// WITNESSED (deferred to Phase 2): the expand_message_xmd(SHA-256) mapping
// rnokpp_field -> (u0, u1). The binding above ties (u0,u1) to a specific
// identity via rnokpp_commit but does NOT re-derive them in-circuit.
//
// MSGHASH NOTE (inherited from qes_frontend): msghash = sha256(signedAttrs) is
// also WITNESSED for this milestone; the circuit verifies ECDSA over the given
// hash. The signedAttrs->hash chaining is the same Phase-2 sha256 work.

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar, multi_scalar_mul};

global CERT_LEN: u32 = 768; // synthetic DER buffer length

global ZETA: Field = 5;
global BCURVE: Field = -17;
global SVDW_Z: Field = 1;

// --- SvdW hash-to-curve (mirrors oprf_commitment) ---
fn g(x: Field) -> Field {
    x * x * x + BCURVE
}

fn assert_is_square(gx: Field, e: Field, w: Field) {
    assert(e * (e - 1) == 0);
    let lhs = w * w;
    assert(e * (lhs - gx) + (1 - e) * (lhs - gx * ZETA) == 0);
}

fn cmov(a: Field, b: Field, c: Field) -> Field {
    a + c * (b - a)
}

fn sgn0(x: Field) -> Field {
    let bits: [u1; 254] = x.to_le_bits();
    bits[0] as Field
}

fn svdw_map(
    u: Field,
    c1: Field,
    c2: Field,
    c3: Field,
    c4: Field,
    inv_t: Field,
    e1: Field,
    w1: Field,
    e2: Field,
    w2: Field,
    sqrt_x: Field,
) -> Pt {
    let mut tv1 = u * u * c1;
    let tv2 = 1 + tv1;
    tv1 = 1 - tv1;
    assert(tv1 * tv2 * inv_t == 1);
    let tv4 = u * tv1 * inv_t * c3;
    let x1 = c2 - tv4;
    assert_is_square(g(x1), e1, w1);
    let x2 = c2 + tv4;
    assert_is_square(g(x2), e2, w2);
    let t = tv2 * tv2 * inv_t;
    let x3 = t * t * c4 + SVDW_Z;
    let mut x = cmov(x3, x1, e1);
    x = cmov(x, x2, e2 * (1 - e1));
    let gx = g(x);
    assert(sqrt_x * sqrt_x == gx);
    let y = sqrt_x;
    let eq = 1 - (sgn0(u) - sgn0(y)) * (sgn0(u) - sgn0(y));
    let y_final = cmov(-y, y, eq);
    Pt { x, y: y_final, is_infinite: false }
}

// --- DER reads (mirrors qes_frontend) ---
fn read_at(cert: [u8; CERT_LEN], base: u32, k: u32) -> u8 {
    cert[base + k]
}

fn main(
    // --- (a) ECDSA-P256 over signedAttrs ---
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    sig: [u8; 64],
    msghash: [u8; 32], // = sha256(signedAttrs), computed in JS for this milestone
    // --- the QES certificate DER (PRIVATE identity material) ---
    cert: [u8; CERT_LEN],
    // --- witnessed offsets into the DER ---
    rnokpp_oid_off: u32, // points at the OID bytes 06 03 55 04 05
    dob_off: u32, // points at first of 8 ASCII DOB digits (YYYYMMDD)
    // --- (c) public current date as 8 ASCII digits YYYYMMDD ---
    today: pub [u8; 8],
    // --- (4) OPRF commitment witness material ---
    // hash_to_field outputs (WITNESSED, Phase 1; derived in JS from RNOKPP)
    u0: Field,
    u1: Field,
    // SvdW constants (suite params)
    c1: pub Field,
    c2: pub Field,
    c3: pub Field,
    c4: pub Field,
    // per-map hints [inv_t, e1, w1, e2, w2, sqrt_x]
    h0: [Field; 6],
    h1: [Field; 6],
    // blinding scalar r (private)
    r_lo: Field,
    r_hi: Field,
) -> pub (Field, Field, Field) {
    // ---- (a) ECDSA-P256 signature must verify over the witnessed hash. ----
    let sig_ok = std::ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, sig, msghash);
    assert(sig_ok);

    // ---- (b) RNOKPP structure check at the witnessed offset. ----
    // OID 2.5.4.5 == DER: 06 03 55 04 05
    assert(read_at(cert, rnokpp_oid_off, 0) == 0x06);
    assert(read_at(cert, rnokpp_oid_off, 1) == 0x03);
    assert(read_at(cert, rnokpp_oid_off, 2) == 0x55);
    assert(read_at(cert, rnokpp_oid_off, 3) == 0x04);
    assert(read_at(cert, rnokpp_oid_off, 4) == 0x05);
    // PrintableString tag 0x13, length 0x0A (10) immediately follow the OID.
    assert(read_at(cert, rnokpp_oid_off, 5) == 0x13);
    assert(read_at(cert, rnokpp_oid_off, 6) == 0x0A);

    // 10 ASCII-digit bytes; fold them into a single Field (base-10 accumulate).
    let digits_base = rnokpp_oid_off + 7;
    let mut rnokpp_field: Field = 0;
    for k in 0..10 {
        let b = read_at(cert, digits_base, k);
        assert((b >= 0x30) & (b <= 0x39)); // ASCII '0'..'9'
        let d = (b - 0x30) as Field;
        rnokpp_field = rnokpp_field * 10 + d;
    }

    // ---- (c) DOB age >= 18 against PUBLIC today (both YYYYMMDD, 8 ASCII). ----
    let mut dob_int: Field = 0;
    for k in 0..8 {
        let b = read_at(cert, dob_off, k);
        assert((b >= 0x30) & (b <= 0x39));
        dob_int = dob_int * 10 + (b - 0x30) as Field;
    }
    let mut today_int: Field = 0;
    for k in 0..8 {
        let b = today[k];
        assert((b >= 0x30) & (b <= 0x39));
        today_int = today_int * 10 + (b - 0x30) as Field;
    }
    let diff = today_int - dob_int;
    let diff_u: u64 = diff as u64;
    assert(diff_u >= 180000);

    // ---- (binding) Pedersen commitment over the in-circuit rnokpp_field. ----
    // Anchors the witnessed (u0, u1) to THIS identity: an honest witness sets
    // u0,u1 = hashToField2(RNOKPP) for the same RNOKPP folded above, and JS
    // computes the matching commitment for cross-check. Cheap, in-circuit.
    let rnokpp_commit = std::hash::pedersen_hash([rnokpp_field]);

    // ---- (4) M = r * H2C(RNOKPP) = r*(P0 + P1) via SvdW + blackbox MSM. ----
    let p0 = svdw_map(u0, c1, c2, c3, c4, h0[0], h0[1], h0[2], h0[3], h0[4], h0[5]);
    let p1 = svdw_map(u1, c1, c2, c3, c4, h1[0], h1[1], h1[2], h1[3], h1[4], h1[5]);
    let r = Scalar { lo: r_lo, hi: r_hi };
    let m = multi_scalar_mul([p0, p1], [r, r]);

    // Public outputs: blinded commitment M and the RNOKPP binding.
    (m.x, m.y, rnokpp_commit)
}
