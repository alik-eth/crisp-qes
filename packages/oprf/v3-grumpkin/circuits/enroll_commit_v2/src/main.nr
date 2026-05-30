// enroll_commit_v2 circuit (v3 Grumpkin OPRF, operator-blind enrollment; build/unaudited).
//
// PHASE 2: the FUSED enroll_commit circuit with hash_to_field done FULLY
// IN-CIRCUIT. Replaces the Phase-1 witnessed (u0, u1) + Pedersen binding with
// an in-circuit expand_message_xmd(SHA-256) over the cert-extracted RNOKPP.
//
// PROVES in ONE proof, over a (synthetic) Diia-style P-256 cert held privately:
//   (1) ECDSA-P256 signature over signedAttrs verifies (stdlib blackbox).
//   (2) RNOKPP (10 ASCII digits) extracted from cert DER behind OID 2.5.4.5
//       (06 03 55 04 05) + PrintableString (13 0A) + 10 digits.
//   (3) DOB (8 ASCII digits YYYYMMDD) proves age >= 18 vs PUBLIC today.
//   (4) u0, u1 = hash_to_field(RNOKPP) via expand_message_xmd(SHA-256),
//       computed IN-CIRCUIT (full SHA-256 incl. padding + message schedule via
//       the noir-lang/sha256 lib, which chains the sha256_compression blackbox).
//   (5) M = r * H2C(RNOKPP) where H2C = map(u0) + map(u1) (RFC-9380 SvdW),
//       M is the PUBLIC output.
//
// IN-CIRCUIT (proven): ECDSA verify, DER + 10 RNOKPP digits, age check, the
// THREE expand_message_xmd SHA-256 hashes (b1,b2,b3) over the RNOKPP, the
// 48-byte-BE -> field reduction giving u0,u1, SvdW hash-to-curve, blinded MSM.
// WITNESSED: only msghash = sha256(signedAttrs) (the ECDSA message digest) and
// the SvdW square-root hints. The RNOKPP -> (u0,u1) path is NO LONGER
// witnessed -- it is fully derived in-circuit here.
//
// PADDING / BLOCK HANDLING. RFC 9380 expand_message_xmd, DST =
// "CRISP-QES-V3-Grumpkin_XMD:SHA-256_SVDW_RO_" (42 bytes), len(DST)=0x2a so
// DST_prime = DST || 0x2a (43 bytes). L = 48, len_in_bytes = 96, ell = 3.
//   Z_pad = 64 zero bytes (one SHA-256 block).
//   b0 = SHA256( Z_pad[64] || msg[10] || I2OSP(96,2)=00 60 || I2OSP(0,1)=00
//                || DST_prime[43] )            -> 120-byte input
//   b1 = SHA256( b0[32] || 01 || DST_prime[43] )          -> 76-byte input
//   b2 = SHA256( (b0 XOR b1)[32] || 02 || DST_prime[43] )  -> 76-byte input
//   b3 = SHA256( (b0 XOR b2)[32] || 03 || DST_prime[43] )  -> 76-byte input
// uniform_bytes = b1 || b2 || b3 (96 bytes). u0 = bytes[0..48],
// u1 = bytes[48..96]. SHA-256 padding (0x80, zero pad, 64-bit big-endian bit
// length) and the 16->64 message-schedule expansion are handled inside
// sha256::digest, which calls std::hash::sha256_compression per 64-byte block.

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar, multi_scalar_mul};

global CERT_LEN: u32 = 768;

global ZETA: Field = 5;
global BCURVE: Field = -17;
global SVDW_Z: Field = 1;

// DST = "CRISP-QES-V3-Grumpkin_XMD:SHA-256_SVDW_RO_" (42 bytes).
global DST_LEN: u32 = 42;
global DST: [u8; 42] = [
    67, 82, 73, 83, 80, 45, 81, 69, 83, 45, 86, 51, 45, 71, 114, 117, 109, 112, 107, 105, 110, 95,
    88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 86, 68, 87, 95, 82, 79, 95,
];

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

fn read_at(cert: [u8; CERT_LEN], base: u32, k: u32) -> u8 {
    cert[base + k]
}

// Reduce a big-endian byte array to a Field (== bytesToNumberBE(bytes) mod P).
// Horner accumulation in the field auto-reduces mod the BN254 base field P,
// matching lib.mjs's Fp.create(bytesToNumberBE(...)).
fn be_bytes_to_field<let M: u32>(bytes: [u8; M]) -> Field {
    let mut acc: Field = 0;
    for i in 0..M {
        acc = acc * 256 + bytes[i] as Field;
    }
    acc
}

fn main(
    // --- (a) ECDSA-P256 over signedAttrs ---
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    sig: [u8; 64],
    msghash: [u8; 32], // = sha256(signedAttrs), witnessed (Phase-2 of the cert side is out of scope)
    // --- the QES certificate DER (PRIVATE) ---
    cert: [u8; CERT_LEN],
    rnokpp_oid_off: u32,
    dob_off: u32,
    // --- public current date YYYYMMDD ---
    today: pub [u8; 8],
    // --- SvdW suite constants ---
    c1: pub Field,
    c2: pub Field,
    c3: pub Field,
    c4: pub Field,
    // --- per-map SvdW hints [inv_t, e1, w1, e2, w2, sqrt_x] ---
    h0: [Field; 6],
    h1: [Field; 6],
    // --- blinding scalar r (private) ---
    r_lo: Field,
    r_hi: Field,
) -> pub (Field, Field) {
    // ---- (a) ECDSA-P256 verify over the witnessed message hash. ----
    let sig_ok = std::ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, sig, msghash);
    assert(sig_ok);

    // ---- (b) RNOKPP DER structure + 10 digit bytes. ----
    assert(read_at(cert, rnokpp_oid_off, 0) == 0x06);
    assert(read_at(cert, rnokpp_oid_off, 1) == 0x03);
    assert(read_at(cert, rnokpp_oid_off, 2) == 0x55);
    assert(read_at(cert, rnokpp_oid_off, 3) == 0x04);
    assert(read_at(cert, rnokpp_oid_off, 4) == 0x05);
    assert(read_at(cert, rnokpp_oid_off, 5) == 0x13);
    assert(read_at(cert, rnokpp_oid_off, 6) == 0x0A);

    let digits_base = rnokpp_oid_off + 7;
    let mut rnokpp_bytes: [u8; 10] = [0; 10];
    for k in 0..10 {
        let b = read_at(cert, digits_base, k);
        assert((b >= 0x30) & (b <= 0x39));
        rnokpp_bytes[k] = b;
    }

    // ---- (c) age >= 18. ----
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
    let diff_u: u64 = (today_int - dob_int) as u64;
    assert(diff_u >= 180000);

    // ---- (4) hash_to_field(RNOKPP) = expand_message_xmd(SHA-256) IN-CIRCUIT. ----
    // DST_prime = DST || I2OSP(len(DST),1) = DST || 0x2a  (43 bytes).
    let dst_prime_len: u32 = DST_LEN + 1;

    // b0 = SHA256( Z_pad[64] || msg[10] || 00 60 || 00 || DST_prime[43] ) : 120 bytes
    let mut in0: [u8; 120] = [0; 120];
    // Z_pad: bytes 0..64 already zero.
    for k in 0..10 {
        in0[64 + k] = rnokpp_bytes[k];
    }
    in0[74] = 0x00; // I2OSP(96,2) high byte
    in0[75] = 0x60; // I2OSP(96,2) low byte (96)
    in0[76] = 0x00; // I2OSP(0,1)
    for k in 0..DST_LEN {
        in0[77 + k] = DST[k];
    }
    in0[77 + DST_LEN] = DST_LEN as u8; // 0x2a, the len byte of DST_prime
    let _ = dst_prime_len; // documented above; layout uses DST_LEN directly
    let b0: [u8; 32] = sha256::digest(in0);

    // b1 = SHA256( b0[32] || 01 || DST_prime[43] ) : 76 bytes
    let mut in1: [u8; 76] = [0; 76];
    for k in 0..32 {
        in1[k] = b0[k];
    }
    in1[32] = 0x01;
    for k in 0..DST_LEN {
        in1[33 + k] = DST[k];
    }
    in1[33 + DST_LEN] = DST_LEN as u8;
    let b1: [u8; 32] = sha256::digest(in1);

    // b2 = SHA256( (b0 XOR b1)[32] || 02 || DST_prime[43] ) : 76 bytes
    let mut in2: [u8; 76] = [0; 76];
    for k in 0..32 {
        in2[k] = b0[k] ^ b1[k];
    }
    in2[32] = 0x02;
    for k in 0..DST_LEN {
        in2[33 + k] = DST[k];
    }
    in2[33 + DST_LEN] = DST_LEN as u8;
    let b2: [u8; 32] = sha256::digest(in2);

    // b3 = SHA256( (b0 XOR b2)[32] || 03 || DST_prime[43] ) : 76 bytes
    let mut in3: [u8; 76] = [0; 76];
    for k in 0..32 {
        in3[k] = b0[k] ^ b2[k];
    }
    in3[32] = 0x03;
    for k in 0..DST_LEN {
        in3[33 + k] = DST[k];
    }
    in3[33 + DST_LEN] = DST_LEN as u8;
    let b3: [u8; 32] = sha256::digest(in3);

    // uniform_bytes = b1 || b2 || b3 (96 bytes). u0 = [0..48], u1 = [48..96].
    let mut u0_bytes: [u8; 48] = [0; 48];
    let mut u1_bytes: [u8; 48] = [0; 48];
    for k in 0..32 {
        u0_bytes[k] = b1[k];
    }
    for k in 0..16 {
        u0_bytes[32 + k] = b2[k];
    }
    for k in 0..16 {
        u1_bytes[k] = b2[16 + k];
    }
    for k in 0..32 {
        u1_bytes[16 + k] = b3[k];
    }
    let u0 = be_bytes_to_field(u0_bytes);
    let u1 = be_bytes_to_field(u1_bytes);

    // ---- (5) M = r * H2C(RNOKPP) = r*(P0 + P1) via SvdW + blackbox MSM. ----
    let p0 = svdw_map(u0, c1, c2, c3, c4, h0[0], h0[1], h0[2], h0[3], h0[4], h0[5]);
    let p1 = svdw_map(u1, c1, c2, c3, c4, h1[0], h1[1], h1[2], h1[3], h1[4], h1[5]);
    let r = Scalar { lo: r_lo, hi: r_hi };
    let m = multi_scalar_mul([p0, p1], [r, r]);

    (m.x, m.y)
}
