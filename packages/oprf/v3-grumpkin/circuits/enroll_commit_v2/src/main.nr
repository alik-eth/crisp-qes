// enroll_commit_v2 circuit (v3 Grumpkin OPRF, operator-blind enrollment; build/unaudited).
//
// PHASE 2 + DIIA TRUST-CHAIN: the FUSED enroll_commit circuit with
// hash_to_field done FULLY IN-CIRCUIT, NOW with an in-circuit Diia CA -> leaf
// certificate-chain verification that authenticates the identity.
//
// PROVES in ONE proof, over a Diia-style P-256 leaf cert held privately:
//   (0) Diia CA -> leaf TBS chain: the leaf TBS bytes are signed by a PINNED
//       Diia QTSP CA key, and the leaf's own SPKI P-256 key equals the pubkey
//       used to sign the challenge (signed_attrs). This binds the identity to
//       a real Diia-issued cert -- without it, RNOKPP/pubkey were free witnesses
//       and a prover could enroll ANY RNOKPP with their OWN keypair.
//   (1) ECDSA-P256 signature over signedAttrs verifies (stdlib blackbox), under
//       the leaf SPKI key (now proven == cert key).
//   (2) RNOKPP (10 ASCII digits) extracted from the AUTHENTICATED leaf_tbs DER
//       behind OID 2.5.4.5 (06 03 55 04 05) + PrintableString (13 10) +
//       "TINUA-" (54 49 4E 55 41 2D) + 10 digits. The "TINUA-" prefix is
//       asserted but NOT hashed; only the 10 digits feed hash_to_field.
//   (3) DOB (8 ASCII digits YYYYMMDD) proves age >= 18 vs PUBLIC today, read
//       from the AUTHENTICATED leaf_tbs.
//   (4) u0, u1 = hash_to_field(RNOKPP) via expand_message_xmd(SHA-256),
//       computed IN-CIRCUIT.
//   (5) M = r * H2C(RNOKPP) where H2C = map(u0) + map(u1) (RFC-9380 SvdW),
//       M is the PUBLIC output.
//
// CHAIN PROVEN: Diia CA -> leaf TBS (carries RNOKPP + DOB + leaf SPKI) -> leaf
// key signs the challenge. RNOKPP/DOB are no longer read from a free cert[]
// buffer; they come from the CA-authenticated leaf_tbs.
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
// u1 = bytes[48..96].

use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar, multi_scalar_mul};

// LEAF_TBS_LEN bounds the leaf certificate's signed TBS bytes. Real Diia leaf
// TBS is ~1203 B (20 SHA-256 blocks); 1536 gives 24-block headroom. sha256_var
// digests exactly leaf_tbs_len bytes, so padding bytes never enter the hash.
global LEAF_TBS_LEN: u32 = 1536;

// Bound on the CMS signedAttrs blob the ECDSA signature actually covers
// (real Diia signedAttrs ~100-300 B). Hashed in-circuit with sha256_var so
// only `signed_attrs_len` bytes are digested (padding bytes are ignored).
global SA_LEN: u32 = 2048;

// Number of pinned Diia QTSP CA keys in the production root set.
global N_PINNED: u32 = 2;

// Pinned Diia QTSP CA P-256 public keys (the PRODUCTION root set). These are
// the ONLY keys main() trusts to have signed a leaf TBS. NO synthetic test CA
// is ever placed here -- its private key would be a backdoor. The Noir #[test]
// functions exercise assert_diia_chain with a SEPARATE synthetic pinned set.
//   UA-43395033-2311 and UA-43395033-2503 (Diia QTSP).
global DIIA_PINNED_CA: [([u8; 32], [u8; 32]); 2] = [
    (
        // UA-43395033-2311 x
        [
            0x85, 0x00, 0x04, 0x82, 0x65, 0xe9, 0x19, 0xc1, 0x73, 0x8e, 0x87, 0x35, 0x72, 0xc1,
            0xf6, 0x44, 0x38, 0x95, 0xa0, 0xc0, 0x39, 0x85, 0xfc, 0x71, 0xbd, 0x96, 0xa6, 0xf6,
            0x2a, 0x53, 0xbc, 0xc8,
        ],
        // UA-43395033-2311 y
        [
            0x69, 0xd2, 0x3c, 0xa6, 0xe6, 0xa2, 0xa7, 0xdc, 0x44, 0x3b, 0xbb, 0x2a, 0x0b, 0x91,
            0x4e, 0xe3, 0x5f, 0x1c, 0x74, 0xe2, 0x82, 0xec, 0xd8, 0xe6, 0xc5, 0x28, 0x7c, 0x7a,
            0x3d, 0x4a, 0xee, 0x10,
        ],
    ),
    (
        // UA-43395033-2503 x
        [
            0xc8, 0xb3, 0x54, 0x6f, 0x4a, 0x34, 0xc0, 0x21, 0xa3, 0x1b, 0x35, 0x78, 0x05, 0x7d,
            0x1d, 0xe3, 0x04, 0xcb, 0xf1, 0x74, 0x3a, 0x39, 0x1b, 0x20, 0x32, 0xcd, 0x5b, 0x7d,
            0x37, 0x18, 0x41, 0x48,
        ],
        // UA-43395033-2503 y
        [
            0xc2, 0x44, 0x0e, 0xa2, 0xfb, 0xa1, 0x08, 0x72, 0xb0, 0xbc, 0x90, 0xa9, 0x23, 0x71,
            0xad, 0x50, 0xf5, 0x9d, 0x0e, 0x9c, 0x02, 0x16, 0xed, 0x52, 0xfd, 0x25, 0x9b, 0x8a,
            0x8c, 0xc9, 0xee, 0x54,
        ],
    ),
];

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

fn read_at(buf: [u8; LEAF_TBS_LEN], base: u32, k: u32) -> u8 {
    buf[base + k]
}

// Reduce a big-endian byte array to a Field (== bytesToNumberBE(bytes) mod P).
fn be_bytes_to_field<let M: u32>(bytes: [u8; M]) -> Field {
    let mut acc: Field = 0;
    for i in 0..M {
        acc = acc * 256 + bytes[i] as Field;
    }
    acc
}

// Byte-equality of two [u8;32] arrays as a 0/1 Field accumulator. Returns 1 if
// equal, 0 otherwise. Used for constant-time pinned-CA membership.
fn bytes32_eq(a: [u8; 32], b: [u8; 32]) -> Field {
    let mut acc: u32 = 0;
    for i in 0..32 {
        acc += (a[i] != b[i]) as u32;
    }
    (acc == 0) as Field
}

// Assert (ca_x, ca_y) is byte-equal to one of the `pinned` CA keys. The pinned
// set is a PARAMETER so main() can pass the real Diia root set while #[test]
// passes a synthetic set (whose private key never appears in production).
fn assert_ca_pinned(ca_x: [u8; 32], ca_y: [u8; 32], pinned: [([u8; 32], [u8; 32]); N_PINNED]) {
    let mut hits: Field = 0;
    for i in 0..N_PINNED {
        let (px, py) = pinned[i];
        // Both coordinates must match the SAME pinned entry.
        hits += bytes32_eq(ca_x, px) * bytes32_eq(ca_y, py);
    }
    // Exactly-one (or more) match required. Pinned keys are distinct, so a
    // valid CA hits exactly one entry => hits == 1; a non-pinned CA => hits == 0.
    assert(hits == 1);
}

// Bind the signed_attrs key to the leaf cert SPKI (cert <-> pubkey). The leaf
// SPKI carries the uncompressed P-256 point 04 || X(32) || Y(32). spki_off
// points at X[0]; the 0x04 marker is the byte before it. The 65-byte point
// (04 + 64) MUST lie inside the CA-signed region [0, tbs_len). Asserts the
// extracted (X, Y) equals (pubkey_x, pubkey_y). Factored so a #[test] can drive
// the cert<->pubkey mismatch negative directly.
fn assert_spki_binds_pubkey(
    leaf_tbs: [u8; LEAF_TBS_LEN],
    tbs_len: u32,
    spki_off: u32,
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
) {
    assert(spki_off >= 1);
    assert(spki_off + 64 <= tbs_len);
    assert(read_at(leaf_tbs, spki_off - 1, 0) == 0x04);
    for k in 0..32 {
        assert(read_at(leaf_tbs, spki_off, k) == pubkey_x[k]);
    }
    for k in 0..32 {
        assert(read_at(leaf_tbs, spki_off + 32, k) == pubkey_y[k]);
    }
}

// Extract + validate the RNOKPP DER block from the AUTHENTICATED leaf_tbs and
// return the 10 ASCII digit bytes. The full block (OID 5 + tag/len 2 +
// "TINUA-" 6 + 10 digits = 23 bytes) MUST lie inside [0, tbs_len); reading from
// outside the CA-signed region is rejected by the bound check. Factored so a
// #[test] can drive the out-of-bounds negative directly.
fn extract_rnokpp(leaf_tbs: [u8; LEAF_TBS_LEN], tbs_len: u32, oid_off: u32) -> [u8; 10] {
    assert(oid_off + 23 <= tbs_len);
    // OID 2.5.4.5 == DER: 06 03 55 04 05
    assert(read_at(leaf_tbs, oid_off, 0) == 0x06);
    assert(read_at(leaf_tbs, oid_off, 1) == 0x03);
    assert(read_at(leaf_tbs, oid_off, 2) == 0x55);
    assert(read_at(leaf_tbs, oid_off, 3) == 0x04);
    assert(read_at(leaf_tbs, oid_off, 4) == 0x05);
    // PrintableString tag 0x13, length 0x10 (16) = len("TINUA-") + 10 digits.
    assert(read_at(leaf_tbs, oid_off, 5) == 0x13);
    assert(read_at(leaf_tbs, oid_off, 6) == 0x10);

    // "TINUA-" ASCII prefix: 0x54 0x49 0x4E 0x55 0x41 0x2D (6 bytes).
    let prefix_base = oid_off + 7;
    assert(read_at(leaf_tbs, prefix_base, 0) == 0x54); // 'T'
    assert(read_at(leaf_tbs, prefix_base, 1) == 0x49); // 'I'
    assert(read_at(leaf_tbs, prefix_base, 2) == 0x4E); // 'N'
    assert(read_at(leaf_tbs, prefix_base, 3) == 0x55); // 'U'
    assert(read_at(leaf_tbs, prefix_base, 4) == 0x41); // 'A'
    assert(read_at(leaf_tbs, prefix_base, 5) == 0x2D); // '-'

    // The 10 ASCII RNOKPP digits follow the "TINUA-" prefix. Only THESE 10
    // digits are folded/hashed (NOT the prefix).
    let digits_base = oid_off + 13;
    let mut rnokpp_bytes: [u8; 10] = [0; 10];
    for k in 0..10 {
        let b = read_at(leaf_tbs, digits_base, k);
        assert((b >= 0x30) & (b <= 0x39));
        rnokpp_bytes[k] = b;
    }
    rnokpp_bytes
}

// Verify the Diia CA -> leaf TBS link and pin the CA, given the pinned set as a
// parameter. e_leaf MUST be sha256_var(leaf_tbs, leaf_tbs_len) computed by the
// caller (the authenticated digest). This is the single soundness-critical
// chain step, factored so tests can substitute a synthetic pinned set.
fn assert_diia_chain(
    ca_x: [u8; 32],
    ca_y: [u8; 32],
    leaf_cert_sig: [u8; 64],
    e_leaf: [u8; 32],
    pinned: [([u8; 32], [u8; 32]); N_PINNED],
) {
    // (3) CA must be in the pinned Diia root set.
    assert_ca_pinned(ca_x, ca_y, pinned);
    // (2) The pinned CA must have signed this leaf TBS digest.
    let ok = std::ecdsa_secp256r1::verify_signature(ca_x, ca_y, leaf_cert_sig, e_leaf);
    assert(ok);
}

fn main(
    // --- (a) ECDSA-P256 over signedAttrs (leaf key) ---
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    sig: [u8; 64],
    // --- CMS signedAttrs the ECDSA signature covers (PRIVATE) ---
    signed_attrs: [u8; SA_LEN],
    signed_attrs_len: u32,
    msg_digest_off: u32,
    // --- Diia leaf certificate TBS (PRIVATE), CA-authenticated below ---
    leaf_tbs: [u8; LEAF_TBS_LEN],
    leaf_tbs_len: u32,
    // --- CA chain: pinned Diia CA key + its signature over the leaf TBS ---
    ca_pubkey_x: [u8; 32],
    ca_pubkey_y: [u8; 32],
    leaf_cert_sig: [u8; 64],
    // --- offset of the leaf SPKI P-256 point X coordinate in leaf_tbs ---
    // (the byte immediately AFTER the 0x04 uncompressed-point marker) ---
    leaf_spki_off: u32,
    // --- RNOKPP OID + DOB offsets, now indexing into leaf_tbs ---
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
) -> pub (Field, Field, Field, Field) {
    // ---- (0) Diia CA -> leaf TBS chain + CA pinning. ----
    // sha256_var digests exactly leaf_tbs_len bytes; the CA signature must cover
    // that digest, and the CA must be in the PRODUCTION pinned Diia root set.
    let e_leaf: [u8; 32] = sha256::sha256_var(leaf_tbs, leaf_tbs_len);
    assert_diia_chain(
        ca_pubkey_x,
        ca_pubkey_y,
        leaf_cert_sig,
        e_leaf,
        DIIA_PINNED_CA,
    );

    // ---- (0') Bind signed_attrs key to the leaf cert SPKI (cert <-> pubkey).
    assert_spki_binds_pubkey(leaf_tbs, leaf_tbs_len, leaf_spki_off, pubkey_x, pubkey_y);

    // ---- (a) ECDSA-P256 verify over the IN-CIRCUIT signedAttrs hash. ----
    let msghash: [u8; 32] = sha256::sha256_var(signed_attrs, signed_attrs_len);
    let sig_ok = std::ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, sig, msghash);
    assert(sig_ok);

    // ---- (a') extract PKCS#9 messageDigest from signedAttrs. ----
    assert(signed_attrs[msg_digest_off] == 0x04);
    assert(signed_attrs[msg_digest_off + 1] == 0x20);
    assert(msg_digest_off + 34 <= signed_attrs_len);
    let mut digest_hi: Field = 0; // bytes [0..16]
    let mut digest_lo: Field = 0; // bytes [16..32]
    for k in 0..16 {
        digest_hi = digest_hi * 256 + signed_attrs[msg_digest_off + 2 + k] as Field;
    }
    for k in 0..16 {
        digest_lo = digest_lo * 256 + signed_attrs[msg_digest_off + 18 + k] as Field;
    }

    // ---- (b) RNOKPP DER structure + 10 digit bytes from AUTHENTICATED leaf_tbs.
    let rnokpp_bytes: [u8; 10] = extract_rnokpp(leaf_tbs, leaf_tbs_len, rnokpp_oid_off);

    // ---- (c) age >= 18, DOB read from AUTHENTICATED leaf_tbs. ----
    // The 8-byte DOB must lie inside the CA-signed region.
    assert(dob_off + 8 <= leaf_tbs_len);
    let mut dob_int: Field = 0;
    for k in 0..8 {
        let b = read_at(leaf_tbs, dob_off, k);
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
    let dst_prime_len: u32 = DST_LEN + 1;

    // b0 = SHA256( Z_pad[64] || msg[10] || 00 60 || 00 || DST_prime[43] ) : 120 bytes
    let mut in0: [u8; 120] = [0; 120];
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

    (m.x, m.y, digest_hi, digest_lo)
}

// ===========================================================================
// TESTS for the Diia trust-chain logic.
//
// SOUNDNESS NOTE: these tests exercise assert_diia_chain / assert_ca_pinned
// with a SYNTHETIC pinned set whose private key lives ONLY in the test helper
// (gen-chain-test-tuple.mjs). The synthetic CA is NEVER added to the production
// DIIA_PINNED_CA global -- doing so would be a backdoor. The real-Diia happy
// path is validated out-of-band with a real .p7s (PII, not committed).
//
// The (ca_x, ca_y, leaf_cert_sig, e_leaf) tuple below is generated by
// `node gen-chain-test-tuple.mjs`: a synthetic CA signing the SHA-256 digest of
// a synthetic leaf TBS that carries RNOKPP + DOB + leaf SPKI.
// ===========================================================================

// Synthetic CA pubkey (test-only; NOT a Diia key, NOT in DIIA_PINNED_CA).
fn test_synth_ca() -> ([u8; 32], [u8; 32]) {
    let ca_x: [u8; 32] = [
        241, 165, 35, 221, 3, 198, 49, 15, 232, 124, 198, 6, 75, 133, 189, 148, 83, 206, 186, 17,
        46, 126, 170, 183, 214, 92, 191, 164, 134, 135, 50, 251,
    ];
    let ca_y: [u8; 32] = [
        136, 97, 90, 166, 69, 250, 240, 208, 104, 123, 211, 3, 84, 221, 219, 235, 110, 62, 90, 101,
        207, 69, 238, 243, 232, 49, 193, 172, 245, 71, 53, 178,
    ];
    (ca_x, ca_y)
}

// Valid CA signature over e_leaf (the synthetic leaf-TBS digest).
fn test_synth_sig() -> [u8; 64] {
    [
        208, 187, 48, 203, 19, 90, 113, 97, 43, 249, 253, 51, 172, 241, 75, 218, 215, 83, 103, 75,
        175, 126, 149, 65, 75, 175, 1, 2, 35, 117, 204, 188, 25, 228, 38, 171, 1, 235, 81, 36, 78,
        87, 174, 211, 121, 34, 140, 47, 88, 41, 15, 144, 56, 141, 254, 218, 133, 116, 46, 156, 12,
        232, 175, 47,
    ]
}

// e_leaf = sha256(synthetic leaf_tbs[0..leaf_tbs_len]) the CA signed.
fn test_synth_e_leaf() -> [u8; 32] {
    [
        50, 12, 101, 7, 195, 231, 25, 150, 231, 72, 107, 122, 209, 213, 55, 150, 79, 124, 192, 112,
        55, 20, 235, 113, 134, 193, 195, 205, 55, 226, 249, 153,
    ]
}

// A synthetic pinned set that INCLUDES the synthetic CA (test happy path).
fn test_pinned_with_synth() -> [([u8; 32], [u8; 32]); N_PINNED] {
    let (ca_x, ca_y) = test_synth_ca();
    // Second slot is a distinct dummy key (an arbitrary other point's coords);
    // it must never coincide with the synthetic CA.
    let dummy_x: [u8; 32] = [1; 32];
    let dummy_y: [u8; 32] = [2; 32];
    [(ca_x, ca_y), (dummy_x, dummy_y)]
}

// A synthetic pinned set that does NOT include the synthetic CA (negative b).
fn test_pinned_without_synth() -> [([u8; 32], [u8; 32]); N_PINNED] {
    let dummy_x: [u8; 32] = [1; 32];
    let dummy_y: [u8; 32] = [2; 32];
    let other_x: [u8; 32] = [3; 32];
    let other_y: [u8; 32] = [4; 32];
    [(dummy_x, dummy_y), (other_x, other_y)]
}

// HAPPY (synthetic CA): chain verifies with the synthetic pinned set.
#[test]
fn test_chain_happy() {
    let (ca_x, ca_y) = test_synth_ca();
    assert_diia_chain(
        ca_x,
        ca_y,
        test_synth_sig(),
        test_synth_e_leaf(),
        test_pinned_with_synth(),
    );
}

// NEGATIVE (a): tampered leaf_tbs => e_leaf differs => CA sig invalid => fail.
#[test(should_fail)]
fn test_chain_tampered_leaf_fails() {
    let (ca_x, ca_y) = test_synth_ca();
    let mut bad_e = test_synth_e_leaf();
    bad_e[0] ^= 0x01; // flip one digest bit (simulates a tampered leaf_tbs)
    assert_diia_chain(ca_x, ca_y, test_synth_sig(), bad_e, test_pinned_with_synth());
}

// NEGATIVE (b): CA not in the pinned set => assert_ca_pinned fails closed.
#[test(should_fail)]
fn test_chain_ca_not_pinned_fails() {
    let (ca_x, ca_y) = test_synth_ca();
    assert_diia_chain(
        ca_x,
        ca_y,
        test_synth_sig(),
        test_synth_e_leaf(),
        test_pinned_without_synth(),
    );
}

// assert_ca_pinned positive: synthetic CA is in the synthetic pinned set.
#[test]
fn test_ca_pinned_member() {
    let (ca_x, ca_y) = test_synth_ca();
    assert_ca_pinned(ca_x, ca_y, test_pinned_with_synth());
}

// assert_ca_pinned negative: a half-match (x matches, y does not) must fail.
// Guards against an OR-over-coordinates bug where matching either coordinate
// would wrongly pass.
#[test(should_fail)]
fn test_ca_pinned_half_match_fails() {
    let (ca_x, _ca_y) = test_synth_ca();
    let wrong_y: [u8; 32] = [9; 32];
    assert_ca_pinned(ca_x, wrong_y, test_pinned_with_synth());
}

// Synthetic leaf SPKI key (the cert subject's key), matching the layout the
// witness generator embeds in leaf_tbs.
fn test_leaf_pub() -> ([u8; 32], [u8; 32]) {
    let leaf_x: [u8; 32] = [
        103, 102, 225, 157, 67, 65, 53, 26, 9, 181, 128, 225, 211, 77, 248, 81, 171, 9, 17, 161,
        158, 155, 18, 48, 164, 49, 143, 91, 175, 228, 241, 213,
    ];
    let leaf_y: [u8; 32] = [
        65, 155, 42, 26, 9, 39, 142, 121, 81, 45, 129, 119, 157, 31, 187, 190, 176, 223, 1, 220,
        39, 86, 171, 149, 239, 209, 128, 1, 188, 196, 75, 174,
    ];
    (leaf_x, leaf_y)
}

// Build a synthetic leaf_tbs mirroring gen-chain-test-tuple.mjs / the witness
// generator: filler bytes (i*17+5), SPKI point at spkiMarkerOff=100
// (04 || X || Y, so leaf_spki_off=101), RNOKPP block at 300, DOB at 500.
// leaf_tbs_len = 900.
fn test_build_leaf_tbs() -> [u8; LEAF_TBS_LEN] {
    let mut tbs: [u8; LEAF_TBS_LEN] = [0; LEAF_TBS_LEN];
    for i in 0..900 {
        tbs[i] = ((i * 17 + 5) & 0xff) as u8;
    }
    // SPKI uncompressed point at marker offset 100.
    let (leaf_x, leaf_y) = test_leaf_pub();
    tbs[100] = 0x04;
    for k in 0..32 {
        tbs[101 + k] = leaf_x[k];
    }
    for k in 0..32 {
        tbs[133 + k] = leaf_y[k];
    }
    // RNOKPP block at 300: 06 03 55 04 05 13 10 "TINUA-" + "1234567890".
    let oid: [u8; 7] = [0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x10];
    for k in 0..7 {
        tbs[300 + k] = oid[k];
    }
    let tinua: [u8; 6] = [0x54, 0x49, 0x4E, 0x55, 0x41, 0x2D];
    for k in 0..6 {
        tbs[307 + k] = tinua[k];
    }
    let digits: [u8; 10] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
    for k in 0..10 {
        tbs[313 + k] = digits[k];
    }
    // DOB "19900115" at 500.
    let dob: [u8; 8] = [0x31, 0x39, 0x39, 0x30, 0x30, 0x31, 0x31, 0x35];
    for k in 0..8 {
        tbs[500 + k] = dob[k];
    }
    tbs
}

// SPKI bind positive: pubkey == leaf SPKI in leaf_tbs.
#[test]
fn test_spki_bind_ok() {
    let tbs = test_build_leaf_tbs();
    let (leaf_x, leaf_y) = test_leaf_pub();
    assert_spki_binds_pubkey(tbs, 900, 101, leaf_x, leaf_y);
}

// NEGATIVE (c): pubkey != leaf SPKI in leaf_tbs => cert<->pubkey bind fails.
#[test(should_fail)]
fn test_spki_bind_wrong_pubkey_fails() {
    let tbs = test_build_leaf_tbs();
    let (leaf_x, _leaf_y) = test_leaf_pub();
    let attacker_y: [u8; 32] = [7; 32];
    assert_spki_binds_pubkey(tbs, 900, 101, leaf_x, attacker_y);
}

// RNOKPP extraction positive: reads the 10 digits from the authenticated block.
#[test]
fn test_rnokpp_extract_ok() {
    let tbs = test_build_leaf_tbs();
    let digits = extract_rnokpp(tbs, 900, 300);
    let expected: [u8; 10] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
    for k in 0..10 {
        assert(digits[k] == expected[k]);
    }
}

// NEGATIVE (d): rnokpp_oid_off points OUTSIDE [0, leaf_tbs_len) (into the
// unauthenticated padding region). Even with a valid-looking RNOKPP block
// planted there, the `oid_off + 23 <= tbs_len` bound must reject it.
#[test(should_fail)]
fn test_rnokpp_out_of_bounds_fails() {
    let mut tbs = test_build_leaf_tbs();
    // Plant a valid RNOKPP block at 950 (>= tbs_len 900, in padding).
    let oid: [u8; 7] = [0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x10];
    for k in 0..7 {
        tbs[950 + k] = oid[k];
    }
    let tinua: [u8; 6] = [0x54, 0x49, 0x4E, 0x55, 0x41, 0x2D];
    for k in 0..6 {
        tbs[957 + k] = tinua[k];
    }
    let digits: [u8; 10] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
    for k in 0..10 {
        tbs[963 + k] = digits[k];
    }
    let _ = extract_rnokpp(tbs, 900, 950); // bound check must fail
}
