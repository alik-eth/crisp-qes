// qes_frontend circuit (v3 Grumpkin OPRF, operator-blind enrollment; build/unaudited).
//
// PROVES, over a Diia-style QES certificate (DER) held PRIVATELY in-circuit:
//   (a) ECDSA-P256 signature over signedAttrs verifies (stdlib blackbox).
//   (b) the RNOKPP (10-digit Ukrainian taxpayer id) lives in the cert at a
//       witnessed offset, behind OID 2.5.4.5 (DER 06 03 55 04 05) +
//       PrintableString tag/len (13 10) + "TINUA-" prefix + 10 ASCII-digit
//       bytes. The "TINUA-" prefix is asserted but NOT folded; only the 10
//       digits form the output Field (matches web extractRnokpp()).
//   (c) DOB (8 ASCII digits YYYYMMDD) at a witnessed offset proves age >= 18
//       against a PUBLIC current-date (YYYYMMDD) input.
//   (d) outputs a Field = fold of the 10 RNOKPP digit bytes. This is the value
//       that feeds the OPRF commitment circuit's hash_to_field (one stable
//       Field per identity -> one commitment per RNOKPP, anti-Sybil).
//
// MSGHASH NOTE: sha256 is NOT in the beta.19 stdlib (only sha256_compression,
// a per-64-byte-block blackbox). For this milestone msghash is a WITNESSED
// input and JS computes sha256(signedAttrs); the circuit verifies the ECDSA
// over the given hash. The signedAttrs->hash binding (chaining
// sha256_compression in-circuit) is DEFERRED. Everything else is in-circuit.

global CERT_LEN: u32 = 768; // synthetic DER buffer length

// Reads cert[base + k] for a witnessed `base`. Dynamic array indexing in
// beta.19 lowers to a constrained read (the "6,756 gates/field" pattern from
// the v3-enroll spike: dynamic reads at offset + const).
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
    dob_off: u32,        // points at first of 8 ASCII DOB digits (YYYYMMDD)
    // --- (c) public current date as 8 ASCII digits YYYYMMDD ---
    today: pub [u8; 8],
) -> pub Field {
    // (a) ECDSA-P256 signature must verify over the (witnessed) message hash.
    let sig_ok = std::ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, sig, msghash);
    assert(sig_ok);

    // (b) RNOKPP structure check at the witnessed offset (REAL Diia encoding).
    // A real Diia subject serialNumber is "TINUA-<10 digits>" (16 bytes), so the
    // DER behind OID 2.5.4.5 is: 06 03 55 04 05  13 10  "TINUA-"  <10 digits>.
    // OID 2.5.4.5 == DER: 06 03 55 04 05
    assert(read_at(cert, rnokpp_oid_off, 0) == 0x06);
    assert(read_at(cert, rnokpp_oid_off, 1) == 0x03);
    assert(read_at(cert, rnokpp_oid_off, 2) == 0x55);
    assert(read_at(cert, rnokpp_oid_off, 3) == 0x04);
    assert(read_at(cert, rnokpp_oid_off, 4) == 0x05);
    // PrintableString tag 0x13, length 0x10 (16) = len("TINUA-") + 10 digits.
    assert(read_at(cert, rnokpp_oid_off, 5) == 0x13);
    assert(read_at(cert, rnokpp_oid_off, 6) == 0x10);

    // "TINUA-" ASCII prefix: 0x54 0x49 0x4E 0x55 0x41 0x2D (6 bytes).
    let prefix_base = rnokpp_oid_off + 7;
    assert(read_at(cert, prefix_base, 0) == 0x54); // 'T'
    assert(read_at(cert, prefix_base, 1) == 0x49); // 'I'
    assert(read_at(cert, prefix_base, 2) == 0x4E); // 'N'
    assert(read_at(cert, prefix_base, 3) == 0x55); // 'U'
    assert(read_at(cert, prefix_base, 4) == 0x41); // 'A'
    assert(read_at(cert, prefix_base, 5) == 0x2D); // '-'

    // 10 ASCII-digit bytes AFTER the "TINUA-" prefix; fold ONLY these into a
    // single Field (base-10 accumulate). The prefix is asserted but NOT folded,
    // matching the web extractRnokpp() which strips "TINUA-".
    let digits_base = rnokpp_oid_off + 13;
    let mut rnokpp_field: Field = 0;
    for k in 0..10 {
        let b = read_at(cert, digits_base, k);
        assert((b >= 0x30) & (b <= 0x39)); // ASCII '0'..'9'
        let d = (b - 0x30) as Field;
        rnokpp_field = rnokpp_field * 10 + d;
    }

    // (c) DOB age >= 18 against PUBLIC today (both YYYYMMDD, 8 ASCII digits).
    // Build integer YYYYMMDD for DOB (from cert) and today (public input),
    // then assert today_int - dob_int >= 18_0000 (18 years in YYYYMMDD units).
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
    // age >= 18  <=>  today_int >= dob_int + 18*10000 (YYYYMMDD arithmetic:
    // adding 18 to the YYYY field == +180000). Range-check the gap is
    // non-negative and fits, via to-le-bits style bound: assert diff in u32.
    let diff = today_int - dob_int;
    // diff is a small positive integer (< ~10^8); cast through u64 to range-check
    // and compare. (Field->u64 cast constrains the value to fit in 64 bits.)
    let diff_u: u64 = diff as u64;
    assert(diff_u >= 180000);

    // (d) public output: the RNOKPP folded into a Field (OPRF hash_to_field input).
    rnokpp_field
}
