// In-circuit P-256 SubjectPublicKeyInfo (SPKI) parsing.
//
// The CRISP-QES trust chain is anchored in the canonical 27-byte prefix
// that opens every well-formed ECDSA-P-256 SPKI:
//
//   30 59                       SEQUENCE (89 bytes total)
//     30 13                     SEQUENCE (19 bytes - AlgorithmIdentifier)
//       06 07 2a 86 48 ce 3d 02 01      OID id-ecPublicKey
//       06 08 2a 86 48 ce 3d 03 01 07   OID secp256r1
//     03 42 00 04               BIT STRING (66 bytes, 0 unused, uncompressed point)
//   -- then 32 bytes X || 32 bytes Y
//
// The SDK passes `pubkey_offset` pointing at the first X byte; this module
// asserts the 27 bytes immediately preceding that offset match the
// canonical prefix and extracts the 64 bytes of (X, Y) as two BN254 fields.
//
// Pinning the prefix is what binds the extracted (X, Y) to *this* SPKI -
// otherwise a malicious witness could splice 64 random bytes inside an
// otherwise honest-looking TBS and claim them as the pubkey.

pub global P256_SPKI_PREFIX_LEN: u32 = 27;
pub global P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// Assert that `bytes[offset - 27 .. offset]` equals the canonical 27-byte
/// ECDSA-P-256 SPKI prefix. The caller is responsible for proving
/// `offset >= 27` (a u32 range check is automatic, but the >=27 bound is
/// a property check the caller must enforce).
pub fn assert_p256_spki_prefix<let N: u32>(bytes: [u8; N], offset: u32) {
    for i in 0..P256_SPKI_PREFIX_LEN {
        assert(bytes[offset - P256_SPKI_PREFIX_LEN + i] == P256_SPKI_PREFIX[i]);
    }
}

/// Big-endian-pack 16 bytes into a BN254 field element. Output is strictly
/// less than 2^128, well inside the BN254 prime, so the value is losslessly
/// preserved (no implicit mod-p reduction).
fn pack_be16<let N: u32>(bytes: [u8; N], offset: u32) -> Field {
    let mut acc: Field = 0;
    for i in 0..16 {
        acc = acc * 256 + (bytes[offset + i] as Field);
    }
    acc
}

/// Extract the affine (X, Y) coordinates following the canonical SPKI
/// prefix at `bytes[offset .. offset + 64]` and split them into four
/// 128-bit BN254 field-element limbs:
///
///   (x_hi, x_lo, y_hi, y_lo)
///
/// where `x_hi = BE(bytes[offset..offset+16])`,
/// `x_lo = BE(bytes[offset+16..offset+32])`, and similarly for Y. The
/// limb split is required because P-256 coordinates can exceed the BN254
/// modulus; publishing them as single Field public inputs would silently
/// mod-reduce ~25% of pubkeys, breaking the contract-side ECDSA call.
/// Each limb is strictly < 2^128 << field modulus.
///
/// The caller is responsible for proving `offset + 64 <= N` (the 64 pubkey
/// bytes lie inside the buffer).
pub fn extract_p256_xy<let N: u32>(
    bytes: [u8; N],
    offset: u32,
) -> (Field, Field, Field, Field) {
    let x_hi = pack_be16(bytes, offset);
    let x_lo = pack_be16(bytes, offset + 16);
    let y_hi = pack_be16(bytes, offset + 32);
    let y_lo = pack_be16(bytes, offset + 48);
    (x_hi, x_lo, y_hi, y_lo)
}
