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

/// Big-endian-pack 32 bytes into a BN254 field element. NOTE: P-256
/// coordinates can exceed the BN254 modulus, in which case the returned
/// Field is the value reduced mod p. The contract is responsible for
/// detecting that mismatch by comparing each public input against the
/// caller-supplied uint256 in calldata.
fn pack_be32(bytes: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + (bytes[i] as Field);
    }
    acc
}

/// Extract the affine (X, Y) coordinates following the canonical SPKI
/// prefix at `bytes[offset .. offset + 64]`. Returns both as BN254 field
/// elements (BE-packed). The caller is responsible for proving
/// `offset + 64 <= N` (i.e. the 64 pubkey bytes lie inside the buffer).
pub fn extract_p256_xy<let N: u32>(bytes: [u8; N], offset: u32) -> (Field, Field) {
    let mut x_bytes: [u8; 32] = [0; 32];
    let mut y_bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        x_bytes[i] = bytes[offset + i];
        y_bytes[i] = bytes[offset + 32 + i];
    }
    (pack_be32(x_bytes), pack_be32(y_bytes))
}
