// CAdES `signedAttrs` helpers: SHA-256 binding to the public input slot and
// `messageDigest` extraction + petition-binding.
//
// The SDK parser surfaces `signedAttrs_bytes` (the canonical `SET` re-tag
// already applied - see `packages/sdk/src/p7s.ts`) and the byte offset of
// the embedded `messageDigest` OCTET STRING *value*. The circuit:
//
//   - hashes the first `signed_attrs_len` bytes via SHA-256 and asserts the
//     result matches the public `signed_attrs_sha256` slot;
//   - copies 32 bytes from `signed_attrs_bytes[message_digest_offset..]` and
//     asserts they equal `sha256(petition_id_be32 || "::" || petition_text_hash)`.

use sha256::sha256_var;

pub global SIGNED_ATTRS_MAX_BYTES: u32 = 512;
global INNER_MSG_LEN: u32 = 66; // 32 (petition_id) + 2 (::) + 32 (text_hash)

/// 32-byte SHA-256 of (petition_id big-endian 32 bytes || "::" || petition_text_hash).
pub fn inner_message_digest(
    petition_id: Field,
    petition_text_hash: [u8; 32],
) -> [u8; 32] {
    let pid_bytes: [u8; 32] = petition_id.to_be_bytes();
    let mut buf: [u8; INNER_MSG_LEN] = [0; INNER_MSG_LEN];
    for i in 0..32 {
        buf[i] = pid_bytes[i];
    }
    buf[32] = 0x3A; // ':'
    buf[33] = 0x3A; // ':'
    for i in 0..32 {
        buf[34 + i] = petition_text_hash[i];
    }
    sha256_var(buf, INNER_MSG_LEN)
}

/// Copy 32 bytes from `bytes[offset..offset+32]`. Bounds (offset + 32 <= len)
/// must be checked by the caller.
pub fn extract_digest<let MAX: u32>(bytes: [u8; MAX], offset: u32) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for i in 0..32 {
        out[i] = bytes[offset + i];
    }
    out
}

/// SHA-256 of the fixed-size, len-tagged `signedAttrs` buffer.
pub fn signed_attrs_hash(
    signed_attrs_bytes: [u8; SIGNED_ATTRS_MAX_BYTES],
    signed_attrs_len: u32,
) -> [u8; 32] {
    sha256_var(signed_attrs_bytes, signed_attrs_len)
}

/// Big-endian byte-array -> Field. Used to convert the SHA-256 digest output
/// (32 bytes) into the field-typed public-input slot. NOTE: SHA-256 produces
/// up to 256 bits but BN254 has ~254-bit capacity - values >= field modulus
/// are reduced mod p both circuit-side and verifier-side, so the equality
/// check is well-defined inside the circuit. The on-chain P-256 precompile
/// reads the raw bytes32 (no reduction); see spec note in sec 2.1.
pub fn be_bytes32_to_field(b: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + (b[i] as Field);
    }
    acc
}
