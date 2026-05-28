// CAdES `signedAttrs` helpers: SHA-256 binding to the public input slots and
// `messageDigest` extraction + petition-binding.
//
// The SDK parser surfaces `signedAttrs_bytes` (the canonical `SET` re-tag
// already applied - see `packages/sdk/src/p7s.ts`) and the byte offset of
// the embedded `messageDigest` OCTET STRING *value*. The circuit:
//
//   - hashes the first `signed_attrs_len` bytes via SHA-256 and asserts the
//     128-bit hi/lo limbs match public input slots 5 and 6;
//   - copies 32 bytes from `signed_attrs_bytes[message_digest_offset..]` and
//     asserts they equal `sha256(petition_id_be32 || "::" || petition_text_hash)`.
//
// The hi/lo split is a workaround for BN254's < 2^254 capacity: a single
// `Field` cannot losslessly carry a 256-bit SHA-256 output, so the contract
// would read a mod-p reduced value (~25% bad outcomes). Splitting at 128
// bits keeps each limb strictly < 2^128 << field modulus, and the contract
// reconstructs the raw bytes32 by concatenation before feeding the
// RIP-7212 precompile.

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

/// Big-endian 16-byte slice -> Field. Each output is strictly < 2^128 and
/// therefore always strictly less than the BN254 field modulus, so the
/// circuit / verifier / contract all agree on the same numeric value (no
/// implicit mod-p reduction).
///
/// `offset` indexes into the 32-byte SHA-256 digest; pass 0 for the high
/// limb and 16 for the low limb.
pub fn be_bytes16_to_field(b: [u8; 32], offset: u32) -> Field {
    let mut acc: Field = 0;
    for i in 0..16 {
        acc = acc * 256 + (b[offset + i] as Field);
    }
    acc
}
