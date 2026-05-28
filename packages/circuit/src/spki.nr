// In-circuit SPKI commitment.
//
// Trust-root anchor for CRISP-QES D-v2: the trust-list builder
// (`packages/lotl-flattener`) commits each trusted *intermediate* CA's SPKI
// DER as a Pedersen-Merkle leaf. The Noir circuit recomputes that leaf
// commit inside the proof, then walks the Merkle path up to `trust_root`.
//
// Both sides MUST mirror this construction byte-for-byte:
//
//   1. Zero-pad the SPKI DER to exactly `SPKI_MAX_BYTES` (1024) bytes.
//   2. Split the buffer into 34 chunks: 33 chunks of 31 contiguous bytes,
//      then 1 trailing chunk of 1 byte (33*31 + 1 = 1024).
//   3. Big-endian-pack each chunk into a BN254 field element.
//   4. spki_commit = pedersen_hash_with_separator(fields, SPKI_COMMIT_DOMAIN)
//
// Rationale: Noir stdlib `pedersen_hash_with_separator` takes `[Field; N]`,
// not bytes, so the SDK can't simply call bb.js's `pedersen_hash_buffer`
// (which uses an opaque internal chunking). Pinning a single, explicit
// chunking here keeps the SDK + flattener implementations trivial and
// auditable. Pack size 31 < log2(p)/8 keeps every chunk strictly inside
// the BN254 field range.

use std::hash::pedersen_hash_with_separator;

pub global SPKI_COMMIT_DOMAIN: u32 = 1;
pub global INTERMEDIATE_SPKI_MAX_BYTES: u32 = 1024;

global SPKI_NUM_CHUNKS: u32 = 34;
global SPKI_FULL_CHUNKS: u32 = 33;
global SPKI_CHUNK_BYTES: u32 = 31;

/// Pack 31 bytes big-endian into a single BN254 field element.
fn pack31_be(chunk: [u8; 31]) -> Field {
    let mut acc: Field = 0;
    for i in 0..31 {
        acc = acc * 256 + (chunk[i] as Field);
    }
    acc
}

/// Compute the canonical SPKI commitment for the fixed-size, zero-padded
/// intermediate CA SPKI buffer. See module-level doc for the exact algorithm.
pub fn intermediate_spki_commit(spki_bytes: [u8; INTERMEDIATE_SPKI_MAX_BYTES]) -> Field {
    let mut fields: [Field; SPKI_NUM_CHUNKS] = [0; SPKI_NUM_CHUNKS];
    for c in 0..SPKI_FULL_CHUNKS {
        let mut chunk: [u8; 31] = [0; 31];
        for b in 0..SPKI_CHUNK_BYTES {
            chunk[b] = spki_bytes[c * SPKI_CHUNK_BYTES + b];
        }
        fields[c] = pack31_be(chunk);
    }
    fields[33] = spki_bytes[1023] as Field;
    pedersen_hash_with_separator(fields, SPKI_COMMIT_DOMAIN)
}
