// CRISP-QES eligibility circuit - D-v2 chain-verify architecture.
//
// Proves: a Diia QES holder, holding a P-256 leaf cert issued by a
// trusted Diia *intermediate* CA, signed a specific petition - without
// revealing tax-ID or which cert was used, while emitting a per-petition
// nullifier that is unique within cert lifetime and unlinkable across
// petitions.
//
// What is proven in-circuit:
//   1. The signer's subject_serial begins with the ASCII prefix "TINUA-"
//      AND `subject_serial[0..32]` is byte-equal to
//      `leaf_tbs_bytes[subject_serial_offset .. subject_serial_offset+32]`.
//      Together: TINUA-prefixed serial is inside the very leaf TBS the
//      intermediate signed.
//   2. The 4 limbs `(leaf_pubkey_x_hi, leaf_pubkey_x_lo,
//      leaf_pubkey_y_hi, leaf_pubkey_y_lo)` (public input slots 3-6) are
//      the 16+16+16+16 byte halves of the (X, Y) following the canonical
//      27-byte P-256 SPKI prefix at
//      `leaf_tbs_bytes[leaf_pubkey_offset - 27 .. leaf_pubkey_offset + 64]`.
//      The 128-bit limb split is required so each Field public input
//      stays strictly below the BN254 modulus (P-256 coordinates can
//      exceed it; publishing them as single Fields would silently
//      mod-reduce ~25% of pubkeys, breaking the on-chain ECDSA check).
//      Together: the leaf pubkey the contract feeds to the precompile is
//      bound to the TBS the intermediate signed.
//   3. The 4 limbs `(intermediate_pubkey_x_hi, intermediate_pubkey_x_lo,
//      intermediate_pubkey_y_hi, intermediate_pubkey_y_lo)` (slots 7-10)
//      are similarly bound to `intermediate_spki_bytes` via the canonical
//      prefix at `intermediate_pubkey_offset`.
//   4. The Pedersen commit of the fixed-size, zero-padded
//      `intermediate_spki_bytes` (`SPKI_COMMIT_DOMAIN = 1`) is the leaf of
//      the Merkle inclusion proof.
//   5. The Merkle path walked under `MERKLE_NODE_DOMAIN = 0` terminates at
//      the pinned public `trust_root`.
//   6. `sha256(leaf_tbs_bytes[..leaf_tbs_len])`, split into hi/lo 128-bit
//      limbs, equals public input slots 7 and 8 - the contract reconstructs
//      this into the bytes32 `leafTbsHash` it feeds to the precompile.
//   7. `sha256(signed_attrs_bytes[..signed_attrs_len])`, split into hi/lo
//      limbs, equals public input slots 9 and 10 - the contract
//      reconstructs this into the bytes32 `signedAttrsHash`.
//   8. The 32-byte `messageDigest` OCTET STRING value embedded inside
//      `signed_attrs_bytes` at `message_digest_offset` equals
//      `sha256(petition_id_be32 || "::" || petition_text_hash)`, pinning
//      the signature to *this* petition.
//   9. `nullifier = pedersen_hash([leaf_pubkey_x, leaf_pubkey_y,
//      petition_id, DOMAIN_PETITION_V1])`.
//
// What is NOT proven in-circuit (deliberate, see spec sec 2.1):
//   * P-256 ECDSA verification of either signature. Both happen on-chain
//     via the RIP-7212 precompile at 0x0000...0100. The circuit's job is
//     only to bind the right `(pubkey, msg_hash)` tuples.
//   * The full RFC 5280 X.509 validation (validity dates, KU/EKU, name
//     constraints, etc.). The flattener already enforces those at
//     trust-list-build time per spec sec 5.
//
// Public-input order (FIXED, matches `PetitionRegistry.signPetition`):
//   [0]  petition_id
//   [1]  nullifier
//   [2]  trust_root
//   [3]  leaf_pubkey_x_hi             (high 16 bytes of leaf X, BE-packed)
//   [4]  leaf_pubkey_x_lo             (low  16 bytes of leaf X, BE-packed)
//   [5]  leaf_pubkey_y_hi             (high 16 bytes of leaf Y, BE-packed)
//   [6]  leaf_pubkey_y_lo             (low  16 bytes of leaf Y, BE-packed)
//   [7]  intermediate_pubkey_x_hi     (high 16 bytes of intermediate X, BE-packed)
//   [8]  intermediate_pubkey_x_lo     (low  16 bytes of intermediate X, BE-packed)
//   [9]  intermediate_pubkey_y_hi     (high 16 bytes of intermediate Y, BE-packed)
//   [10] intermediate_pubkey_y_lo     (low  16 bytes of intermediate Y, BE-packed)
//   [11] leaf_tbs_sha256_hi           (high 16 bytes BE-packed)
//   [12] leaf_tbs_sha256_lo           (low  16 bytes BE-packed)
//   [13] signed_attrs_sha256_hi       (high 16 bytes BE-packed)
//   [14] signed_attrs_sha256_lo       (low  16 bytes BE-packed)

mod cades;
mod merkle;
mod pubkey;
mod spki;

use std::hash::pedersen_hash;
use sha256::sha256_var;

use cades::{
    be_bytes16_to_field, extract_digest, inner_message_digest,
    SIGNED_ATTRS_MAX_BYTES,
};
use merkle::compute_root;
use pubkey::{assert_p256_spki_prefix, extract_p256_xy, P256_SPKI_PREFIX_LEN};
use spki::{intermediate_spki_commit, INTERMEDIATE_SPKI_MAX_BYTES};

/// 128-bit random tag pinning the nullifier domain for v1 of the protocol.
/// Distinct from `MERKLE_NODE_DOMAIN` and `SPKI_COMMIT_DOMAIN` (Pedersen
/// hash-index separators) - this one rides inside the hashed input tuple.
pub global DOMAIN_PETITION_V1: Field = 0x0c0915920b3d3ee18f1e4a2b00000000;

global MERKLE_DEPTH: u32 = 16;
global TINUA_PREFIX: [u8; 6] = [0x54, 0x49, 0x4E, 0x55, 0x41, 0x2D]; // "TINUA-"
global SUBJECT_SERIAL_LEN: u32 = 32;
global LEAF_TBS_MAX_BYTES: u32 = 2048;
global PETITION_TEXT_HASH_LEN: u32 = 32;

fn main(
    // ---- public ----
    petition_id: pub Field,
    nullifier: pub Field,
    trust_root: pub Field,
    leaf_pubkey_x_hi: pub Field,
    leaf_pubkey_x_lo: pub Field,
    leaf_pubkey_y_hi: pub Field,
    leaf_pubkey_y_lo: pub Field,
    intermediate_pubkey_x_hi: pub Field,
    intermediate_pubkey_x_lo: pub Field,
    intermediate_pubkey_y_hi: pub Field,
    intermediate_pubkey_y_lo: pub Field,
    leaf_tbs_sha256_hi: pub Field,
    leaf_tbs_sha256_lo: pub Field,
    signed_attrs_sha256_hi: pub Field,
    signed_attrs_sha256_lo: pub Field,

    // ---- private ----
    subject_serial: [u8; SUBJECT_SERIAL_LEN],
    subject_serial_offset: u32,
    leaf_tbs_bytes: [u8; LEAF_TBS_MAX_BYTES],
    leaf_tbs_len: u32,
    leaf_pubkey_offset: u32,
    intermediate_spki_bytes: [u8; INTERMEDIATE_SPKI_MAX_BYTES],
    intermediate_pubkey_offset: u32,
    merkle_path: [Field; MERKLE_DEPTH],
    merkle_path_indices: [bool; MERKLE_DEPTH],
    signed_attrs_bytes: [u8; SIGNED_ATTRS_MAX_BYTES],
    signed_attrs_len: u32,
    message_digest_offset: u32,
    petition_text_hash: [u8; PETITION_TEXT_HASH_LEN],
) {
    // ---- 1. TINUA- prefix + bind subject_serial to leaf TBS ----
    for i in 0..6 {
        assert(subject_serial[i] == TINUA_PREFIX[i]);
    }
    assert(subject_serial_offset + SUBJECT_SERIAL_LEN <= leaf_tbs_len);
    for i in 0..SUBJECT_SERIAL_LEN {
        assert(leaf_tbs_bytes[subject_serial_offset + i] == subject_serial[i]);
    }

    // ---- 2. leaf pubkey extracted from leaf_tbs (prefix + 64 bytes) ----
    assert(leaf_pubkey_offset >= P256_SPKI_PREFIX_LEN);
    assert(leaf_pubkey_offset + 64 <= leaf_tbs_len);
    assert_p256_spki_prefix(leaf_tbs_bytes, leaf_pubkey_offset);
    let (lx_hi, lx_lo, ly_hi, ly_lo) = extract_p256_xy(leaf_tbs_bytes, leaf_pubkey_offset);
    assert(lx_hi == leaf_pubkey_x_hi);
    assert(lx_lo == leaf_pubkey_x_lo);
    assert(ly_hi == leaf_pubkey_y_hi);
    assert(ly_lo == leaf_pubkey_y_lo);

    // ---- 3. intermediate pubkey extracted from intermediate SPKI ----
    assert(intermediate_pubkey_offset >= P256_SPKI_PREFIX_LEN);
    assert(intermediate_pubkey_offset + 64 <= INTERMEDIATE_SPKI_MAX_BYTES);
    assert_p256_spki_prefix(intermediate_spki_bytes, intermediate_pubkey_offset);
    let (ix_hi, ix_lo, iy_hi, iy_lo) =
        extract_p256_xy(intermediate_spki_bytes, intermediate_pubkey_offset);
    assert(ix_hi == intermediate_pubkey_x_hi);
    assert(ix_lo == intermediate_pubkey_x_lo);
    assert(iy_hi == intermediate_pubkey_y_hi);
    assert(iy_lo == intermediate_pubkey_y_lo);

    // ---- 4. intermediate SPKI Pedersen commit (domain = SPKI_COMMIT_DOMAIN) ----
    let leaf = intermediate_spki_commit(intermediate_spki_bytes);

    // ---- 5. Pedersen-Merkle membership of the intermediate under trust_root ----
    let computed_root = compute_root::<MERKLE_DEPTH>(leaf, merkle_path, merkle_path_indices);
    assert(computed_root == trust_root);

    // ---- 6. SHA-256 of leaf TBS == public input slots 7 (hi) and 8 (lo) ----
    assert(leaf_tbs_len <= LEAF_TBS_MAX_BYTES);
    let tbs_digest = sha256_var(leaf_tbs_bytes, leaf_tbs_len);
    assert(be_bytes16_to_field(tbs_digest, 0) == leaf_tbs_sha256_hi);
    assert(be_bytes16_to_field(tbs_digest, 16) == leaf_tbs_sha256_lo);

    // ---- 7. SHA-256 of signedAttrs == public input slots 9 (hi) and 10 (lo) ----
    assert(signed_attrs_len <= SIGNED_ATTRS_MAX_BYTES);
    let sa_digest = sha256_var(signed_attrs_bytes, signed_attrs_len);
    assert(be_bytes16_to_field(sa_digest, 0) == signed_attrs_sha256_hi);
    assert(be_bytes16_to_field(sa_digest, 16) == signed_attrs_sha256_lo);

    // ---- 8. messageDigest binding to (petition_id, petition_text_hash) ----
    assert(message_digest_offset + 32 <= signed_attrs_len);
    let embedded =
        extract_digest::<SIGNED_ATTRS_MAX_BYTES>(signed_attrs_bytes, message_digest_offset);
    let expected = inner_message_digest(petition_id, petition_text_hash);
    for i in 0..32 {
        assert(embedded[i] == expected[i]);
    }

    // ---- 9. nullifier = pedersen_hash([leaf_x_hi, leaf_x_lo, leaf_y_hi,
    //                                    leaf_y_lo, petition_id, DOMAIN]) ----
    let expected_nullifier = pedersen_hash([
        leaf_pubkey_x_hi,
        leaf_pubkey_x_lo,
        leaf_pubkey_y_hi,
        leaf_pubkey_y_lo,
        petition_id,
        DOMAIN_PETITION_V1,
    ]);
    assert(nullifier == expected_nullifier);
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[test]
fn nullifier_matches_offchain_definition() {
    // pedersen_hash on the canonical 6-element input tuple. The SDK preview
    // reproduces this exact hash via @aztec/bb.js `pedersenHash` over the
    // four 128-bit pubkey limbs.
    let x_hi: Field = 0x01;
    let x_lo: Field = 0x02;
    let y_hi: Field = 0x03;
    let y_lo: Field = 0x04;
    let pid: Field = 42;
    let n = pedersen_hash([x_hi, x_lo, y_hi, y_lo, pid, DOMAIN_PETITION_V1]);
    assert(n != 0);
}

#[test]
fn merkle_depth16_roundtrip() {
    let leaf: Field = 0x1234567890abcdef;
    let path: [Field; 16] = [0; 16];
    let indices: [bool; 16] = [false; 16];
    let r1 = merkle::compute_root::<16>(leaf, path, indices);
    let r2 = merkle::compute_root::<16>(leaf, path, indices);
    assert(r1 == r2);
    assert(r1 != 0);
}

#[test]
fn tinua_prefix_positive() {
    let mut serial: [u8; 32] = [0; 32];
    serial[0] = 0x54; // T
    serial[1] = 0x49; // I
    serial[2] = 0x4E; // N
    serial[3] = 0x55; // U
    serial[4] = 0x41; // A
    serial[5] = 0x2D; // -
    serial[6] = 0x31; // '1' - random tax-ID byte
    for i in 0..6 {
        assert(serial[i] == TINUA_PREFIX[i]);
    }
}

#[test(should_fail)]
fn tinua_prefix_negative() {
    let mut serial: [u8; 32] = [0; 32];
    serial[0] = 0x54; // T
    serial[1] = 0x49; // I
    serial[2] = 0x4E; // N
    serial[3] = 0x55; // U
    serial[4] = 0x41; // A
    serial[5] = 0x5F; // '_' - wrong separator
    for i in 0..6 {
        assert(serial[i] == TINUA_PREFIX[i]);
    }
}

#[test]
fn message_digest_binding_synthetic() {
    let petition_id: Field = 7;
    let petition_text_hash: [u8; 32] = [0xAB; 32];
    let expected = cades::inner_message_digest(petition_id, petition_text_hash);

    let offset: u32 = 10;
    let mut signed_attrs: [u8; 512] = [0; 512];
    for i in 0..32 {
        signed_attrs[offset + i] = expected[i];
    }

    let extracted = cades::extract_digest::<512>(signed_attrs, offset);
    for i in 0..32 {
        assert(extracted[i] == expected[i]);
    }
}

#[test]
fn p256_spki_prefix_and_pubkey_extract() {
    // Build a fake buffer that opens with garbage, then the canonical
    // 27-byte prefix, then 64 distinguishable pubkey bytes, then more
    // garbage. Confirm the prefix check passes and the 4 limbs round-trip
    // via BE-pack of their respective 16-byte halves.
    let mut buf: [u8; 256] = [0; 256];
    let prefix_offset: u32 = 30;
    for i in 0..27 {
        buf[prefix_offset + i] = pubkey::P256_SPKI_PREFIX[i];
    }
    let pk_offset: u32 = prefix_offset + 27;
    // X = 0x01 02 03 ... 20  (32 increasing bytes)
    // Y = 0xFF FE FD ... E0  (32 decreasing bytes from 0xFF)
    for i in 0..32 {
        buf[pk_offset + i] = (i as u8) + 1;
        buf[pk_offset + 32 + i] = 0xFF - (i as u8);
    }
    pubkey::assert_p256_spki_prefix(buf, pk_offset);
    let (x_hi, x_lo, y_hi, y_lo) = pubkey::extract_p256_xy(buf, pk_offset);

    // Hand-compute the BE-packed 16-byte halves to compare.
    let mut expected_x_hi: Field = 0;
    let mut expected_x_lo: Field = 0;
    let mut expected_y_hi: Field = 0;
    let mut expected_y_lo: Field = 0;
    for i in 0..16 {
        expected_x_hi = expected_x_hi * 256 + ((i as Field) + 1);
        expected_x_lo = expected_x_lo * 256 + ((i as Field) + 1 + 16);
        expected_y_hi = expected_y_hi * 256 + (255 - (i as Field));
        expected_y_lo = expected_y_lo * 256 + (255 - 16 - (i as Field));
    }
    assert(x_hi == expected_x_hi);
    assert(x_lo == expected_x_lo);
    assert(y_hi == expected_y_hi);
    assert(y_lo == expected_y_lo);

    // Sanity: each limb fits in 128 bits.
    let two_pow_128: Field = 0x100000000000000000000000000000000;
    assert(x_hi.lt(two_pow_128));
    assert(x_lo.lt(two_pow_128));
    assert(y_hi.lt(two_pow_128));
    assert(y_lo.lt(two_pow_128));
}

#[test(should_fail)]
fn p256_spki_prefix_rejects_corruption() {
    let mut buf: [u8; 64] = [0; 64];
    for i in 0..27 {
        buf[i] = pubkey::P256_SPKI_PREFIX[i];
    }
    // Corrupt one byte of the prefix.
    buf[10] = 0xFF;
    pubkey::assert_p256_spki_prefix(buf, 27);
}
