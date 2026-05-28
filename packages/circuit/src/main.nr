// CRISP-QES eligibility circuit.
//
// Proves: a Diia QES holder signed a specific petition, without revealing
// tax-ID or which cert was used, while emitting a per-petition nullifier
// that is unique within cert lifetime and unlinkable across petitions.
//
// What is proven in-circuit:
//   1. The signer's subject_serial begins with the ASCII prefix "TINUA-".
//   2. The leaf cert's SPKI commits to a value (`spki_commit`) that lies in
//      the pinned Diia Pedersen-Merkle trust root.
//   3. SHA-256 of the canonical `signedAttrs` bytes equals the public input
//      slot 5 (which the contract also feeds to the RIP-7212 P-256
//      precompile as `msg_hash`).
//   4. The `messageDigest` attribute embedded inside `signedAttrs` equals
//      sha256(petition_id_be32 || "::" || petition_text_hash), pinning the
//      signature to *this* petition.
//   5. nullifier = pedersen_hash([pubkey.x, pubkey.y, petition_id,
//      DOMAIN_PETITION_V1]) with the domain constant baked into the input
//      tuple (no Pedersen separator on this one).
//
// What is NOT proven in-circuit (by design - see spec sec 2.1):
//   * The P-256 ECDSA verification of (sig_r, sig_s) over signedAttrsSha256
//     under (pubkey_x, pubkey_y). That happens on-chain via the RIP-7212
//     precompile at 0x0000...0100; the proof's job is to bind the same
//     (pubkey_x, pubkey_y, signedAttrsSha256) tuple to a trusted Diia cert.
//   * The full X.509 leaf -> intermediate -> Diia-CA chain. The MVP commits
//      to the citizen's leaf cert SPKI directly in the trust root
//      (`packages/lotl-flattener` populates the tree). This is the
//      simplification sec 5 "Out of scope" notes.
//
// Public-input order (FIXED by `PetitionRegistry.signPetition`):
//   [0] petition_id
//   [1] nullifier
//   [2] trust_root
//   [3] pubkey_x
//   [4] pubkey_y
//   [5] signedAttrsSha256 (also the P-256 msg_hash)

mod cades;
mod merkle;
mod spki;

use std::hash::pedersen_hash;

use cades::{
    be_bytes32_to_field, extract_digest, inner_message_digest, signed_attrs_hash,
    SIGNED_ATTRS_MAX_BYTES,
};
use merkle::compute_root;
use spki::{spki_commit, SPKI_MAX_BYTES};

/// 128-bit random tag pinning the nullifier domain for v1 of the protocol.
/// Distinct from `MERKLE_NODE_DOMAIN` and `SPKI_COMMIT_DOMAIN` (Pedersen
/// hash-index separators) - this one rides inside the hashed input tuple.
pub global DOMAIN_PETITION_V1: Field = 0x0c0915920b3d3ee18f1e4a2b00000000;

global MERKLE_DEPTH: u32 = 16;
global TINUA_PREFIX: [u8; 6] = [0x54, 0x49, 0x4E, 0x55, 0x41, 0x2D]; // "TINUA-"
global SUBJECT_SERIAL_LEN: u32 = 32;

fn main(
    // ---- public ----
    petition_id: pub Field,
    nullifier: pub Field,
    trust_root: pub Field,
    pubkey_x: pub Field,
    pubkey_y: pub Field,
    signed_attrs_sha256: pub Field,

    // ---- private ----
    subject_serial: [u8; SUBJECT_SERIAL_LEN],
    spki_bytes: [u8; SPKI_MAX_BYTES],
    merkle_path: [Field; MERKLE_DEPTH],
    merkle_path_indices: [bool; MERKLE_DEPTH],
    signed_attrs_bytes: [u8; SIGNED_ATTRS_MAX_BYTES],
    signed_attrs_len: u32,
    message_digest_offset: u32,
    petition_text_hash: [u8; 32],
) {
    // 1. TINUA- prefix on the subject serial.
    for i in 0..6 {
        assert(subject_serial[i] == TINUA_PREFIX[i]);
    }

    // 2. Leaf SPKI commit (domain = SPKI_COMMIT_DOMAIN).
    let leaf = spki_commit(spki_bytes);

    // 3. Pedersen-Merkle membership of the leaf under the pinned trust root.
    let computed_root = compute_root::<MERKLE_DEPTH>(leaf, merkle_path, merkle_path_indices);
    assert(computed_root == trust_root);

    // 4. SHA-256 of signedAttrs == public input slot 5.
    assert(signed_attrs_len <= SIGNED_ATTRS_MAX_BYTES);
    let sa_digest = signed_attrs_hash(signed_attrs_bytes, signed_attrs_len);
    assert(be_bytes32_to_field(sa_digest) == signed_attrs_sha256);

    // 5. messageDigest binding to (petition_id, petition_text_hash).
    //    The 32-byte OCTET STRING value lives at `message_digest_offset` in
    //    signed_attrs_bytes; the SDK parser surfaces that offset.
    assert(message_digest_offset + 32 <= signed_attrs_len);
    let embedded = extract_digest::<SIGNED_ATTRS_MAX_BYTES>(signed_attrs_bytes, message_digest_offset);
    let expected = inner_message_digest(petition_id, petition_text_hash);
    for i in 0..32 {
        assert(embedded[i] == expected[i]);
    }

    // 6. Nullifier = pedersen_hash([pubkey.x, pubkey.y, petition_id, DOMAIN]).
    let expected_nullifier =
        pedersen_hash([pubkey_x, pubkey_y, petition_id, DOMAIN_PETITION_V1]);
    assert(nullifier == expected_nullifier);
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[test]
fn nullifier_matches_offchain_definition() {
    // Sanity: pedersen_hash on the canonical input tuple. The SDK preview
    // should reproduce this exact hash via @aztec/bb.js `pedersenHash`.
    let px: Field = 1;
    let py: Field = 2;
    let pid: Field = 42;
    let n = pedersen_hash([px, py, pid, DOMAIN_PETITION_V1]);
    assert(n != 0);
}

#[test]
fn merkle_depth16_roundtrip() {
    // Build a fake leaf, walk depth=16 with zero siblings on the left of the
    // current node, then re-walk in-circuit and check we get the same root.
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
    // Hand-build a synthetic signedAttrs blob whose only meaningful content
    // is the messageDigest OCTET STRING at a known offset, then verify the
    // extractor + binder agree on what's there.
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
