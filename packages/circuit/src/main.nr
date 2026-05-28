// CRISP-QES eligibility circuit (MVP skeleton).
//
// Proves: a Ukrainian Diia QES holder signed a specific petition,
// without revealing tax-ID or which cert was used, while emitting
// a per-petition nullifier that is unique within cert lifetime and
// unlinkable across petitions.
//
// MVP scope: Diia is the only supported QTSP. The pubkey-nullifier scheme
// (see assert below) only resists Sybil because Diia issues a single active
// cert per citizen at a time. Admitting additional QTSPs would let a citizen
// present distinct pubkeys under different trust roots and re-sign the same
// petition. Multi-QTSP is a v2 concern (see spec section 5, "Out of scope").
//
// See docs/specs/2026-05-19-crisp-qes-pivot-design.md section 2.1.
//
// Public signals:
//   petition_id    : binds the proof to a petition
//   nullifier      : Poseidon(pubkey.x, pubkey.y, petition_id, DOMAIN)
//   trust_root     : pinned Diia trusted-CA Poseidon Merkle root
//   chain_bindings : keccak256(petition_id, relayer_or_signer_addr); may be 0
//
// Private signals (kept in main(...) args below):
//   p7s_bytes, leaf_cert, intermediate_cert,
//   pubkey_x, pubkey_y,
//   subject_serial (must start with "TINUA-"),
//   sig_r, sig_s,
//   merkle_path (leaf-cert commit -> trust_root).

global DOMAIN_PETITION_V1: Field = 0x0c0915920b3d3ee18f1e4a2b00000000;

fn main(
    // ---- public ----
    petition_id: pub Field,
    nullifier: pub Field,
    trust_root: pub Field,
    chain_bindings: pub Field,
    // ---- private ----
    // Sizes are placeholders - finalize when wiring real .p7s fixtures.
    _p7s_bytes: [u8; 2048],
    _leaf_cert: [u8; 1024],
    _intermediate_cert: [u8; 1024],
    pubkey_x: Field,
    pubkey_y: Field,
    _subject_serial: [u8; 32],
    _sig_r: Field,
    _sig_s: Field,
    _merkle_path: [Field; 16],
) {
    // TODO(circuit): CAdES walk, signedAttrs digest binding to
    // SHA256(petition_id || "::" || petition_text_hash).
    // TODO(circuit): P-256 ECDSA verify over signedAttrs.
    // TODO(circuit): Merkle membership of leaf-cert commit in trust_root.
    // TODO(circuit): assert subject_serial starts with b"TINUA-".

    // Nullifier = Pedersen(pubkey.x, pubkey.y, petition_id, DOMAIN).
    // Pedersen (not Poseidon) is the chosen MVP hash; the SDK must compute
    // the same Pedersen off-chain so the signer can preview their nullifier
    // before submission.
    let expected = std::hash::pedersen_hash(
        [pubkey_x, pubkey_y, petition_id, DOMAIN_PETITION_V1]
    );
    assert(nullifier == expected);

    // chain_bindings is opaque to the circuit; verifier contract checks it.
    let _ = chain_bindings;
    let _ = trust_root;
}

#[test]
fn smoke_nullifier_binding() {
    let px: Field = 1;
    let py: Field = 2;
    let pid: Field = 42;
    let n = std::hash::pedersen_hash([px, py, pid, DOMAIN_PETITION_V1]);
    main(pid, n, 0, 0, [0; 2048], [0; 1024], [0; 1024], px, py, [0; 32], 0, 0, [0; 16]);
}
