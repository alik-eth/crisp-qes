# Longfellow + In-Circuit P-256 OPRF Enrollment — Design

**Date:** 2026-05-31
**Status:** Draft for user review
**Supersedes (at enrollment only):** the v3 Grumpkin `enroll_commit_v2` + `oprf_nullifier` Noir/UltraHonk enrollment path.
**Leaves unchanged:** the on-chain `PetitionRegistryV2`, the passkey vault, and the Noir/UltraHonk **signing** circuit (membership + `pedersen` nullifier).

---

## 1. Summary

Replace crisp-qes's enrollment prover with a single **longfellow** proof that verifies a real Diia QES certificate *and* runs a verifiable OPRF **in-circuit on P-256**, producing the same kind of opaque 32-byte enrollment leaf `s` the existing signing/registry stack already consumes.

This buys three things crisp-qes does not have today, in one move:

1. **Real Diia trust-root verification (§8.1)** — the cert is proven to chain to a pinned Diia QTSP CA root, in-circuit (`p7s_zk/trust_anchors.rs` + invariant 1). Today's circuit verifies the leaf signature but not its issuer chain.
2. **Multi-country readiness** — the p7s circuit already supports variable-length `serialNumber` ("pan-eIDAS"); each country is a trust-anchor set + extraction offsets, matching the per-country-circuit design doc.
3. **Unguessable, operator-blind, deterministic Sybil secret** — the OPRF output `s = SHA256(k·H2C(rnokpp))` is deterministic per RNOKPP (one leaf per identity) yet unguessable without the server key `k`, so the public on-chain leaf never deanonymizes an RNOKPP. This replaces longfellow's stock `enroll_nullifier = SHA256(stable_id)`, which is brute-forceable across the ~10¹⁰ RNOKPP space.

No trusted setup; post-quantum (SHA-256 + Ligero); prover runs in-browser via WASM, so the `.p7s` and RNOKPP never leave the device (operator-blind preserved).

---

## 2. Decisions locked in brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| OPRF ↔ proof binding | **In-circuit, one proof** | Strongest binding; no cross-proof bridge to trust; OPRF lives entirely in the longfellow fork. |
| OPRF curve | **P-256 (secp256r1)** | Same curve as the Diia cert ECDSA; reuses the in-circuit scalar-mul; only new primitive is P-256 hash-to-curve. Grumpkin would require porting a new field into the C++ builder. |
| Proof topology | **Single proof, generated *after* the blind-eval round** | The OPRF is a 1-round interaction (M must be sent before eval), but only one *proof* is produced, covering `cert → RNOKPP → M → eval → unblind → s`. |
| Repo topology | **Vendor both longfellow repos as submodules under `vendor/`; develop here** | Rust prover (`vendor/longfellow-rs`, dev target) + C++ circuit-builder (`vendor/longfellow-zk`, build-time circuit-gen). |
| Build sequencing | **Memory-measurement spike first** | iOS WASM memory ceiling is the dominant risk; measure before committing to the full build. |
| On-chain verification | **Unchanged — Noir/UltraHonk signing on Base Sepolia** | SP1 wrap is abandoned (tried, did not work). Longfellow proofs are verified **off-chain** by the OPRF service; only `s` reaches the chain. |

---

## 3. Architecture

### 3.1 Components

```
crisp-qes/
  vendor/
    longfellow-rs/      # submodule — pure-Rust prover+verifier (WASM target). Dev target.
    longfellow-zk/      # submodule — C++ circuit-builder. Build-time circuit generation only.
  packages/
    oprf/               # P-256 OPRF service (blind-eval + DLEQ); replaces Grumpkin service.
    web/                # enrollment UI loads the longfellow WASM prover.
    relayer/            # unchanged — appends leaf s, submits sign proofs.
    contracts/          # unchanged — PetitionRegistryV2.
    circuit/            # unchanged — Noir/UltraHonk signing circuit.
```

- **`vendor/longfellow-zk` (C++):** the only layer that can *build* circuits. We add the new in-circuit gadgets here and emit a serialized circuit artifact (`p7s_oprf_v1.circuit`).
- **`vendor/longfellow-rs` (Rust):** *evaluates* the serialized circuit, fills witnesses, runs Sumcheck+Ligero, and exposes prove/verify to JS via `wasm-bindgen`. We add the new witness-fill regions here.
- The serialized circuit artifact is committed (or built in CI from `longfellow-zk`) and loaded by both the WASM prover and the service verifier.

### 3.2 Enrollment data flow

```
1. Client (browser):
     parse .p7s → (RNOKPP, DOB, leaf cert DER, signedAttrs, sig, pubkey)
     pick blind scalar r ∈ Z_n(P-256)
     M = r · H2C_P256(rnokpp)                         # SSWU hash-to-curve + scalar-mul
2. Client → Service:  { M }                            # blinded; reveals nothing about rnokpp
3. Service:
     Y = k · M                                         # k = P-256 OPRF secret key
     return { Y, K = k·G, dleq = (c, z) }              # Chaum–Pedersen DLEQ over P-256
4. Client:
     check DLEQ(M, Y, K)                               # local sanity (also re-checked in-circuit)
     N = r⁻¹ · Y   (= k · H2C(rnokpp))                 # unblind
     s = SHA256(N.x ‖ N.y)  reduced into BN254 field   # the enrollment leaf
5. Client: generate ONE longfellow proof π (in-circuit):
     (a) cert ECDSA-P256 verifies over signedAttrs
     (b) leaf cert chains to pinned Diia QTSP CA root        # §8.1
     (c) RNOKPP extracted from cert DER (var-len serialNumber)
     (d) age ≥ 18 from DOB vs public `today`
     (e) M = r · H2C_P256(rnokpp)
     (f) DLEQ holds: Y = k·M under pinned/public K           # no fake-eval Sybil
     (g) r · N = Y   AND   s = SHA256(N.x ‖ N.y)             # group-eqn unblind, no in-circuit inverse
   public inputs/outputs: { K, Y, today, trust_anchor_index, s }
   private: { cert, signedAttrs, sig, pubkey, rnokpp, dob, r, N }
6. Client → Service: { π, public inputs }
     Service verifies π (off-chain, ~350 KB Ligero). On success → relayer appends s.
7. Relayer: append leaf s to PetitionRegistryV2 Merkle tree.
     Duplicate s ⇒ AlreadyEnrolled (Sybil rejection / recovery path).
8. Client: seal the enrollment secret (s and/or N material) in the passkey vault (unchanged).
```

**Why the DLEQ must be in-circuit (step f):** if `Y` were merely a public input not constrained to `k·M`, a client could substitute a different `Y' = k'·M` (any `k'` it knows) and derive a *different* valid `s` for the same RNOKPP — minting multiple leaves per identity (Sybil). Verifying the DLEQ against the pinned server pubkey `K` inside the proof forecloses this. (This mirrors today's `oprf_nullifier` DLEQ check, now folded into the single proof.)

**Why unblind by group equation (step g):** asserting `r · N == Y` proves `N` is the correct unblind without computing a modular inverse `r⁻¹` in-circuit (same trick the current Grumpkin `oprf_nullifier` uses).

### 3.3 Bound-challenge UX carries over

The shipped v2-style UX (enter RNOKPP → download a challenge → sign it in Diia → upload `.p7s`) is preserved. The challenge still embeds `M` (computable client-side once `r` is chosen). The difference: the binding of "the Diia signature covers this `M`" is now proven **in-circuit** (the cert's `signedAttrs`/messageDigest path + `M = r·H2C(rnokpp)`), rather than enforced by the service's digest comparison. The `epoch`/`intent` framing is retained in the signed content.

### 3.4 What changes vs. stays

**Changes:**
- New `vendor/` submodules (Rust prover, C++ builder).
- New in-circuit gadgets: P-256 SSWU hash-to-curve; DLEQ verify; scalar-mul wiring for `M`, `r·N`; the §8.1 trust-anchor chain check pinned to real Diia roots.
- OPRF service: P-256 key + blind-eval + DLEQ (replaces the Grumpkin service); off-chain longfellow proof verification.
- Web: replace the `enroll_commit_v2` Noir worker with the longfellow WASM prover + a P-256 `.p7s` witness builder.

**Stays exactly as-is:**
- `PetitionRegistryV2` and all contracts.
- The Noir/UltraHonk **signing** circuit and its on-chain verifier — `s` is an opaque 32-byte field to it.
- The passkey-vault sealing/unlock flow.
- The relayer's append/sign/nonce-queue machinery.

---

## 4. The new in-circuit gadgets (the core engineering)

All in `vendor/longfellow-zk/lib/circuits/` (C++ builder), then witness-filled in `vendor/longfellow-rs`:

1. **P-256 hash-to-curve (SSWU, RFC 9380 `P256_XMD:SHA-256_SSWU_RO_`).** New. `expand_message_xmd(SHA-256)` already has SHA primitives in the p7s circuit; add the SSWU `map_to_curve` + `clear_cofactor` (cofactor 1 for P-256, so trivial). Output: `H2C(rnokpp)` as an affine point.
2. **Variable-base scalar-mul.** The ECDSA gadget (`circuits/ecdsa/verify_witness.h::scalar_multf`) already does in-circuit MSM; reuse/parameterize it for `M = r·H2C(rnokpp)` and the DLEQ recomputations.
3. **DLEQ verify.** Recompute `a1 = z·G − c·K`, `a2 = z·M − c·Y`, Fiat–Shamir `c' = H(transcript)`, assert `c' == c`. (Same structure as `oprf_nullifier`, ported to P-256/longfellow's field + SHA-256 transcript.)
4. **Unblind + leaf.** Assert `r·N == Y`; compute `s = SHA256(N.x ‖ N.y)`; expose `s` (reduced into BN254 field so it is a valid Noir-side Merkle leaf).
5. **§8.1 trust-anchor chain.** Wire `trust_anchor_index` to the **real Diia QTSP CA pin set** (the P-256 keys captured in `docs/specs/2026-05-31-multi-country-per-circuit-design.md`).

---

## 5. OPRF service (P-256)

- Holds the P-256 OPRF secret `k`; publishes `K = k·G`.
- `POST /blind-eval { M } → { Y = k·M, K, dleq }` with a Chaum–Pedersen DLEQ.
- `POST /register { π, public } → verify π off-chain → relayer append s`.
- Key custody, rotation, and epoching follow the existing v3 service patterns (epoch label in the signed challenge).
- Anti-DoS rate-limit on `/blind-eval` (Sybil is enforced at the leaf, not here).

---

## 6. Error handling

- **DLEQ check fail (client):** abort before proving; surfaced as "OPRF server response invalid."
- **Proof verify fail (service):** `ProofRejected` (same surface as today).
- **Duplicate leaf:** `AlreadyEnrolled` → recovery path (fetch existing path, skip append) — unchanged.
- **Cert chain / trust-anchor mismatch:** in-circuit assertion failure → proving fails locally with a labelled error ("certificate does not chain to a recognized Diia CA").
- **Age < 18:** in-circuit assertion failure → age-gate error.
- **iOS memory exhaustion:** detected by the spike; fallback is desktop/Android-first with iOS as a tracked follow-up.

---

## 7. Testing strategy

- **Gadget unit tests (Rust + C++):** SSWU known-answer vectors (RFC 9380 P-256 test vectors); DLEQ accept/reject; unblind `r·N==Y`; `s` KAT.
- **Circuit parity:** Rust verifier accepts C++-built proofs for the OPRF circuit (the migration's existing parity harness).
- **End-to-end (synthetic cert):** synthetic Diia-shaped P-256 cert chaining to a test anchor → full flow → `s` matches a host-side reference.
- **End-to-end (real cert, gitignored):** the real Diia `.p7s` fixture verifies + chains to the real pinned root; RNOKPP/DOB never echoed/committed.
- **WASM memory spike:** `prove`-in-browser peak via `wasm_memory_bytes()` on iOS Safari / Android Chrome / desktop.
- **Negative:** wrong anchor, tampered `signedAttrs`, swapped `Y`, under-18 DOB — all must fail.

---

## 8. Risks & open items

1. **iOS WASM prover memory (dominant risk).** Cert ECDSA + chain ECDSA + H2C + ~3 scalar-mults + DLEQ + SHA on top of the existing p7s circuit. Ligero keeps EC cheap in *time*; *peak memory* is the unknown. **Mitigation: the spike is task 1**; if it exceeds iOS's ceiling we ship desktop/Android-first.
2. **C++ circuit-builder work is unavoidable.** The Rust port cannot build circuits; the SSWU/DLEQ gadgets must be authored in `longfellow-zk` and re-serialized. This is the bulk of the effort.
3. **Submodule extraction.** `vendor/longfellow-rs` is created as a standalone repo **`alik-eth/longfellow-rs`** (confirmed), seeded from `alik-eth/zk-eidas@worktree-longfellow-rust-migration:crates/longfellow` (preserving the 59-test p7s work + `abetterinternet` provenance), then added as a submodule.
4. **Proof size.** ~350 KB Ligero proof over HTTP to the service — fine (verified off-chain), but a UX note for slow links.
5. **Field reduction for `s`.** `SHA256(N)` is 256-bit; the Noir Merkle leaf is a BN254 field element (~254-bit). Reduce/mask deterministically and consistently on both prover and registry sides.
6. **OPRF key migration.** Standing up a P-256 OPRF service is a new key; existing Grumpkin enrollments do not carry over (clean-slate enrollment epoch, consistent with prior redeploys).

---

## 9. Out of scope

- SP1 / on-chain longfellow verification (abandoned).
- Porting the C++ circuit-builder to Rust (multi-month; deferred).
- Other countries beyond UA (the architecture supports them; only UA anchors are pinned now).
- Changes to the signing circuit, contracts, or vault.

---

## 10. Success criteria

1. A real Diia `.p7s` produces a longfellow proof, in-browser, that verifies off-chain and yields a leaf `s` accepted by the unchanged registry/signing path.
2. The proof fails for: a cert not chaining to a pinned Diia root; a tampered `signedAttrs`; a substituted `Y`; an under-18 DOB.
3. Two enrollments of the same RNOKPP produce the **same** `s` (deterministic Sybil), and `s` is not invertible to the RNOKPP without `k`.
4. Measured WASM prove peak memory recorded on iOS Safari, Android Chrome, and desktop; an explicit ship-surface decision follows from it.
