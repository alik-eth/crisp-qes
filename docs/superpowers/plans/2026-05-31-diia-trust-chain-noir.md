# Diia Trust-Chain in `enroll_commit_v2` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Verify the Diia CA→leaf certificate chain in-circuit in the deployed `enroll_commit_v2` Noir circuit, closing the identity-authentication gap, on the existing UltraHonk/service/web/chain stack.

**Architecture:** Add a 2nd in-circuit ECDSA-P256 (Diia CA over the leaf TBS) + `sha256_var(leaf_tbs)` + a compile-time CA-key pin + leaf-SPKI↔`pubkey` binding, and move RNOKPP/DOB extraction onto the authenticated `leaf_tbs`. Reuses the circuit's existing `ecdsa_secp256r1` + `sha256_var` gadgets. Everything downstream (OPRF `M`, bound challenge, DLEQ/unblind, signing, on-chain) unchanged.

**Tech Stack:** Noir 1.0.0-beta.19 (`nargo`), Barretenberg `bb` 4.0.0 + `@aztec/bb.js` (UltraHonk, default/Poseidon flavor), vendored `noir-lang/sha256`. `@crisp-qes/sdk` `parseP7s` (exposes `leafTbsBytes`, `leafPubkeyOffset`, `subjectSerialOffset`).

**Spec:** `docs/superpowers/specs/2026-05-31-diia-trust-chain-noir-design.md`. **Branch:** `feat/diia-trust-chain` (off main; longfellow parked elsewhere).

---

## Task 1 — GATE-COUNT + MEMORY SPIKE (front-loaded gate)
**Why:** the 2nd ECDSA + `sha256_var(leaf_tbs)` ≈ doubles the circuit; iOS prove-memory is the one real risk. Measure before the full build.

- [ ] **Step 1:** On a throwaway copy (e.g. `circuits/enroll_commit_v2_spike/`), add to `main`: a `leaf_tbs: [u8; LEAF_TBS_LEN]` (+ `leaf_tbs_len`) input, `let e = sha256::sha256_var(leaf_tbs, leaf_tbs_len)`, and a 2nd `std::ecdsa_secp256r1::verify_signature(ca_x, ca_y, leaf_sig, e)` (`ca_x/y`, `leaf_sig` as inputs). Size `LEAF_TBS_LEN` to ~1536 (24-block headroom over the ~1203 B Diia leaf TBS).
- [ ] **Step 2:** `nargo info` (or `nargo compile` + `bb gates`) on the spike circuit → **record the ACIR/UltraHonk gate count**. Compare to the deployed ~2¹⁹ (276,910). This is the cheap first verdict.
- [ ] **Step 3 (GATE):** If gates ≈ ≤2²⁰ and within the iOS budget heuristic, proceed. If much larger, run a bb.js prove with a dummy-but-valid-sized witness and read peak memory (reuse `bench/v2-mem-floor.mjs`-style harness) to get the real iOS number. Record the verdict (desktop/Android/iOS) in the spec. If it blows iOS, decide: ship chain-check on desktop/Android + lighter iOS path, vs optimize.
- [ ] **Step 4:** Remove the throwaway spike circuit (keep the measurement in the spec).

## Task 2 — implement the 5 additions in `enroll_commit_v2`
**Files:** `circuits/enroll_commit_v2/src/main.nr`.
- [ ] **Step 1:** Add inputs `leaf_tbs[LEAF_TBS_LEN]`, `leaf_tbs_len`, `ca_pubkey_x/y[32]`, `leaf_cert_sig[64]`, `leaf_spki_off`, and move `rnokpp_oid_off`/`dob_off` to index into `leaf_tbs`. Drop the free `cert[]`.
- [ ] **Step 2:** `let e = sha256::sha256_var(leaf_tbs, leaf_tbs_len); assert(verify(ca_pubkey_x, ca_pubkey_y, leaf_cert_sig, e))`.
- [ ] **Step 3:** Pin CA set — `global DIIA_CA: [( [u8;32],[u8;32] ); 2] = [..-2311.., ..-2503..]`; assert `(ca_pubkey_x, ca_pubkey_y)` equals one of them (OR over the 2 entries, byte-equality).
- [ ] **Step 4:** Extract leaf SPKI point from `leaf_tbs` at `leaf_spki_off`; assert `== (pubkey_x, pubkey_y)` (the `signed_attrs` ECDSA key).
- [ ] **Step 5:** RNOKPP + DOB extraction now read `leaf_tbs` (authenticated). Keep the existing OID/`TINUA-`/digit + DOB asserts, retargeted.
- [ ] **Step 6 (tests):** Noir `#[test]`s — happy path proves; negatives FAIL: `leaf_tbs` not CA-signed; `ca_pubkey` ∉ pinned set; `pubkey` ≠ leaf SPKI; RNOKPP digits read from outside the signed region.

## Task 3 — witness generators (synthetic test CA + web)
**Files:** `gen-enroll-commit-v2-witness.mjs`, `packages/web/src/lib/p7sWitness.ts`.
- [ ] **Step 1:** Synthetic witness: a test CA keypair signs a synthetic leaf TBS (carrying RNOKPP+DOB+leaf SPKI); emit `leaf_tbs`, `leaf_cert_sig`, `ca_pubkey` (one of the pinned for the real path; the synthetic test CA for dev — see note), offsets. For dev tests the pinned set must include the synthetic test CA OR the test selects it; coordinate with Task 2 Step 3 (add a dev-only test anchor or a feature flag).
- [ ] **Step 2:** `p7sWitness.ts`: from `parseP7s` emit `leaf_tbs` (`leafTbsBytes`), `leaf_cert_sig`, `ca_pubkey` (the issuing Diia CA key), `leaf_spki_off` (`leafPubkeyOffset`), and the RNOKPP/DOB offsets into `leaf_tbs`. Local pre-check that the leaf verifies under a pinned Diia CA.

## Task 4 — regen fixtures/VK + E2E + iOS measure
- [ ] **Step 1:** Regenerate `target/{proof,public_inputs,vk,vk_hash}` (default flavor) via the service fixture path; the proof's public outputs (`M`, digest) are unchanged.
- [ ] **Step 2:** E2E: enroll (real-shaped synthetic cert) → service verify → sign on Base Sepolia, unchanged downstream.
- [ ] **Step 3:** Real bb.js prove-memory on iOS Safari / Android / desktop with the full circuit; record the ship-surface verdict.

---

## Exit criteria
1. `enroll_commit_v2` proves the Diia CA→leaf→challenge chain; the four negatives fail-closed.
2. RNOKPP/DOB read from the authenticated `leaf_tbs`; `pubkey` bound to the leaf SPKI; `ca_pubkey` pinned.
3. OPRF/challenge/signing paths unchanged; E2E green.
4. Gate count + iOS prove-memory measured and recorded.

## Self-review notes
- **No new proving system** — same UltraHonk gadgets; the risk is *circuit size/iOS memory*, front-loaded in Task 1.
- **Reuse:** longfellow build already confirmed the P-256 chain + captured the real CA keys + validated the gadget shape.
- **Test-CA wrinkle:** the synthetic dev fixture can't be signed by the real Diia key; either pin a dev anchor selectable in tests or feature-flag it — resolve in Task 3 Step 1 without weakening the production pinned set.
