# Diia Trust-Chain in `enroll_commit_v2` (Noir) — Design

**Date:** 2026-05-31
**Status:** Draft for user review
**Scope:** Close the identity-authentication gap in the **deployed** v3 operator-blind enrollment circuit by verifying the Diia CA→leaf certificate chain **in-circuit**. Reuses the deployed Noir/UltraHonk stack, service, web, and chain — no new proving system.
**Supersedes:** the parked longfellow OPRF migration (`docs/superpowers/PARKED-longfellow-oprf.md`) as the active direction.

---

## 1. The gap (why this is the whole point, not a minor add)

Today `enroll_commit_v2` proves: ECDSA over `signed_attrs` under a **free** `pubkey`, RNOKPP/DOB read from a **free** `cert[]` buffer, `M = r·H2C(rnokpp)`, and the bound-challenge `messageDigest`. **Nothing binds `cert[]` or `pubkey` to a real Diia cert** — a prover can supply any RNOKPP in a fabricated `cert[]`, signed by their own keypair, and pass every assertion. The bound challenge only proves "*someone* signed it." So **enrollment identity is currently self-asserted** (the cert/keys are unauthenticated). This is the soundness hole this design closes.

The longfellow build (now parked) confirmed the facts that make the fix tractable: the Diia chain is **ECDSA-P256** end to end, and the real **QTSP CA public keys** (`UA-43395033-2311`, `-2503`) are captured.

## 2. Design — 5 additions to `enroll_commit_v2`

Proves the chain **Diia CA → leaf TBS (carries RNOKPP + DOB + leaf SPKI) → leaf key signs the challenge**, all in one proof, reusing the circuit's existing gadgets (`std::ecdsa_secp256r1`, vendored `sha256::sha256_var`):

1. **Add `leaf_tbs: [u8; LEAF_TBS_LEN]` + `leaf_tbs_len`** — the leaf certificate's signed TBS bytes (~1203 B for Diia; `LEAF_TBS_LEN` sized with headroom, `sha256_var` digests exactly `leaf_tbs_len`).
2. **Second ECDSA**: `assert(verify(ca_pubkey_x, ca_pubkey_y, leaf_cert_sig, sha256_var(leaf_tbs, leaf_tbs_len)))` — proves the leaf TBS is CA-signed.
3. **Pin the CA key to the Diia root set**: `ca_pubkey ∈ { -2311, -2503 }` — a compile-time pinned set; assert the supplied `ca_pubkey` equals one of the pinned entries (a small in-circuit membership / OR over the constant set).
4. **Bind the signed_attrs key to the cert (`cert↔pubkey`)**: extract the leaf SPKI (the P-256 point) from `leaf_tbs` at a witnessed `leaf_spki_off`, assert `== (pubkey_x, pubkey_y)` (the key already used for the `signed_attrs` ECDSA). Now the key that signed the challenge is provably the cert's key.
5. **Read RNOKPP + DOB from `leaf_tbs`** (authenticated) instead of the free `cert[]`: move the OID/`TINUA-`/digits + DOB extraction to `leaf_tbs` at witnessed offsets. Drop the free `cert[]` input.

Everything downstream is unchanged: RNOKPP → `H2C` → `M = r·H2C`, the bound-challenge `messageDigest`, DLEQ/unblind (`oprf_nullifier`), Merkle leaf, signing, on-chain — all identical. Only the *cert-authentication* front of `enroll_commit_v2` changes.

## 3. Decisions (locked)

| Decision | Choice | Rationale |
|---|---|---|
| CA root-set representation | **Compile-time pinned set** of the 2 Diia keys | Simplest; recompile to rotate. On-chain admin-settable Merkle commitment (rotation without recompile) is a later enhancement (§8.1 doc note). |
| Build sequencing | **Gate-count + bb.js prove-memory spike FIRST** | The 2nd ECDSA + `sha256_var(leaf_tbs)` ≈ doubles the circuit (~2¹⁹→~2²⁰); iOS prove-memory is the one real risk. Measure before full build. |
| Proving stack | **Unchanged** — Noir/UltraHonk, deployed service/web/chain | This is the whole point of the pivot: reuse the working, all-platform system. |
| Test CA | **Synthetic test CA** for dev fixtures; real Diia keys pinned but exercised only by the user's real `.p7s` (out-of-band, PII) | Can't sign a synthetic cert with the real Diia key. Same pattern the longfellow build used. |

## 4. Cost & risk — SPIKE MEASURED (2026-05-31)

**Gate-count spike result (Task 1):** added the 2nd ECDSA + `sha256_var(leaf_tbs[1536])` to a throwaway copy and measured via `bb gates`:

| | gates (`circuit_size`) | ACIR opcodes | UltraHonk domain |
|---|---|---|---|
| Deployed (iOS-capable today) | 276,910 | 18,890 | 2¹⁹ = 524,288 |
| **+ Diia chain check** | **459,519** | 28,011 | **2¹⁹ = 524,288 (unchanged)** |

The chain check adds ~183k gates (1.66×) **but stays inside the same 2¹⁹ proving domain.** UltraHonk pads to the next power of two and prover memory is dominated by the padded domain size — so the **prover-memory class is essentially unchanged from the deployed iOS-capable circuit.** The feared ~2²⁰ jump does **not** happen: 459,519 < 524,288. So **iOS is very likely preserved** (no domain increase), and **desktop/Android are not at risk**. This is a strong contrast to the parked longfellow path (2.81 GiB, loses iOS).

**Remaining confirmation:** the definitive bb.js peak-RSS on a real iOS device (Task 4 Step 3) — but the structural signal (same 2¹⁹ domain) is strong. If a future tighter `LEAF_TBS_LEN` is wanted, the real Diia leaf TBS is ~1203 B (20 blocks); the spike used 1536 (24-block headroom) and still fit 2¹⁹.
- **No new proving system, service rewrite, or web rewrite** — the witness builder gains `leaf_tbs`/`leaf_cert_sig`/`ca_pubkey`/offsets (from `@crisp-qes/sdk` `parseP7s`, which already exposes `leafTbsBytes`, `leafPubkeyOffset`, `subjectSerialOffset`).

## 5. Components touched
- `packages/oprf/v3-grumpkin/circuits/enroll_commit_v2/src/main.nr` — the 5 additions.
- `packages/oprf/v3-grumpkin/gen-enroll-commit-v2-witness.mjs` — synthetic witness gains the CA chain (synthetic test CA signs the leaf TBS) + offsets.
- `packages/web/src/lib/p7sWitness.ts` — emit `leaf_tbs`/`leaf_cert_sig`/`ca_pubkey`/`leaf_spki_off` from `parseP7s`.
- `packages/oprf/v3-grumpkin/service/*` — regenerate fixtures/VK; no protocol change (the proof's public outputs are unchanged: `M`, digest).
- Fixtures + VK regen.

## 6. Out of scope
- On-chain admin-settable CA root commitment (later).
- Multi-country (this is the UA/Diia chain; the structure generalizes but only UA is pinned).
- Any longfellow work (parked).

## 7. Success criteria
1. The circuit proves the full Diia CA→leaf→challenge chain; a fabricated `leaf_tbs` not signed by a pinned Diia CA, or a `pubkey` ≠ the cert SPKI, **fails closed**.
2. RNOKPP/DOB are read from the authenticated `leaf_tbs`.
3. The bound-challenge + OPRF + signing paths are unchanged and still pass E2E.
4. Gate count + bb.js prove-memory measured; iOS ship-surface decision recorded.
