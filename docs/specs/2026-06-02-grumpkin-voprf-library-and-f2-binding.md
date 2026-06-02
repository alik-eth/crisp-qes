# Grumpkin VOPRF — reusable Noir library + F2 binding fix (design)

**Date:** 2026-06-02
**Status:** Design (approved direction: fuse via library extraction). Implementation sequences AFTER the F1+F3 pin fixes land (it inherits F1's pinned `G` and F3's pinned `c1..c4`).
**Source:** `docs/2026-06-02-voprf-security-review.md` (finding **F2**, plus the **C-3** residual), and the reuse requirement: VOPRF(Grumpkin) must remain packageable as a Noir library/module for CRISP / Interfold / other consumers.

## 1. Goal

Close **F2** (critical): in `oprf_nullifier`, `r`/`rinv` are free witnesses and only `r·N==Y` is checked, so `rinv` is not tied to the enrollment blind `r_enroll` → a prover mints unbounded distinct nullifiers from one identity (Sybil). Do it in a way that **also packages the VOPRF as a reusable Noir library** so the binding (and F1/F3/C-1) are enforced once and inherited by every consumer.

## 2. Key principle: fusion = shared `r`, achieved by composition (not a monolith)

The binding requirement is only that the **same `r` witness** drives both the blind (`M = r·H2C(id)`) and the unblind (`N = rinv·Y` with `r·rinv ≡ 1`). That is achieved by composing library functions inside the application circuit and threading one `r` — NOT by inlining VOPRF logic into the app-specific `main()`. So we extract a `grumpkin_voprf` Nargo package and have the app circuit call it.

The library exposes **one entry point that takes `r` exactly once**, making the same-`r` binding a property of the function signature (a caller cannot supply two different blind/unblind scalars):

```
// grumpkin_voprf::oprf — reusable, application-agnostic
pub fn oprf_verify_and_nullify(
    h2c_point: Pt,         // H2C(identity), supplied by the app
    r: Scalar, rinv: Scalar,
    kpub: Pt, y: Pt,
    dleq: Dleq,            // { c_lo,c_hi, z_lo,z_hi }
) -> Field {
    let m = scalar_mul(r, h2c_point);            // blind
    verify_dleq(GEN, kpub, m, y, dleq);          // F1 (pinned GEN) + C-1 (limb-bound challenge)
    assert_scalar_inverse(r, rinv);              // F2 + C-3: r·rinv ≡ 1 (mod n), range-checked limbs
    let n = scalar_mul(rinv, y);                 // unblind: N = r_enroll^-1 · k · r_enroll · H2C(id) = k·H2C(id)
    std::hash::pedersen_hash([n.x, n.y])         // raw nullifier; app may scope it
}
```

`m` is also returned (or recomputable as `r·h2c_point`) when the app needs `M` as a public output for the node.

## 3. Library layout (`grumpkin_voprf` Nargo package)

```
packages/oprf/v3-grumpkin/lib-noir/grumpkin_voprf/
  Nargo.toml                      # name = "grumpkin_voprf", type = "lib"
  src/lib.nr                      # re-exports the modules below
  src/params.nr                   # PINNED constants as globals (F1+F3):
                                  #   GEN_X, GEN_Y (canonical Grumpkin generator)
                                  #   SVDW_C1..C4, SVDW_Z, ZETA, BCURVE, DST
  src/h2c.nr                      # h2c_grumpkin(u0,u1, hints) -> Pt  (RFC-9380 SvdW; hint-verified)
  src/dleq.nr                     # verify_dleq(G, Kpub, M, Y, dleq)  (C-1 limb-bound Fiat-Shamir)
  src/scalar.nr                   # assert_scalar_inverse(r, rinv): range-check limbs + r·rinv ≡ 1 mod n
  src/oprf.nr                     # oprf_verify_and_nullify(...) (the single-`r` entry point)
```

**In the library (reusable, no application assumptions):** pinned curve/suite params, hash-to-curve, DLEQ verification (works for a single-node `Kpub` **and** a threshold Lagrange-combined `Kpub` — same shape), the inverse-binding, the unblind, and the raw `pedersen(N)` nullifier.

**NOT in the library (stays app-side):** Diia cert chain, age≥18, RNOKPP→`u0,u1` hashing, bound-challenge / `messageDigest`, petition-scoping (`pedersen([N, petition_id, domain])`), and the public-IO shape. The library returns the raw `N`/`pedersen(N)`; the app scopes/embeds it.

## 4. Application refactor (`enroll_commit_v2`)

`enroll_commit_v2` keeps all its enrollment logic and changes only the OPRF portion:
- add `grumpkin_voprf` as a Nargo dependency;
- compute `h2c_point = grumpkin_voprf::h2c::h2c_grumpkin(u0, u1, hints)` (replacing its inlined SvdW maps);
- add inputs `Kpub, Y, dleq, rinv` (G is the library's pinned global; not an ABI input);
- call `nullifier = grumpkin_voprf::oprf::oprf_verify_and_nullify(h2c_point, r, rinv, Kpub, Y, dleq)` using the **same `r`** it already uses to derive `M`;
- expose `M` and `nullifier` (and existing `messageDigest`) as public outputs.

This collapses enrollment-proof + nullifier-proof into one proof.

## 5. Disposition of existing circuits

- `oprf_commitment` and `oprf_nullifier` standalone circuits are **retired as production artifacts** and re-expressed as **thin test wrappers** over the library (so the library has direct unit-level forgery/honest tests independent of the app). Confirm during implementation that nothing outside the enroll flow consumes `oprf_nullifier` (assumption to verify).
- `qes_frontend` (sign circuit) is unaffected.

## 6. Protocol / client / service changes (2 proofs → 1)

- **Client** (`v3prove.worker`, `v3enroll.ts`, `p7sWitness.ts`): generate ONE fused proof. Proving must occur **after** `/v3/blind-eval` (it needs `Y`+DLEQ); confirm the worker ordering. Thread the same `r` used for `M` into the fused witness.
- **Service** (`proof-gate.mjs`, `server.mjs`): `/v3/blind-eval` unchanged (issues `Y`+DLEQ+`Kpub`); `/v3/register` verifies ONE proof instead of two; the challenge/`messageDigest` binding check stays. Off-chain bb.js verify re-derives the VK from bytecode at boot → no VK-artifact regen, no on-chain redeploy.
- **Determinism preserved:** `nullifier = pedersen(k·H2C(id))` is unchanged per identity → deterministic-commitment **recovery flow still works**, existing on-chain leaves stay valid, **no user migration**.

## 7. Reuse for CRISP / Interfold

A consumer circuit adds `grumpkin_voprf = { path = "..." }` (or a git/registry dep) to its `Nargo.toml` and calls `oprf_verify_and_nullify(...)` after computing its own `H2C(id)` (or reuses `h2c_grumpkin`). It **inherits F1 (pinned G), F3 (pinned c1..c4), C-1 (limb-bound DLEQ), and F2 (single-`r` inverse binding)** with no way to opt out. Threshold deployments pass the Lagrange-combined `Kpub`; the DLEQ shape is identical.

## 8. Security properties (enforced inside the library)

- **F1**: DLEQ base `G` is the library's pinned global — no attacker-chosen base.
- **F3**: SvdW `c1..c4` (+ `SVDW_Z`, DST) are library globals — hash-to-curve cannot be redefined.
- **C-1**: DLEQ challenge limbs bound to `pedersen(transcript)`, range-checked (carried over verbatim).
- **F2 + C-3**: `assert_scalar_inverse(r, rinv)` enforces `r·rinv ≡ 1 (mod n)` on range-checked limbs, and `r` is supplied once → the unblind is tied to the blind. Keep `r·N==Y` as defense-in-depth.

## 9. Testing

- **Library-level (new):** forgery witnesses must be REJECTED — (a) substituted `G`, (b) substituted `c1..c4`, (c) **`rinv` not equal to `r⁻¹`** (the F2 case, accepted by today's `oprf_nullifier`), (d) the C-1 free-`z`/limb forgery. Honest witness ACCEPTED.
- **App-level:** fused `enroll_commit_v2` — honest e2e accepted; the F2 forgery rejected; **the produced nullifier equals the old two-proof path's nullifier for the same identity** (regression → recovery intact).
- **iOS budget:** measure gate count + on-device prover memory for the fused circuit (see Risks).

## 10. Risks

1. **iOS prover budget (gating).** `enroll_commit_v2` ~277k bb proving gates (~238 MB at the 384 MiB cap) + DLEQ/unblind (~+30k) → ~307k *estimated*. Expected ~260 MB, but MUST be measured on-device — the spike was intentionally skipped, so this is verified during implementation; if it exceeds the cap, mitigations are SA_LEN reduction or, as a fallback, Approach A (cross-circuit commitment, keeping circuits separate).
   - **Measured (Task 2, commit 272eb31):** the fusion adds only **+382 ACIR opcodes (26,809 → 27,191, +1.4%)** — the dominant cost (ECDSA-P256 + 4× SHA-256 blocks) is unchanged, and h2c/DLEQ/unblind are cheap by comparison. NOTE the unit: `nargo info` reports **ACIR opcodes**, not bb proving gates — the ~307k figure above is bb gates. The tiny ACIR delta strongly implies the bb-gate delta (and thus the iOS memory delta) is also small, but the **true bb gate count and on-device bb.js prover memory against the 384 MiB cap remain a Task 6 measurement** (see §6 / out-of-scope). No iOS-budget concern at the ACIR level; on-device unconfirmed.
2. **Library calling convention.** The single-`r` entry point makes same-`r` structural, but a consumer must still pass an `r` consistent with the `M` it commits/signs upstream; document this.
3. **Client proof-ordering** change (prove after blind-eval).

## 11. Out of scope (tracked separately)

- Threshold OPRF hardening (per-share + combined DLEQ verification, session binding) — review checklist #7.
- **F4** (salt-free enrollment leaf) — has a design tension with deterministic-commitment recovery; separate decision.
- Randomness hygiene (#6), on-curve/non-identity input checks (#5).
- External audit (the production gate).
