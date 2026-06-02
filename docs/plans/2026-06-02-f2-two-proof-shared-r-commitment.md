# F2 deploy — two proofs bound by shared-`r` commitment — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes. Sequences on top of the grumpkin_voprf library (commits 2bc0a3a/a7c9131) on branch `feat/voprf-security-fixes`.

**Goal:** Close F2 in the DEPLOYED v3 path while preserving the closed-oracle (gated blind-eval) privacy property, by keeping two proofs and binding the same blind `r` across them with `C_r = pedersen([r_lo, r_hi])`.

**Architecture:** `enroll_commit_v2` stays the blind-eval gate and additionally outputs `C_r`. `oprf_nullifier` (register) takes `C_r` as a public input, re-asserts it for its `r`, and (via the library) verifies the DLEQ against the pinned `GEN` (F1), unblinds, and enforces `r·N==Y` (F2). Both circuits compose `grumpkin_voprf` ⇒ inherit F1/F3/C-1/C-3. Threshold-ready: the DLEQ verifies against the published/combined `Kpub` unchanged.

**Spec:** `docs/specs/2026-06-02-f2-two-proof-shared-r-commitment.md`. **Tech:** Noir 1.0.0-beta.19 (`~/.nargo/bin/nargo`), @aztec/bb.js, Node ESM, React/TS client. ASCII-only in `.nr`. Fork rule: explicit `git add <files>`, never `-A`.

**Canonical test vectors (reuse across all tasks):** RNOKPP `"1234567890"`, `r = det("crisp-qes-test-r")`, `k = det("crisp-qes-node-secret-k")`; honest nullifier `0x06f310b1dbbcdbb45604e11517493552d7577117ced0985984078cf754fab227` (the recovery/regression anchor — must be unchanged everywhere).

---

### Task 1 — Library: `commit_r` + `oprf_nullify_bound` + tests

**Files:** `packages/oprf/v3-grumpkin/lib-noir/grumpkin_voprf/src/oprf.nr` (modify), `.../src/lib.nr` (tests).

- [ ] Add to `oprf.nr` (keep the existing `oprf_verify_and_nullify` for fused consumers):

```rust
// Binding commitment to the blind scalar r (the cross-proof link for the
// two-proof deployment). Pedersen-binding => two proofs sharing C_r share r.
// Range-checks the limbs so any committer (enroll + nullifier) gets C-3 for free.
pub fn commit_r(r: Scalar) -> Field {
    r.lo.assert_max_bit_size::<128>();
    r.hi.assert_max_bit_size::<128>();
    std::hash::pedersen_hash([r.lo, r.hi])
}

// Two-proof register entry point: verify the node's DLEQ and derive the nullifier,
// with the F2 binding done ACROSS proofs via C_r (the enroll proof published it).
// `m` is a public input here (the nullifier proof does not recompute r*H2C(id));
// the service cross-checks m == the enroll proof's M and c_r == the enroll C_r.
//   nullifier = pedersen([N.x,N.y]), N = k*H2C(id) when r == r_enroll (forced by C_r).
pub fn oprf_nullify_bound(
    m: Pt, y: Pt, kpub: Pt,
    r: Scalar, rinv: Scalar, c_r: Field,
    c_lo: Field, c_hi: Field, z_lo: Field, z_hi: Field,
) -> Field {
    rinv.lo.assert_max_bit_size::<128>();
    rinv.hi.assert_max_bit_size::<128>();
    // F2 cross-proof binding: this r is the SAME r the enroll proof committed to
    // (Pedersen binding). commit_r also range-checks r's limbs (C-3).
    assert(commit_r(r) == c_r);
    // Reject the point at infinity as an unblind input (explicit; the group eq
    // below compares only affine coords). Mirrors oprf_verify_and_nullify.
    assert(!y.is_infinite);
    // F1 + C-1: verify Y = k*M against the pinned generator.
    dleq::verify_dleq(kpub, m, y, c_lo, c_hi, z_lo, z_hi);
    // Unblind N = rinv*Y.
    let n = multi_scalar_mul([y], [rinv]);
    assert(!n.is_infinite);
    // F2: r*N == Y with r bound to enroll via C_r => rinv = r_enroll^-1 => N = k*H2C(id).
    let ycheck = multi_scalar_mul([n], [r]);
    assert((ycheck.x == y.x) & (ycheck.y == y.y));
    std::hash::pedersen_hash([n.x, n.y])
}
```

- [ ] In `lib.nr` add `#[test]`s (reuse the existing honest vectors module; compute the enroll-side `C_r` from `R_LO/R_HI`):
  - `test_commit_r_deterministic`: `commit_r(r()) == commit_r(r())` and equals a hardcoded expected value (capture it from the first compile).
  - `test_nullify_bound_honest`: with `m = (MX,MY)` (already in the test module), `c_r = commit_r(r())`, honest `kpub/y/dleq`, asserts result `== EXPECTED_NULLIFIER`.
  - `#[test(should_fail)] test_nullify_bound_wrong_cr`: pass `c_r = commit_r(r()) + 1` ⇒ the `commit_r(r)==c_r` assert fails.
  - `#[test(should_fail)] test_nullify_bound_f2_wrong_rinv`: honest `c_r` + `r`, but `rinv = RINV2` ⇒ `r·N==Y` fails.
  - `#[test(should_fail)] test_nullify_bound_dleq_inconsistent`: wrong `y` ⇒ C-1 fails.
- [ ] `cd lib-noir/grumpkin_voprf && ~/.nargo/bin/nargo test` — all pass (prior 6 + 5 new). `nargo compile` clean.
- [ ] Commit: `git add lib-noir/grumpkin_voprf/src/oprf.nr lib-noir/grumpkin_voprf/src/lib.nr` → `feat(grumpkin_voprf): add commit_r + oprf_nullify_bound (two-proof F2 binding)`.

### Task 2 — `enroll_commit_v2`: revert the fusion → two-proof + `C_r`

**Files:** `packages/oprf/v3-grumpkin/circuits/enroll_commit_v2/src/main.nr`.

- [ ] Revert the OPRF tail from the fused form (commit 272eb31) back to: compute `h2c = grumpkin_voprf::h2c::h2c_grumpkin(u0,u1,h0,h1)`, `let r = Scalar{lo:r_lo,hi:r_hi}`, `let m = multi_scalar_mul([h2c],[r])`. REMOVE the fused inputs `kpx,kpy,yx,yy,c_lo,c_hi,z_lo,z_hi,rinv_lo,rinv_hi` and the `oprf_verify_and_nullify` call.
- [ ] ADD `let c_r = grumpkin_voprf::oprf::commit_r(r);`.
- [ ] Return `-> pub (Field, Field, Field, Field, Field)` = `(m.x, m.y, c_r, digest_hi, digest_lo)`. Document the layout: `today[0..8), M.x[8], M.y[9], C_r[10], digest_hi[11], digest_lo[12]` (13 words).
- [ ] Keep `grumpkin_voprf` dep + `use ... multi_scalar_mul`. Keep all enrollment logic (Diia chain, ECDSA, messageDigest, RNOKPP, age, expand_message_xmd). No `c1..c4` inputs (lib owns SvdW).
- [ ] Tests: keep Diia-chain tests. Replace the fused tests with `#[test] test_enroll_emits_expected_cr` (asserts `commit_r` of the test `r` equals the value Task 1 pinned) and keep/adjust the honest-`M` cross-check. Remove fused F2 test (covered by the nullifier now).
- [ ] `nargo compile` clean; `nargo test` green; record `nargo info` (expect ~baseline + 1 pedersen).
- [ ] Commit: `git add circuits/enroll_commit_v2/src/main.nr` → `feat(enroll_commit_v2): revert fusion -> two-proof + C_r output (privacy-preserving F2)`.

### Task 3 — `oprf_nullifier`: rewrite over the library + `C_r`

**Files:** `packages/oprf/v3-grumpkin/circuits/oprf_nullifier/{Nargo.toml, src/main.nr}`.

- [ ] Add `grumpkin_voprf = { path = "../../lib-noir/grumpkin_voprf" }` to Nargo.toml.
- [ ] Replace `main` with the library composition. New signature:

```rust
use std::embedded_curve_ops::{EmbeddedCurvePoint as Pt, EmbeddedCurveScalar as Scalar};
fn main(
    kpx: pub Field, kpy: pub Field,   // node Kpub (single or Lagrange-combined)
    yx: pub Field, yy: pub Field,     // node response Y = k*M
    mx: pub Field, my: pub Field,     // blinded element M (service binds == enroll M)
    c_r: pub Field,                   // shared-r commitment (service binds == enroll C_r)
    r_lo: Field, r_hi: Field,
    rinv_lo: Field, rinv_hi: Field,
    c_lo: Field, c_hi: Field, z_lo: Field, z_hi: Field,
) -> pub Field {
    let kpub = Pt { x: kpx, y: kpy, is_infinite: false };
    let y = Pt { x: yx, y: yy, is_infinite: false };
    let m = Pt { x: mx, y: my, is_infinite: false };
    let r = Scalar { lo: r_lo, hi: r_hi };
    let rinv = Scalar { lo: rinv_lo, hi: rinv_hi };
    grumpkin_voprf::oprf::oprf_nullify_bound(m, y, kpub, r, rinv, c_r, c_lo, c_hi, z_lo, z_hi)
}
```
  (G is the lib's pinned global ⇒ removed from public inputs, closing F1's free-base surface; `c_expected` removed ⇒ C-1 is the limb binding inside the lib.)
- [ ] Public-input layout (8 words): `kpx[0] kpy[1] yx[2] yy[3] mx[4] my[5] c_r[6]`, return `nullifier[7]`.
- [ ] Tests: `#[test] test_honest` (asserts `EXPECTED_NULLIFIER`); `#[test(should_fail)]` for wrong `c_r`, wrong `rinv`, inconsistent `y`.
- [ ] `nargo compile` + `nargo test` green; record `nargo info`.
- [ ] Commit: `git add circuits/oprf_nullifier/Nargo.toml circuits/oprf_nullifier/src/main.nr` → `feat(oprf_nullifier): rewrite over grumpkin_voprf + C_r binding (F1+F2+C-1+C-3)`.

### Task 4 — Witness generators (new ABIs)

**Files:** `gen-enroll-commit-v2-witness.mjs`, `gen-nullifier-witness.mjs`; update `lib.mjs` only if a shared helper is needed (e.g. `commitR(r)` mirroring the circuit's pedersen).

- [ ] `lib.mjs`: add `export function commitR(rScalar)` computing `pedersen([r_lo, r_hi])` with the SAME pedersen the circuit uses (Grumpkin/BN254 pedersen via the existing helper; verify it matches Task 1's pinned `C_r` by cross-check).
- [ ] `gen-enroll-commit-v2-witness.mjs`: drop `c1..c4`; emit the 13-word reality — same `r`; the circuit now outputs `C_r` (no new INPUT needed, it's computed in-circuit) — ensure the generator's documented expected outputs include `C_r = commitR(r)`.
- [ ] `gen-nullifier-witness.mjs`: emit the new 8-word ABI — `kpx,kpy,yx,yy,mx,my,c_r` (with `c_r = commitR(r)`, same `r,k` as enroll) + private `r,rinv,c,z` limbs; drop `G`/`c_expected`.
- [ ] Sanity: `nargo execute` both circuits on the generated witnesses reaches the OPRF/nullifier asserts (enroll still fails at `assert_ca_pinned` with the synthetic CA — expected; nullifier should fully execute and output `EXPECTED_NULLIFIER`).
- [ ] Commit: `git add gen-enroll-commit-v2-witness.mjs gen-nullifier-witness.mjs lib.mjs` → `test: regenerate enroll/nullifier witnesses for the two-proof + C_r ABI`.

### Task 5 — Service: `proof-gate.mjs` layouts + `C_r` cross-check, `server.mjs` wiring

**Files:** `service/proof-gate.mjs`, `service/server.mjs`.

- [ ] `proof-gate.mjs` enroll layout: `PUBLIC_INPUT_WORD_COUNT = 13`; `M_X_WORD_INDEX = 8`; add `C_R_WORD_INDEX = 10`; `DIGEST_HI_WORD_INDEX = 11`, `DIGEST_LO_WORD_INDEX = 12`; add `extractCrFromEnroll(words) -> bigint`. Update `extractMFromPublicInputs`/`extractDigestFromPublicInputs` for the new count/indices.
- [ ] `proof-gate.mjs` nullifier layout: `NULLIFIER_PUBLIC_INPUT_WORD_COUNT = 8`; `KPUB@0, Y@2, M@4, C_R@6, COMMITMENT@7`; remove `G`/`cExpected`. Update `extractNullifierPublics`.
- [ ] `verifyNullifierProof`: add param `expectedCr`; add cross-check `(d) p.cr === expectedCr` ⇒ `NullifierMismatchedCr` on mismatch. Keep (a) M, (b) Kpub, (c) commitment.
- [ ] `server.mjs` `/v3/register`: after verifying the enroll proof, `const expectedCr = extractCrFromEnroll(enrollPublicInputs)` and pass it into `verifyNullifierProof`. `/v3/blind-eval` unchanged except the enroll layout indices (M now at [8]).
- [ ] Update `service/register-test.mjs` for the new ABIs so it stays green.
- [ ] Run `node service/register-test.mjs` (or its npm script) — green.
- [ ] Commit: `git add service/proof-gate.mjs service/server.mjs service/register-test.mjs` → `feat(service): two-proof C_r cross-check + new enroll/nullifier public-input layouts`.

### Task 6 — Client migration (thread same `r` + `C_r`, new ABIs)

**Files:** `packages/web/src/lib/grumpkin.ts`, `packages/web/src/worker/v3prove.worker.ts`, `packages/web/src/lib/v3enroll.ts`, `packages/web/src/lib/p7sWitness.ts`, `packages/web/src/pages/V3Enroll.tsx`.

- [ ] `grumpkin.ts`: update the public-input packing for BOTH circuits to the new layouts (enroll 13 words w/ `C_r`; nullifier 8 words w/ `kpub,y,m,c_r`); add a `commitR` mirror if the client needs to read/forward `C_r`.
- [ ] `v3enroll.ts` / `v3prove.worker.ts`: the enroll proof now yields `C_r` in its public inputs; capture it and forward to `/v3/register`. The nullifier witness must use the SAME `r` (and its `rinv`) as the enroll proof and include `c_r`. Drop the removed `G` input. Proving order unchanged (enroll → blind-eval → nullifier → register).
- [ ] `p7sWitness.ts`: adjust any enroll witness fields tied to the removed `c1..c4` / added `C_r` shape.
- [ ] `V3Enroll.tsx`: thread `C_r` through the register call if it constructs the payload.
- [ ] Typecheck/build the web package (`pnpm -C packages/web build` or the repo's TS check) — green.
- [ ] Commit: `git add packages/web/src/lib/grumpkin.ts packages/web/src/worker/v3prove.worker.ts packages/web/src/lib/v3enroll.ts packages/web/src/lib/p7sWitness.ts packages/web/src/pages/V3Enroll.tsx` → `feat(web): two-proof client — thread shared r + C_r, new circuit ABIs`.

### Task 7 — e2e: full two-proof flow green locally

**Files:** `packages/oprf/v3-grumpkin/e2e-test.mjs`.

- [ ] Update `e2e-test.mjs` to the new flow: enroll proof (13-word, emits `C_r`) → blind-eval (gated) → nullifier proof (8-word, same `r` + `c_r`) → register (asserts the `C_r` cross-check). Update the Prover.toml writers + public-input parsing for both circuits.
- [ ] Run the e2e (`node e2e-test.mjs` or the npm script) — all stages green, including the `C_r` cross-check enforced, and the produced nullifier equals `EXPECTED_NULLIFIER`.
- [ ] Commit: `git add e2e-test.mjs` → `test(e2e): two-proof flow with shared-r C_r cross-check`.

### Task 8 — Retire `oprf_commitment`; retarget `test-pinned-constants.mjs`

**Files:** `circuits/oprf_commitment/` (delete), `test-pinned-constants.mjs`, `forge-f3-*.mjs`.

- [ ] CONFIRM (re-grep) `oprf_commitment` has no consumer beyond test/witness harnesses (already verified: web/src + service clean).
- [ ] Delete the `oprf_commitment` circuit; ensure its F3 forgery coverage lives in the lib (params pinning + h2c tests). Retarget `test-pinned-constants.mjs`'s F3 leg to the lib; clean its stale log strings (the removed `test_svdw_*` names) and its F1 leg to the rewritten nullifier.
- [ ] Run `node test-pinned-constants.mjs` — green.
- [ ] Commit: `git add -u circuits/oprf_commitment test-pinned-constants.mjs forge-f3-*.mjs` (explicit paths) → `chore: retire oprf_commitment; retarget pinned-constants harness to grumpkin_voprf`.

### Task 9 — Adversarial re-verification (F1/F2/F3 against the NEW circuits)

**Files:** the `forge-*` witnesses (update to the new ABIs).

- [ ] F1: confirm the generator-substitution forgery is now IMPOSSIBLE to even express (G is not an input). Document this (no witness slot for a forged G).
- [ ] F2: update `forge-f2-nullifier-witness.mjs` to the new 8-word ABI — a witness with `rinv ≠ r⁻¹` (or `r` not matching `c_r`) must be REJECTED by `nargo execute` on the rewritten `oprf_nullifier` (the standalone previously ACCEPTED the analogue). Capture the rejection.
- [ ] F3: confirm the forged-SvdW path is gone (constants are lib globals; no `c1..c4` inputs to the enroll circuit).
- [ ] Record the results in `docs/2026-06-02-voprf-security-review.md` (§4/§5): F1/F2/F3 now closed in the deployed two-proof path; F4 unchanged (threshold-pending); C-1/C-3 carried in the lib.
- [ ] Commit: `git add forge-*.mjs docs/2026-06-02-voprf-security-review.md` → `test+docs: adversarial re-verify F1/F2/F3 closed on the two-proof circuits`.

### Out of scope (user-gated / tracked)
- Outward-facing **redeploy** (web + Fly) + **on-device iOS prove test**.
- **Threshold (#7)** — per-share DLEQ verification, session/epoch binding, `combine()` index dedup, wiring t-of-n nodes (NEXT workstream; the F2 design is already threshold-compatible).
- **F4** salt-free leaf (recovery tension); randomness hygiene (#6); external audit.
