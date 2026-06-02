# Threshold OPRF (2-of-3) demo — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. `- [ ]` checkboxes. Sequences ON TOP of the completed F2 two-proof work (branch `feat/voprf-security-fixes`). Spec: `docs/specs/2026-06-02-threshold-oprf-demo.md`.

**Goal:** Replace single-key OPRF with a 2-of-3 threshold whose register proof self-attests (in-circuit per-share DLEQs + Lagrange combine), closing review #7 and laying the real F4 path. Demo-grade, wired, **fresh threshold key `k'` in a new epoch** (no leaf migration).

**Tech:** Noir 1.0.0-beta.19 (`~/.nargo/bin/nargo`), @aztec/bb.js, Node ESM, React/TS. ASCII-only in `.nr`. Fork rule: explicit `git add`. **t=2, n=3.** Lagrange `λ_i` are native-field ops (N = BN254 base field = Noir field).

---

### Task 1 — Library: per-share DLEQ + threshold entry point + Lagrange (in-circuit)

**Files:** `lib-noir/grumpkin_voprf/src/dleq.nr`, `src/oprf.nr`, `src/lib.nr` (tests).

- [ ] `dleq.nr`: add `verify_dleq_share(kpub_i, m, b_i, epoch: Field, c_lo,c_hi,z_lo,z_hi)` — identical to `verify_dleq` but proving `B_i=k_i·M` vs `Kpub_i` and with `epoch` appended to the transcript: `ch = pedersen([GEN.x,GEN.y, kpub_i.x,kpub_i.y, m.x,m.y, b_i.x,b_i.y, a1.x,a1.y, a2.x,a2.y, epoch])`; keep the C-1 limb binding + 128-bit range checks + pinned GEN (F1).
- [ ] `oprf.nr`: add `lagrange2(idx1: Field, idx2: Field) -> (Field, Field)` computing `λ1 = -idx2/(idx1-idx2)`, `λ2 = -idx1/(idx2-idx1)` (native field; the t=2 case of `Π_{j≠i}(-idx_j)/(idx_i-idx_j)`). Assert `idx1 != idx2` (denominator nonzero / dedup).
- [ ] `oprf.nr`: add `oprf_nullify_threshold(m, kpub1, b1, kpub2, b2, idx1, idx2, epoch, c1.., c2.., r, rinv, c_r) -> Field`: assert distinct idx; `verify_dleq_share` for each; `(l1,l2)=lagrange2(...)`; `Y = multi_scalar_mul([b1,b2],[l1_scalar,l2_scalar])` (convert λ Field→Scalar via 128-bit limb split — λ are full field elements, so split into lo/hi and range-check); then the F2 tail (range-check rinv; `assert(commit_r(r)==c_r)`; `assert(!Y.is_infinite)` guard; `n=rinv·Y`; `!n.is_infinite`; `assert(r·n==Y)` ("F2: r*N != Y"); `pedersen([n.x,n.y])`). Keep `oprf_nullify_bound` (single-key) for reference.
  - NOTE on λ→Scalar: `multi_scalar_mul` takes `EmbeddedCurveScalar{lo,hi}`. λ_i is a native Field < N; split into 128-bit limbs (helper) and pass. Range-check the limbs. (Same pattern as the c/z/r limbs.)
- [ ] `lib.nr` tests (reuse the pinned vectors; generate a 2-of-3 vector set from threshold-oprf.mjs in Task 3 if needed, or hardcode a small one): `test_verify_dleq_share_honest`/`_wrong_k`/`_wrong_epoch`; `test_lagrange2_matches_js` (λ for idx {1,2}); `test_nullify_threshold_honest` (== `pedersen(k'·H2C(id))` for the test vector); `should_fail`: bad DLEQ_i, duplicate idx (idx1==idx2), wrong c_r, wrong rinv.
- [ ] `nargo test` green; `nargo compile` clean. Commit: `feat(grumpkin_voprf): verify_dleq_share (epoch-bound) + lagrange2 + oprf_nullify_threshold`.

### Task 2 — Threshold nullifier circuit (compiled for t=2)

**Files:** `circuits/oprf_nullifier/src/main.nr` (rewrite main to the threshold ABI), `Nargo.toml` (keep lib dep).

- [ ] Replace `main` per spec §6: public `mx,my, kp1x,kp1y, kp2x,kp2y, idx1, idx2, epoch, c_r`; private `b1x,b1y,b2x,b2y, c1_lo,c1_hi,z1_lo,z1_hi, c2_lo,c2_hi,z2_lo,z2_hi, r_lo,r_hi, rinv_lo,rinv_hi`. Build the points/scalars and call `grumpkin_voprf::oprf::oprf_nullify_threshold(...)`. Return `nullifier`.
- [ ] Document the 11-word layout: `mx[0] my[1] kp1x[2] kp1y[3] kp2x[4] kp2y[5] idx1[6] idx2[7] epoch[8] c_r[9]`, return `nullifier[10]`.
- [ ] `#[test]`s mirroring the lib (honest == anchor; should_fail: bad DLEQ, dup idx, wrong c_r, wrong rinv).
- [ ] `nargo compile` + `nargo test` green; record `nargo info`. Commit: `feat(oprf_nullifier): threshold (2-of-3) — in-circuit per-share DLEQ + Lagrange combine`.

### Task 3 — JS threshold hardening + witness generator

**Files:** `threshold/threshold-oprf.mjs`, `lib.mjs`, `gen-nullifier-witness.mjs` (or a new `gen-threshold-nullifier-witness.mjs`).

- [ ] `threshold-oprf.mjs`: `partialEval(share, M, epoch)` now ALSO returns a per-share DLEQ `{c,z}` over `(Kpub_i, M, B_i, epoch)` (reuse `dleqProveBase`-style with the epoch in the transcript — mirror `verify_dleq_share`'s transcript EXACTLY). `combine(partials)` asserts distinct indices (throw on dup). Add `verifyPartialDleq(...)` (client/service-side checker).
- [ ] `lib.mjs`: add a `dleqProveShare(Kpub_i, k_i, M, B_i, epoch, t)` matching the circuit transcript (GEN, Kpub_i, M, B_i, a1, a2, epoch) so JS-generated witnesses verify in-circuit. Export `lagrange2`/`lagrangeCoeff` if not already shared.
- [ ] Witness generator for the threshold nullifier: 2-of-3 shares via `dkgKeygen(3,2)`, pick indices {1,2}, build B_i + per-share DLEQ_i + the 11-word ABI Prover.toml. `nargo execute oprf_nullifier` → the canonical `pedersen(k'·H2C(id))`. Pin that expected nullifier for the epoch's `k'`.
- [ ] Commit: `test(threshold): per-share DLEQ + combine dedup + 2-of-3 nullifier witness generator`.

### Task 4 — Node → share node (run 3 instances)

**Files:** `service/oprf-node.mjs`.

- [ ] `OprfNode` holds `{ i (index), k_i }`; `evaluate(M, epoch)` returns `{ i, B_i: hex, dleq: {c,z}, Kpub_i: hex }` (per-share DLEQ, epoch-bound, via `dleqProveShare`). Add a `publicShare()` → `{ i, Kpub_i }`. Keep the single-key path only if trivially compatible, else replace (deployed flow goes threshold).
- [ ] A small `makeNodes(n,t,epoch)` test helper (uses `dkgKeygen`) that returns n share-nodes + the published `Kpub_i` set, for e2e + tests.
- [ ] Unit test: `evaluate` DLEQ verifies via `verifyPartialDleq`; `Kpub_i == k_i·G`. Commit: `feat(oprf-node): share node — partial eval + epoch-bound per-share DLEQ + published Kpub_i`.

### Task 5 — Service: blind-eval fan-out gating + register threshold verify

**Files:** `service/proof-gate.mjs`, `service/server.mjs`.

- [ ] `proof-gate.mjs`: new threshold nullifier layout (11 words) + `extractThresholdNullifierPublics` ({M, Kpub1, Kpub2, idx1, idx2, epoch, c_r, nullifier}). `verifyThresholdNullifierProof({...})` cross-checks: (a) `M`==enroll's `M` [HARD], (d) `c_r`==enroll's `C_r`, (e) `{Kpub1@idx1, Kpub2@idx2}` ⊆ the node's **published Kpub set** (by index), (f) `epoch`==current `enrollEpoch`, (c) `nullifier`==submitted commitment; then bb verify. Keep the enroll gate unchanged.
- [ ] `server.mjs`: hold the published Kpub set + `enrollEpoch`. `/v3/blind-eval` is per-node (each of the t nodes gates on the enroll proof, as today) — for the demo the server can host the 3 share-nodes and expose `/v3/blind-eval?node=i` OR the client calls 2 node URLs; pick the simplest that keeps each node gating independently (document it). `/v3/register` calls `verifyThresholdNullifierProof`. Update `register-test.mjs`.
- [ ] Load check + the runnable gate-unit slice (fake gate) exercising (a)/(c)/(d)/(e)/(f). Commit: `feat(service): threshold register verify (published Kpub set + epoch) + blind-eval fan-out`.

### Task 6 — Client: fan-out + threshold witness

**Files:** `packages/web/src/lib/v3enroll.ts`, `p7sWitness.ts`, `grumpkin.ts`, worker (likely unchanged).

- [ ] Blind-eval fan-out to t=2 nodes; collect `{i, B_i, dleq_i, Kpub_i}`; verify each DLEQ client-side (fail fast); combine `Y` for local commitment/UX.
- [ ] Build the threshold nullifier witness (11-word public + private B_i/DLEQ/r/rinv) with the same `r` + `c_r` from enroll `publicInputs[10]`; register.
- [ ] `grumpkin.ts`: per-share DLEQ verify + `lagrange2` + threshold witness packer (mirror lib/JS). `tsc --noEmit` green. Commit: `feat(web): threshold client — blind-eval fan-out + threshold nullifier witness`.

### Task 7 — e2e: 2-of-3 end to end

**Files:** `e2e-test.mjs`.

- [ ] 3 in-process share-nodes (`makeNodes(3,2,epoch)`); fan-out to {1,2}; per-share DLEQs; nargo execute + real bb proof on the threshold nullifier; checks: determinism (same id, DIFFERENT t-subset {1,3} and different blind → SAME leaf), distinctness (different id), and a **cheating-node negative** (corrupt one `B_i` → `nargo execute` FAILS at `verify_dleq_share`). Enroll stage stays JS-computed (prod CA pin, as in the F2 e2e). Commit: `test(e2e): 2-of-3 threshold — fan-out + in-circuit combine + cheating-node reject`.

### Task 8 — Adversarial re-verify (#7) + docs

**Files:** a `forge-threshold-*.mjs`, `docs/2026-06-02-voprf-security-review.md`.

- [ ] Regression guards (exit nonzero unless rejected): forged `B_i` (wrong `k_i`) → `verify_dleq_share` reject; duplicate index (idx1==idx2) → reject; stale epoch (DLEQ epoch ≠ public epoch) → reject.
- [ ] Update the review doc: checklist **#7 CLOSED** (per-share DLEQ in-circuit, combine dedup, epoch binding); **F4** now mitigated under 2-of-3 honest-keyholder assumption — *operational caveat: requires independent operators* (the demo may run one operator's instances). Reference the threshold commits.
- [ ] Commit: `test+docs: #7 closed (per-share DLEQ/dedup/epoch); F4 mitigated under 2-of-3 (independent operators caveat)`.

### Out of scope (tracked)
- Production verifiable **DKG** (Feldman/Pedersen + complaint round); **independent-operator** deployment (the F4-real prerequisite); redeploy (web + Fly, n node services) + **on-device iOS test**; external audit.
