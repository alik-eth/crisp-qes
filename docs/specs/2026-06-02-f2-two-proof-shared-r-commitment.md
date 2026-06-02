# F2 fix (deployed v3) — two proofs bound by a shared-`r` commitment

**Date:** 2026-06-02
**Status:** Design (approach approved 2026-06-02). SUPERSEDES the *deployment* sections (§4, §6) of `docs/specs/2026-06-02-grumpkin-voprf-library-and-f2-binding.md` — the fused single-circuit work from that spec stays as a reusable LIBRARY entry point, but the DEPLOYED v3 enrollment path uses the two-proof composition below.
**Source:** finding **F2** (`docs/2026-06-02-voprf-security-review.md`); the privacy-vs-fusion fork resolved 2026-06-02 (see [[project_f2_deploy_two_proof]]).

## 1. Why not the single fused proof

The fused circuit takes `Y` (node response) + DLEQ as inputs, so the client can only build it **after** `/v3/blind-eval`. But `/v3/blind-eval` is **gated by the enroll proof** (`server.mjs:383`): the node only evaluates an `M` that is ZK-proven to be the requester's *own* cert-bound identity (`M = r·H2C(RNOKPP)`). That gate is load-bearing for **privacy** — it makes the OPRF a *closed* oracle:

- **Closed (today):** to obtain `Y = k·M` you must prove `M` is *your* cert's identity ⇒ you can only ever learn `k·H2C(your_own_id)`.
- **Open (if single proof):** the proof moves after blind-eval ⇒ blind-eval can't require it ⇒ anyone who guesses a 10-digit RNOKPP can compute `M = r·H2C(id)`, get `Y`, unblind `N = k·H2C(id)`, and membership-test the enrollment registry (`pedersen(N)`, deterministic and un-saltable because recovery needs it). That is a deanonymization regression.

So single-proof and closed-oracle are mutually exclusive. We keep **two proofs** and close F2 by **binding the same `r` across them** with a Pedersen commitment.

## 2. The binding (closes F2)

The F2 hole: in the standalone `oprf_nullifier`, `r`/`rinv` are free witnesses tied only by `r·N==Y`, with an `r` **unrelated** to the enrollment blind `r_enroll` ⇒ any invertible `s` gives `N = s·Y` ⇒ unbounded nullifiers.

Fix: the enroll proof publishes `C_r = pedersen([r_lo, r_hi])`; the nullifier proof takes `C_r` as a public input and asserts `pedersen([r_lo, r_hi]) == C_r` for **its** `r`. Pedersen binding ⇒ the two proofs use the *same* `r`. Then the nullifier proof's `r·N==Y` (with `N = rinv·Y`) forces `rinv = r⁻¹ = r_enroll⁻¹`, so:

```
N = r_enroll⁻¹ · Y = r_enroll⁻¹ · k · M = r_enroll⁻¹ · k · r_enroll · H2C(id) = k·H2C(id)
```

the canonical, deterministic OPRF output — no Sybil leverage. (`C_r` adds no new linkage: the two proofs already share the public `M`, line 358.)

## 3. Circuit changes

Both circuits compose the `grumpkin_voprf` library (one source of pinned constants ⇒ inherit F1/F3/C-1/C-3).

### 3a. `enroll_commit_v2` (the blind-eval gate) — REVERT the Task-2 fusion, then add `C_r`
- Keep ALL enrollment logic: Diia CA→leaf chain, SPKI↔pubkey, ECDSA-P256, messageDigest, RNOKPP, age≥18, expand_message_xmd → `u0,u1`.
- Compute `h2c = grumpkin_voprf::h2c::h2c_grumpkin(u0,u1,h0,h1)` (drops the `c1..c4` public inputs — lib owns them, F3) and `M = r·h2c` (lib MSM).
- Add `let c_r = grumpkin_voprf::oprf::commit_r(r);` (new lib helper, §3c).
- **No** DLEQ / `Y` / nullifier here (it gates blind-eval, which precedes `Y`).
- **Public outputs:** `(M.x, M.y, C_r, digest_hi, digest_lo)`.
- **Public-input layout (13 words):** `today[0..8)`, then return `M.x[8] M.y[9] C_r[10] digest_hi[11] digest_lo[12]`.

### 3b. `oprf_nullifier` (the register proof) — rewrite over the library + `C_r`
- Inputs: PUBLIC `kpx,kpy, yx,yy, mx,my, c_r`; PRIVATE `r_lo,r_hi, rinv_lo,rinv_hi, c_lo,c_hi, z_lo,z_hi`. (G is the lib's pinned global — `G.x/G.y` drop from the public inputs, closing the F1 attack surface that the standalone's free `G` created.)
- Body via a new lib entry point `oprf_nullify_bound` (§3c): assert `commit_r(r)==c_r`; `verify_dleq(kpub, m, y, dleq)` (F1+C-1); `n = rinv·y`; `assert(r·n==y)` (F2, with `r` bound to enroll via `c_r`); `is_infinite` guards; `nullifier = pedersen([n.x,n.y])`.
- **Public outputs:** `(nullifier)`.
- **Public-input layout (8 words):** `kpx[0] kpy[1] yx[2] yy[3] mx[4] my[5] c_r[6]` then return `nullifier[7]`.

### 3c. `grumpkin_voprf` library additions
- `oprf::commit_r(r: Scalar) -> Field { pedersen_hash([r.lo, r.hi]) }` (range-check the limbs).
- `oprf::oprf_nullify_bound(m, y, kpub, r, rinv, c_r, c_lo,c_hi,z_lo,z_hi) -> Field` — the two-proof register entry point (the §3b body). Reuses `verify_dleq` + the `is_infinite` guards.
- KEEP `oprf::oprf_verify_and_nullify` (the fused single-`r` entry point) for consumers without a gated-oracle stage (CRISP/Interfold).

## 4. Service changes (`proof-gate.mjs`, `server.mjs`)
- `proof-gate.mjs`: update the enroll layout to 13 words (add `C_R_WORD_INDEX=10`, `extractCrFromEnroll`); rewrite the nullifier layout to 8 words (`KPUB@0, Y@2, M@4, C_R@6, COMMITMENT@7`); drop the removed `G`/`c_expected` indices.
- `verifyNullifierProof`: keep cross-checks (a) `M` == enroll's `M`, (b) `Kpub` == this node's, (c) `commitment` == submitted; **add (d) `C_r` == enroll proof's `C_r`** — the cross-proof `r` binding.
  - **(a) `M`-check is HARD / non-skippable.** `C_r` binds `r`, but the *identity* is bound by `M = r·H2C(id)`. If `M` is not cross-checked, a prover with the honest `r` (so `commit_r(r)==c_r` passes) could submit `m' = r·H2C(id')` for a chosen identity and, if it ever obtained `Y'=k·m'`, mint `N=k·H2C(id')` for an arbitrary identity. The gated blind-eval (only evaluates the enroll-bound `M`) and the in-circuit DLEQ (binds `m` to the node's `Y`) already prevent obtaining `Y'`, so this is defense-in-depth — but the `M`-check must never be dropped. Document it as load-bearing.
- `server.mjs`: `/v3/blind-eval` unchanged in shape (still gated by the enroll proof + `challengeDigestOk`); `/v3/register` passes the enroll proof's `C_r` into `verifyNullifierProof` as `expectedCr`. Off-chain bb.js re-derives both VKs at boot ⇒ no VK-artifact regen step beyond recompiling the circuits; no on-chain redeploy (enroll/nullifier are off-chain gated).

## 5. Client changes (`v3prove.worker.ts`, `v3enroll.ts`, `p7sWitness.ts`, `V3Enroll.tsx`, `grumpkin.ts`)
- Enroll proof witness: add `C_r` output handling (it now appears in the enroll public inputs). Same `r` as today.
- Nullifier proof witness: thread the SAME `r` (and `C_r`) used by the enroll proof; drop the now-removed `G` input; supply `kpub/y/m/c_r` + private `r/rinv/c/z` per the new ABI. Proving order unchanged (enroll before blind-eval; nullifier after).
- `grumpkin.ts`: update the public-input packing for both circuits to the new layouts.

## 6. Determinism / recovery / migration
- `nullifier = pedersen(k·H2C(id))` is unchanged per identity ⇒ deterministic-commitment **recovery still works**; existing on-chain leaves stay valid; **no user migration**. (`C_r` is an extra per-session public value; it does not enter the leaf.)

## 7. Disposition of `oprf_commitment`
- `oprf_commitment` has **no deployed consumer** (web/src + service grep clean). Retire it: fold its F3 forgery coverage into the lib's tests and retarget `test-pinned-constants.mjs`’s F3 leg to the lib. (Tracked in the plan; not load-bearing for F2.)

## 8. Testing
- **Library:** `commit_r` determinism; `oprf_nullify_bound` honest accept (nullifier == `0x06f3…fab227`); REJECT — wrong `C_r` (r≠r_enroll), wrong `rinv` (F2), C-1 free-`z`, DLEQ-inconsistent `Y`, degenerate `y`.
- **Circuits:** enroll honest (emits the right `C_r`); nullifier honest (same identity ⇒ same nullifier as the old path — regression/recovery anchor); cross-proof: a nullifier witness whose `r`≠ enroll's `r` is rejected (different `C_r`).
- **e2e-test.mjs:** the full two-proof flow green locally (enroll → blind-eval → nullifier → register), with the new `C_r` cross-check enforced.
- **iOS budget:** both circuits gain only a pedersen (+ small DLEQ for nullifier); record `nargo info` deltas. On-device measurement remains Task 6-deploy (user-gated).

## 9. Out of scope (user-gated / tracked)
- Outward-facing **redeploy** (web + Fly) and the **on-device iOS prove test**.
- Threshold OPRF hardening (#7), F4 enrollment-leaf salt (tension with recovery), randomness hygiene (#6), external audit.
