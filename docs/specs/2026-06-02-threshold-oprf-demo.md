# Threshold OPRF (t-of-n) — demo-grade, wired, in-circuit verified — design

**Date:** 2026-06-02
**Status:** Design (forks approved 2026-06-02: demo-grade + wired; in-circuit per-share DLEQ verification).
**Source:** review checklist **#7** (`docs/2026-06-02-voprf-security-review.md`) + the F4 mitigation path (see [[project_f2_deploy_two_proof]], [[project_v3_grumpkin_oprf]]). Sequences ON TOP of the completed F2 two-proof work (branch `feat/voprf-security-fixes`).

## 1. Goal & scope

Replace the single-key OPRF with a **t-of-n threshold** so the key `k` is never held or reconstructed at any single party — the real mitigation for **F4** (operator deanonymization). The register proof **self-attests** that the OPRF output `Y` is a valid t-of-n evaluation (per-share DLEQs + Lagrange combine verified **in-circuit**), closing the #7 soundness gaps: per-share DLEQ verification, `combine()` index dedup, and session/epoch binding.

**In scope:** the #7 soundness layer + wiring t-of-n nodes into the deployed blind-eval/register flow + the new threshold nullifier circuit/library + client fan-out. **Parameters: t-of-n = 2-of-3** (the circuit is compiled for t=2; n=3 nodes published, any 2 evaluate).

**Out of scope (tracked):** a production verifiable **DKG** (Feldman/Pedersen commitments + complaint round — keep the prototype dealer/DKG-lite keygen); running the nodes under **independent operators** (operational — the code enforces no-single-keyholder, but real F4 mitigation requires the 3 nodes to be independently operated; the demo may run them as one operator's instances and SAY so); redeploy + on-device iOS test; external audit.

## 2. Threat model / what F4 needs

- The architecture guarantees no single party computes `k·H2C(id)`: each node `i` only ever computes `B_i = k_i·M` on a blinded `M`, and `Y = Σ λ_i·B_i` is formed by linear combination of points (k never assembled).
- **F4 is mitigated iff ≥ (n−t+1) nodes are honest/independent** (here 2: with 2-of-3, deanonymizing the registry needs ≥2 colluding nodes). With one operator running all 3, F4 is NOT mitigated — this is an operational property the demo must disclose, not a code property.

## 3. Keygen (demo-grade, keep prototype)

Reuse `threshold/threshold-oprf.mjs` `dkgKeygen(n,t)` (DKG-lite: each node deals a Shamir sub-share, final share = sum; `kImplied` is test-only). Each node publishes `Kpub_i = k_i·G` (a verifiable commitment to its share). The group key `Kpub = k·G = Σ λ_i·Kpub_i` is derivable but unused in-circuit. Production DKG (verifiable commitments + complaints) is out of scope.

## 4. Per-share DLEQ + session binding

Each node `i`, on `POST /v3/blind-eval`, returns `B_i = k_i·M` and a Chaum-Pedersen **per-share DLEQ** proving `log_G(Kpub_i) == log_M(B_i)` (same `k_i`), with the **epoch bound into the transcript**:

```
a1_i = t_i·GEN,  a2_i = t_i·M
c_i  = pedersen([GEN, Kpub_i, M, B_i, a1_i, a2_i, epoch])   // epoch binds the session
z_i  = t_i + c_i·k_i   (mod N)
```

`epoch` is the service's `enrollEpoch` (already present). Binding it stops a `B_i` from epoch E being replayed in epoch E'.

## 5. Library additions (`grumpkin_voprf`)

- `dleq::verify_dleq_share(kpub_i, m, b_i, epoch, c_lo,c_hi,z_lo,z_hi)` — the §4 per-share DLEQ verify against the **pinned GEN** (F1), with `epoch` in the transcript and the C-1 limb binding (carried over). (A thin epoch-aware variant of `verify_dleq`.)
- `oprf::oprf_nullify_threshold` — the t-of-n register entry point (the §6 body). Verifies the t per-share DLEQs, computes the Lagrange combine **in-circuit**, asserts distinct indices, unblinds, and applies the F2 `C_r` + `r·N==Y` binding. Keeps `oprf_nullify_bound` (single-key) for reference/other consumers.

Lagrange coefficients `λ_i = Π_{j≠i} (−idx_j)/(idx_i − idx_j) (mod N)` are computed **in-circuit** — `N` is the Grumpkin scalar order = the **BN254 base field = Noir's native field**, so this is native field arithmetic (cheap), not non-native.

## 6. Threshold nullifier circuit (`oprf_nullifier`, compiled for t=2)

```
fn main(
    mx: pub Field, my: pub Field,                 // M (service: == enroll's M)
    kp1x: pub Field, kp1y: pub Field,             // Kpub_1 (service: in published set)
    kp2x: pub Field, kp2y: pub Field,             // Kpub_2
    idx1: pub Field, idx2: pub Field,             // node indices (service: the t responders)
    epoch: pub Field,                             // session (service: == current enrollEpoch)
    c_r: pub Field,                               // shared-r commitment (service: == enroll's C_r)
    // private witness: the partials + per-share DLEQs + blind:
    b1x, b1y, b2x, b2y,                           // B_1, B_2
    c1_lo,c1_hi,z1_lo,z1_hi,                      // DLEQ_1
    c2_lo,c2_hi,z2_lo,z2_hi,                      // DLEQ_2
    r_lo, r_hi, rinv_lo, rinv_hi,
) -> pub Field {
    // 1. distinct indices (combine() dedup, in-circuit)
    assert(idx1 != idx2);
    // 2. per-share DLEQs vs pinned GEN, epoch-bound (F1 + C-1 + session)
    verify_dleq_share(Kpub_1, M, B_1, epoch, c1..);
    verify_dleq_share(Kpub_2, M, B_2, epoch, c2..);
    // 3. Lagrange combine IN-CIRCUIT: lambda_i from idx (native field), Y = sum lambda_i*B_i
    let (l1, l2) = lagrange2(idx1, idx2);
    let Y = msm([B_1, B_2], [l1, l2]);
    // 4. unblind + F2 binding (C_r + r*N==Y), is_infinite guards, nullifier
    //    (reuses oprf_nullify_bound's tail, with Y now the in-circuit combined point)
    nullifier = oprf_nullify_threshold_tail(Y, r, rinv, c_r);   // commit_r(r)==c_r; n=rinv*Y; r*N==Y; pedersen(N)
}
```

**Public-input layout (11 words):** `mx[0] my[1] kp1x[2] kp1y[3] kp2x[4] kp2y[5] idx1[6] idx2[7] epoch[8] c_r[9]`, return `nullifier[10]`. (`B_i`, DLEQ limbs, `r`, `rinv` are private.)

Inherits F1 (pinned GEN), F2 (`C_r` + `r·N==Y`), C-1 (limb-bound challenges), C-3 (range-checked limbs), is_infinite guards — all from the library. F3 lives in the enroll circuit (unchanged).

## 7. Service (`oprf-node.mjs`, `server.mjs`, `proof-gate.mjs`)

- **`oprf-node.mjs` → share node:** holds `k_i` + its index `i`; `evaluate(M)` returns `{ i, B_i, dleq_i (epoch-bound), Kpub_i }`. Publishes `Kpub_i`. For the demo, run **3 node instances** (in-process for e2e; separate Fly services for the live demo) with the `dkgKeygen` shares.
- **`/v3/blind-eval`:** still gated per node by the enroll proof (each of the t nodes independently verifies the enroll proof + M-binding before spending `k_i·M`). The client fans out to t nodes.
- **`/v3/register` (`proof-gate.mjs`):** new 11-word threshold layout; cross-checks: (a) `M` == enroll's `M` [HARD], (d) `c_r` == enroll's `C_r`, (e) `Kpub_1, Kpub_2` ∈ the **published Kpub set** and `idx1, idx2` are their indices, (f) `epoch` == current `enrollEpoch`, (c) `nullifier` == submitted commitment. The proof self-attests the DLEQs + combine, so the service only pins the published keys/epoch.

## 8. Client (`v3enroll.ts`/`p7sWitness.ts`, `grumpkin.ts`, worker)

- Blind-eval **fan-out**: POST the enroll proof to t nodes; collect `{i, B_i, dleq_i, Kpub_i}`. Verify each DLEQ client-side (fail fast) and combine `Y` (for the local commitment/UX), but the **proof** carries the shares for in-circuit verification.
- Build the **threshold nullifier witness** (the §6 private+public inputs: t shares + DLEQs + indices + epoch + same `r`/`rinv` + `c_r` from enroll `publicInputs[10]`).
- `grumpkin.ts`: per-share DLEQ verify + Lagrange combine helpers (mirror the lib); threshold witness packer.

## 9. #7 closure (explicit)

- **Per-share DLEQ verification:** in-circuit (§6 step 2) — a cheating/faulty node's `B_i ≠ k_i·M` fails the proof.
- **`combine()` index dedup:** in-circuit `assert(idx1 != idx2)` (§6 step 1) + the service checks indices are distinct published nodes.
- **Session/epoch binding:** `epoch` in every per-share DLEQ transcript (§4) + service checks `epoch == current` (§7).

## 10. Testing

- **Library:** `verify_dleq_share` honest accept / wrong-`k_i` reject / wrong-epoch reject; `lagrange2` matches JS `lagrangeCoeff`; `oprf_nullify_threshold` honest (nullifier == single-key path's `pedersen(k·H2C(id))` for the SAME effective `k` — determinism/recovery preserved), reject: bad DLEQ_i, duplicate indices, wrong `c_r`, wrong `rinv`.
- **Circuit:** `nargo test` for the t=2 threshold nullifier; `nargo execute` on a generated 2-of-3 witness yields the canonical nullifier.
- **e2e-test.mjs:** 2-of-3 fan-out (3 in-process nodes) → per-share DLEQs → in-circuit combine → nullifier; determinism (same id, different t-subset/blind → SAME leaf), distinctness, and a **cheating-node** negative (one `B_i` corrupted → proof rejected).
- **Adversarial:** a forged `B_i` (wrong `k_i`) rejected; a duplicate-index witness rejected; a stale-epoch witness rejected.

## 11. Determinism / recovery

`Y = k·M` for the SAME effective `k` as the single-key key ⇒ `nullifier = pedersen(k·H2C(id))` unchanged per identity ⇒ recovery + existing leaves preserved, **provided the threshold key equals the deployed single-key `k`** (the DKG must reproduce the same `k`, or this is a fresh-epoch migration). DECISION NEEDED at planning: reuse the existing `k` as the DKG secret (preserves leaves) vs a new threshold key (new epoch, re-enroll). For the demo, a fresh threshold key in a new epoch is simplest; flag the migration implication.

## 12. Security properties

- **F4:** mitigated under the 2-of-3 honest-majority-of-keyholders assumption (needs ≥2 colluding nodes to deanonymize) — real only with independent operators.
- **F1/C-1:** per-share DLEQs verified against the pinned GEN with limb-bound, epoch-bound challenges.
- **F2:** `C_r` + `r·N==Y` carried over (unchanged).
- **#7:** per-share verification + index dedup + session binding, all enforced.
- Still **EXPERIMENTAL/UNAUDITED**; production DKG + independent operators + audit remain.
