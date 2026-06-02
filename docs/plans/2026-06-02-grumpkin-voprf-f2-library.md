# Grumpkin VOPRF — F2 fused binding via reusable library — implementation plan

> Execute with subagent-driven development. Sequences on top of F1+F3 (commit 8da263b, branch feat/voprf-security-fixes). Spec: docs/specs/2026-06-02-grumpkin-voprf-library-and-f2-binding.md.

**Goal:** Close F2 (free rinv/r → Sybil) by extracting a reusable `grumpkin_voprf` Noir library whose single-`r` entry point makes the blind↔unblind binding structural, and composing it in `enroll_commit_v2`.

**Key implementation refinement (binding without non-native arithmetic):** do NOT compute `r·rinv ≡ 1 (mod n)` natively. Instead reuse the original group-equation `assert(scalar_mul(r, N) == Y)` where `N = scalar_mul(rinv, Y)` — but with `r` being the SAME witness used for the blind `M = scalar_mul(r, h2c)`. Since `Y` is prime-order, `r·N==Y` forces `rinv = r⁻¹`, and `r = r_enroll` ⇒ `N = r_enroll⁻¹·Y = k·H2C(id)`. Add 128-bit range-checks on r/rinv limbs (closes C-3 residual). This matches the original's "avoid non-native mod-n" design.

**Library API (target):**
```
grumpkin_voprf::params   // globals: GEN_X, GEN_Y, SVDW_C1..C4, SVDW_Z, ZETA, BCURVE, DST  (values from 8da263b)
grumpkin_voprf::h2c::h2c_grumpkin(u0: Field, u1: Field, h0: [Field;6], h1: [Field;6]) -> Pt
grumpkin_voprf::dleq::verify_dleq(kpub: Pt, m: Pt, y: Pt, c_lo,c_hi,z_lo,z_hi: Field)   // GEN pinned; C-1 limb-bound
grumpkin_voprf::oprf::oprf_verify_and_nullify(h2c: Pt, r: Scalar, rinv: Scalar, kpub: Pt, y: Pt, dleq...) -> Field
```
`oprf_verify_and_nullify` takes `r` ONCE: computes `m = r·h2c`, `verify_dleq(kpub,m,y,dleq)`, `n = rinv·y`, `assert(r·n == y)` (binding), range-checks limbs, returns `pedersen([n.x,n.y])`. (Also expose `m` for the app's public output.)

---

### Task 1 — Scaffold `grumpkin_voprf` library: params + h2c + dleq + scalar binding, with unit tests

**Files:** create `packages/oprf/v3-grumpkin/lib-noir/grumpkin_voprf/{Nargo.toml, src/lib.nr, src/params.nr, src/h2c.nr, src/dleq.nr, src/oprf.nr}`.

- [ ] Nargo.toml `type = "lib"`, name `grumpkin_voprf`.
- [ ] `params.nr`: copy the pinned globals VERBATIM from the F1/F3 commit (oprf_nullifier GEN_X/GEN_Y; oprf_commitment SVDW_C1..C4, SVDW_Z, ZETA, BCURVE, DST). One source of truth.
- [ ] `h2c.nr`: port `svdw_map` + `h2c_grumpkin = map(u0)+map(u1)` from oprf_commitment (keep hint-verification: assert_is_square, sqrt, cmov, sgn0). Use params globals.
- [ ] `dleq.nr`: port the in-circuit DLEQ verify from oprf_nullifier — recompute a1=z·GEN−c·Kpub, a2=z·M−c·Y, `c == pedersen([GEN, Kpub, M, Y, a1, a2])`, limb-bind `c_lo+c_hi·2^128 == ch` with 128-bit range-checks (C-1). GEN from params (F1).
- [ ] `oprf.nr`: `oprf_verify_and_nullify(...)` per the API above (single-`r`, group-equation binding, range-checked limbs, pedersen nullifier).
- [ ] `lib.nr`: re-export modules.
- [ ] Unit `#[test]`s in the lib: honest inputs ACCEPT; and these REJECT — F1 (substituted via a non-pinned base is impossible since GEN is a const, so instead test that a Y/Kpub inconsistent with GEN fails the DLEQ), F3 (n/a here — constants are globals, can't be passed), C-1 (free-z/limb forgery), **F2 (rinv ≠ r⁻¹ ⇒ group eq fails)**. Reuse forge-f1/f3 logic where applicable.
- [ ] `nargo test` in the lib passes. Commit.

### Task 2 — Refactor `enroll_commit_v2` to compose the library (the fusion)

**Files:** `packages/oprf/v3-grumpkin/circuits/enroll_commit_v2/{Nargo.toml, src/main.nr}`.

- [ ] Add `grumpkin_voprf = { path = "../../lib-noir/grumpkin_voprf" }` to Nargo.toml.
- [ ] Replace the inlined SvdW maps with `grumpkin_voprf::h2c::h2c_grumpkin(u0,u1,h0,h1)`.
- [ ] Add inputs `kpub, y, dleq(c_lo,c_hi,z_lo,z_hi), rinv` (GEN is the lib global). Keep existing enrollment inputs.
- [ ] Call `let nullifier = grumpkin_voprf::oprf::oprf_verify_and_nullify(h2c_point, r, rinv, kpub, y, ...)` using the SAME `r` that derives `M`.
- [ ] Expose `nullifier` as a public output (alongside `M`, `messageDigest`). Keep `assert_canonical_svdw` removed only if h2c moves to lib (the lib owns the constants now).
- [ ] `#[test]`s: honest accept; **F2 forgery (mismatched rinv) reject**; the produced nullifier equals `pedersen(k·H2C(id))` for a fixed identity (regression vs the old two-proof nullifier — compute the expected value from lib.mjs).
- [ ] `nargo compile` + `nargo info` to RECORD the gate count (iOS budget check — flag if main ACIR opcodes push memory near the 384 MiB cap; ~277k→~307k expected). `nargo test` passes. Commit.

### Task 3 — Retire standalone oprf_commitment / oprf_nullifier

**Files:** `packages/oprf/v3-grumpkin/circuits/{oprf_commitment,oprf_nullifier}/`.

- [ ] First CONFIRM no consumer outside the enroll flow imports these (grep service/, web/, threshold/, *.mjs). If a consumer exists, STOP and report.
- [ ] Re-express each as a thin wrapper circuit that calls the library (so the lib retains direct circuit-level forgery tests), OR delete them and move their forgery tests into the lib's `#[test]`s. Keep `test-pinned-constants.mjs` working (retarget to the lib).
- [ ] `nargo compile`/test green across the package. Commit.

### Out of scope of this plan (flagged, outward-facing — needs user go-ahead)
- **Task 6 — client/service 2→1 proof + redeploy + on-device iOS prove test:** update `web/src/worker/v3prove.worker.ts`, `v3enroll.ts`, `p7sWitness.ts` (one fused proof; prove AFTER /v3/blind-eval) and `service/proof-gate.mjs`, `server.mjs` (verify one proof); redeploy web + fly service; measure real iOS prover memory. This is the integration + outward-facing deploy; do separately with explicit approval.
