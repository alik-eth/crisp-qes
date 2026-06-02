# Security Review — CRISP-QES v3 Grumpkin VOPRF

**Scope:** `oprf_commitment`, `oprf_nullifier`, `enroll_commit_v2`, `qes_frontend` circuits; `packages/oprf/v3-grumpkin` JS (lib, threshold, service); `packages/web/src/lib/grumpkin.ts`.
**Status of target:** Documented EXPERIMENTAL / UNAUDITED. This review treats it against its own stated threat model (obliviousness, verifiability, one-pseudonym-per-identity, unlinkability, SNARK soundness).
**Date:** 2026-06-02. Reviewer model: claude-opus-4-8.

---

## 1. Executive Summary

**The scheme is NOT sound as deployed.** The OPRF math (blind → DLEQ-evaluate → unblind → nullifier) is correct on paper, and the prior C-1 DLEQ-challenge-binding fix is genuinely in place and complete. However, the v3 circuits are **under-constrained in three independent and mutually-reinforcing ways that each, alone, completely break the central anti-Sybil guarantee** (one-pseudonym-per-identity). A single legitimately-enrolled citizen can mint an unbounded number of distinct, mutually-unlinkable nullifiers — corrupting any petition tally or vote built on this enrollment.

The three root causes are all the same class of bug: **a security-critical value is accepted as a free witness / unpinned public input and never tied to the canonical protocol value.**

1. **`rinv`/`r` are free witnesses** in `oprf_nullifier` — the unblind re-scales `Y` by an arbitrary scalar. `N` is attacker-chosen.
2. **The generator `G` is an unpinned public input** in `oprf_nullifier` — the DLEQ proves equality of logs against an *attacker-chosen base*, so the attacker picks the effective key `k'` and never needs a real node evaluation.
3. **The SvdW suite constants `c1..c4` are unpinned public inputs** in both `oprf_commitment` and the **deployed** `enroll_commit_v2` — the prover redefines hash-to-curve, so one identity maps to arbitrarily many on-curve points.

Each is independently exploitable through the live `POST /v3/register` path; the only server-side dedup is an exact-match on the `pedersen(N)` leaf (`server.mjs:557`), which never fires on genuinely-distinct forged values. The verifier-side gate (`proof-gate.mjs`) pins `M`, `Kpub`, and the commitment, but none of these pin `N`, `G`, `Y`, or `c1..c4` to canonical values.

A medium-severity privacy finding (deterministic, salt-free, single-key enrollment leaf over a brute-forceable RNOKPP space) is also confirmed and lets a curious keyholder de-anonymize the registry offline.

**Bottom line:** the cryptographic design is salvageable, but the circuits must be re-constrained (pin G and c1..c4 as in-circuit constants; bind the nullifier blind to the enrollment blind) before any of the soundness guarantees hold. Do not treat current nullifiers as Sybil-resistant.

---

## 2. Findings Table (sorted by final severity, deduplicated)

The synthesis input contained eight findings spanning multiple "dimensions" that collapse to **three distinct circuit root causes** plus one privacy issue. They are deduplicated below.

| # | Severity | Root cause | Location | Property broken |
|---|----------|-----------|----------|-----------------|
| **F1** | **Critical** | Unconstrained generator `G` in `oprf_nullifier` (DLEQ base reparameterizable; attacker chooses effective key, no real eval needed) | `oprf_nullifier/src/main.nr:27,37,51,58`; `proof-gate.mjs:249,336-397` | one-pseudonym-per-identity, verifiability, OPRF-binding |
| **F2** | **Critical** | Free `rinv`/`r` witnesses — `r*N==Y` does not bind `N` to the identity; nullifier malleable | `oprf_nullifier/src/main.nr:63-71` | one-pseudonym-per-identity, unlinkability |
| **F3** | **Critical** | Unconstrained SvdW constants `c1..c4` redefine hash-to-curve (also in **deployed** `enroll_commit_v2`) | `oprf_commitment/src/main.nr:51-52,60-61`; `enroll_commit_v2/src/main.nr:297-300,440-441`; `proof-gate.mjs:270-313` | one-pseudonym-per-identity |
| **F4** | **Medium** | Deterministic, salt-free, single-key enrollment leaf over brute-forceable RNOKPP space | `oprf_nullifier/src/main.nr:71`; `server.mjs:557-566` | obliviousness vs operator; cross-context linkage (conditional) |

**Severity reconciliation notes:**
- F1 was reported variously as `high` and `critical`. Verifiers split, but the majority and the strongest analyses rate it **critical**: the G-substitution attack needs *no real OPRF evaluation* (forge eligibility from the public `Kpub` alone) and yields unbounded nullifiers. **Final: critical.** One verifier kept `high` solely on the "EXPERIMENTAL/UNAUDITED" caveat; that caveat does not change the soundness fact, so it is not allowed to lower severity here.
- F2 and the "group-equation r*N==Y does not bind N" and "nullifier malleable" findings are the **same bug** across three dimensions (`protocol`, `dleq`, `circuit_nullifier`). All verifiers unanimously **critical**. Deduplicated to F2.
- F3's two presentations (`circuit_commitment` critical; `curve_params` high) are the **same bug**. The deciding factor is that it is live in the **deployed** `enroll_commit_v2`, not just the experimental v3 path. Verifiers split critical/high; because it independently grants unbounded Sybil pseudonyms from one cert in production, **final: critical**.
- F4: one verifier marked the cross-context half `real=false` (the per-petition nullifier layer *does* fold `petition_id` — see appendix), but the operator-rainbow-table half is confirmed by the majority. **Final: medium**, scoped to the operator-deanonymization claim.

> Note: F1, F2, and F3 are **independent** — fixing any one does not fix the others. F4 (enrollment-leaf privacy) is partly *amplified* by F1/F2 (attacker-controlled N) but stands as a separate design issue.

---

## 3. Per-Finding Detail

### F1 — Critical: Generator `G` is an unpinned public input in `oprf_nullifier`

**Location:** `packages/oprf/v3-grumpkin/circuits/oprf_nullifier/src/main.nr:27` (`gx: pub Field, gy: pub Field`), `:37` (`g = Pt{x:gx,y:gy,is_infinite:false}`), `:51` (`a1 = multi_scalar_mul([g, neg(kpub)],[z,c])`), `:58` (G in the Fiat-Shamir transcript). Verifier: `proof-gate.mjs:249` extracts `p.G`, `:336-397` never compares it to the canonical generator.

**Attack (no real OPRF evaluation needed).** `Kpub = k·G_canonical` is public and is the only thing the gate pins (`proof-gate.mjs:366`). A malicious client:
1. Picks any scalar `k'` it knows.
2. Sets the substituted base `G' = (k')⁻¹·Kpub` (a valid on-curve prime-order point) so that `Kpub = k'·G'`.
3. Sets `Y = k'·M` for the cert-bound `M`.
4. Produces an **honest** Chaum-Pedersen DLEQ over base `G'`: nonce `t`, `a1=t·G'`, `a2=t·M`, `c=pedersen([G',Kpub,M,Y,a1,a2])`, `z=t+c·k'`.

Every in-circuit assert passes — including the C-1 binding `c_lo + c_hi·2¹²⁸ == ch == c_expected` (lines 60-61), because `c` is the genuine transcript hash over the attacker's own `G'`. The group-eq unblind `r·N==Y` holds for `r=rinv⁻¹`. The result is `N = rinv·Y = k'·H2C(id)` for **attacker-chosen `k'`**, so `pedersen(N)` takes unbounded distinct values for one identity. (Confirmed by an actual `nargo execute` run in verification: "Circuit witness successfully solved.")

**Impact.** Defeats one-pseudonym-per-identity (unbounded Sybil from one Diia cert), and breaks verifiability/OPRF-binding outright — the node never has to evaluate the user's `M`. The `proof-gate.mjs:80` comment claiming "word [0] is the fixed 0x..01" describes a check that does not exist.

**Fix.** Hardcode the Grumpkin generator as an in-circuit `global GEN_X=1, GEN_Y=17631683881184975370165255887551781615748388533673675138860` and build `g` from it; **drop `gx,gy` from the ABI**. If they must remain (transcript symmetry with JS), `assert(gx==GEN_X); assert(gy==GEN_Y)`. Defense-in-depth: have `verifyNullifierProof` reject `p.G != Point.BASE`, and additionally pin the proof's `Y` to the node's actually-issued evaluation.

---

### F2 — Critical: `rinv`/`r` are free witnesses; nullifier is malleable

**Location:** `oprf_nullifier/src/main.nr:63-71` (`rinv` line 64, `r` line 65, `n = rinv·Y` line 66, `ycheck = r·n` line 67, `assert(ycheck==y)` line 68, `pedersen([n.x,n.y])` line 71).

**Attack.** `rinv` and `r` are fully free 128-bit-limb private witnesses, tied only by `r·(rinv·Y)==Y`. On prime-order Grumpkin (cofactor 1, order `N` prime per `lib.mjs`), for `Y≠O` this collapses to `r·rinv ≡ 1 (mod N)` — satisfiable by **any** invertible `s` via `rinv:=s, r:=s⁻¹ mod N`. Then `N = s·Y` is an arbitrary group element and the nullifier `pedersen(s·Y)` is attacker-chosen. Nothing ties this circuit's `r` to the enrollment blind `r₀` that built `M` (it lives in a separate circuit and `enroll_commit_v2` exports no commitment to `r` — `enroll_commit_v2/src/main.nr:445` returns only `(m.x,m.y,digest_hi,digest_lo)`). `M` is public but enters only the DLEQ recompute (`a2 = z·M - c·Y`, line 52); it never constrains `N`.

A single honest enrollment + one honest `Y=k·M` yields, for each chosen `s_i`, a distinct valid proof with identical pinned `M`/`Kpub` and a fresh `pedersen(s_i·Y)`.

**Impact.** Unbounded distinct registrations from one identity. The server's only dedup is `leafIndexOf.has(commitment)` (`server.mjs:557`) — distinct values sail through.

**Fix.** Bind the unblind to the *same* blind that formed `M`. Either (a) have `enroll_commit_v2` output a hiding commitment to `r` (e.g. `r·G` or `pedersen(r)`) that `oprf_nullifier` must reproduce from its `r` witness, OR (b) fuse blind+unblind into one circuit that recomputes `H2C(id)` and asserts `M = r·(P0+P1)` **and** `N = rinv·Y` for the same `(r,rinv)` with an explicit range-checked `r·rinv==1 mod N`. Note `r·N==Y` alone is insufficient — that is exactly what is deployed and broken.

---

### F3 — Critical: SvdW constants `c1..c4` are unpinned (incl. deployed `enroll_commit_v2`)

**Location:** `oprf_commitment/src/main.nr:51-52,60-61`; `enroll_commit_v2/src/main.nr:297-300,440-441`; verifier `proof-gate.mjs:270-313` (and the doc-only comment at `:25`).

**Attack.** `c1,c2,c3,c4` are `pub Field` inputs threaded straight into `svdw_map` as the *entire* RFC-9380 suite parameterization (`tv4 = u·tv1·inv_t·c3; x1=c2-tv4; x2=c2+tv4; x3=t²·c4+Z`). The circuit only ever forces the **selected** `x` on-curve (`assert(sqrt_x*sqrt_x==gx)`, line 41) plus the squareness gadgets — it **never** asserts the defining relations `c1=g(Z)`, `2·c2+Z=0`, `c3²=-c1·(3Z²+4A)`, `c4·(3Z²+4A)=-4·c1` (only `BCURVE=-17`, `ZETA=5`, `SVDW_Z=1` are globals). So for fixed identity material `(u0,u1)`, a malicious prover supplies a different valid `(c1,c2,c3,c4)` (e.g. scale/offset variants, or the degenerate `c3=0` so `x1=x2=c2`, choosing `c2` = x-coord of any on-curve point) and lands `H2C'(id)` on a *different* on-curve point with all asserts satisfied. Distinct H2C' → distinct `M=r·H2C'` → distinct `Y=k·M` → distinct `N=k·H2C'` → distinct nullifier.

This was empirically reproduced: scaling only `c4` (preserving the x3-selection path) produced 6 distinct on-curve H2C points from the same `(u0,u1)`, each passing every assertion.

**Impact.** Unlimited distinct pseudonyms from one identity — **and it is live in the deployed `enroll_commit_v2`**, not only the experimental v3 path. The `nullifier`-gate binds `nullifier.M == enroll.M`, but both share the same forged H2C', so every variant passes. The self-audit's `vectors.test.mjs` check that "c1..c4 == lib's" is an *off-circuit* JS check and proves nothing about what the circuit accepts.

**Fix.** Make `c1..c4` in-circuit `global` constants (like `BCURVE`/`ZETA`/`SVDW_Z`) and **remove them from the ABI** in both circuits. If they must stay as inputs, assert each defining relation in-circuit. Defense-in-depth: have `proof-gate.mjs` reject any proof whose `publicInputs[8..12] != canonical SVDW_CONSTS`. (Minor: `A=0` on Grumpkin so the `+4A` term vanishes; relations simplify to `c3²=-3·c1·Z²`, `3·c4·Z²=-4·c1`.)

---

### F4 — Medium: Deterministic salt-free single-key enrollment leaf is offline-deanonymizable

**Location:** `oprf_nullifier/src/main.nr:71` (`pedersen([n.x,n.y])`); `server.mjs:557-566` (appended to global `EnrollmentRegistry`); single key `server.mjs:663-679` / `oprf-node.mjs:84`.

**Attack.** The leaf is `pedersen([N.x,N.y])` with `N = k·H2C(RNOKPP)`, a single global key `k`, **no petition/epoch/domain separator folded into the committed value**, and `H2C` over the bare RNOKPP (single fixed DST `lib.mjs:75`). RNOKPP is a 10-digit checksummed Ukrainian taxpayer ID — ~10⁷–10⁸ effective candidates. A curious/malicious operator (who holds `k`) enumerates all valid RNOKPPs, computes `pedersen(k·H2C(id))` per candidate, builds a rainbow table, and maps every on-chain leaf back to a concrete RNOKPP — fully de-anonymizing the registry post-hoc. Obliviousness protects the in-flight blinded `M`, but not the published deterministic leaf against the keyholder.

**Scope honesty.** The *cross-context* half is largely mitigated already: the per-petition nullifier (`packages/circuit/src/main.nr`) folds `petition_id` + a domain tag, so two petitions by the same citizen are unlinkable, and the enrollment secret is a private Merkle-membership witness, not republished per petition. The confirmed residual is the **operator rainbow-table deanonymization** of the enrollment registry itself.

**Fix.** (a) Keep `k` under a genuine threshold so no single party can compute `k·H2C(id)` (the deployed service uses single-key; `threshold-oprf.mjs` is an undeployed prototype with `kImplied` marked test-only — see appendix). (b) Treat RNOKPP brute-forceability as an explicit documented threat. (c) Where any enrollment-derived value is consumed across contexts, fold a public context tag into the committed value.

---

## 4. Status of Prior C-1 / C-3 Self-Audit Fixes

| Item | Claim | Verified status |
|------|-------|-----------------|
| **C-1** — DLEQ challenge limbs bound to recomputed transcript hash | Fixed | **CONFIRMED CLOSED.** `oprf_nullifier/src/main.nr:58-61`: `ch = pedersen_hash([gx,gy,kpx,kpy,mx,my,yx,yy,a1.x,a1.y,a2.x,a2.y])`, `assert(c_lo + c_hi·2¹²⁸ == ch)`, `assert(ch == c_expected)`. The free-`z`/free-limbs forgery (the `forge-nullifier-witness.mjs` probe targets) is correctly blocked. **No regression.** Note: this fix is *orthogonal* to F1 — the G-substitution attack uses an honest `c` over the attacker's `G'`, so C-1 does not catch it. |
| **C-3** — scalar-limb 128-bit range checks / unique decomposition | Hygiene | **PARTIALLY CLOSED.** `c_lo,c_hi,z_lo,z_hi` are range-checked (`:43-46`). **`rinv_lo,rinv_hi,r_lo,r_hi` are NOT range-checked** (`:64-65`). This is a minor residual on its own (considered, not independently severity-bearing — see appendix), but it sits inside the F2 critical: the missing constraint that matters for F2 is the *binding to the enrollment blind*, not the range check. The commitment-circuit `r_lo/r_hi` are likewise unchecked. |

Net: C-1 is a real, complete fix. C-3 is incomplete (rinv/r limbs unchecked), but the dominant defect on those witnesses is F2's missing identity-binding, not the range gap.

---

### 2026-06-02 — F2 deploy (two-proof + shared-`r` commitment) landed on `feat/voprf-security-fixes`

The confirmed-CRITICAL set **F1, F2, F3 is now CLOSED in the deployed (off-chain-gated) path.** The fix extracts the VOPRF primitives into a reusable `grumpkin_voprf` Noir library and rewires the deployed two-proof enrollment flow to compose it. The deployed path stays **two proofs** (enroll gates `/v3/blind-eval`; nullifier runs at `/v3/register`) deliberately — a fused single proof would have to move after blind-eval, opening the OPRF to an oracle (RNOKPP-guessing deanonymization), so F2 is closed by **binding the same `r` across the two proofs** rather than by fusion.

- **F1 (DLEQ generator substitution) — CLOSED BY CONSTRUCTION.** `oprf_nullifier` no longer takes `gx,gy` as inputs; the DLEQ base is `grumpkin_voprf::params::GEN_X/GEN_Y`, a pinned in-circuit global. The attacker has no witness slot for a substituted `G' = (k')⁻¹·Kpub`, so the attack is unexpressible. Asserted by `test-pinned-constants.mjs` ("oprf_nullifier ABI has no [gx, gy] input").
- **F2 (free `rinv`/`r` → unbounded Sybil nullifiers) — CLOSED, LIVE-VERIFIED.** The enroll proof publishes `C_r = commit_r(r) = pedersen([CR_DOMAIN, r_lo, r_hi])`; the register proof (`oprf_nullifier`) takes `C_r` as a public input and asserts `commit_r(r) == C_r` (Pedersen-binds its `r` to the enroll blind) **and** `r·N == Y` (forces `rinv = r⁻¹`), yielding the canonical `N = k·H2C(id)`. The service additionally hard-checks **(a)** `nullifier.M == enroll.M` (identity binding, non-skippable) and **(d)** `nullifier.C_r == enroll.C_r`. Live-verified: the forgery the **pre-fix standalone accepted** (rinv = 2·r⁻¹, free `r`) is now REJECTED at `"F2: r*N != Y"`, and a wrong-`r` commitment (`C_r+1`) at `"c_r mismatch (r != enroll r)"`, with `e2e-test.mjs` independently showing the tampered-`c_r` reject + determinism/distinctness. (The original single-key `forge-f2-nullifier-witness.mjs` was retired when `oprf_nullifier` became the threshold circuit; the deployed-circuit F2 rinv guard is now `forge-threshold-witness.mjs`'s `(F-rinv)` case, and the single-key F2 coverage lives in the `grumpkin_voprf` lib tests.)
- **F3 (non-canonical SvdW suite) — CLOSED BY CONSTRUCTION.** `c1..c4` (+ `SVDW_Z`, `ZETA`, `BCURVE`, `DST`) are `grumpkin_voprf::params` globals consumed by `h2c`; `enroll_commit_v2` no longer takes them as inputs, so hash-to-curve cannot be redefined. The standalone `oprf_commitment` circuit (and its `forge-f3-*` probes) were retired. Asserted by `test-pinned-constants.mjs` ("enroll_commit_v2 ABI has no [c1, c2, c3, c4] input").
- **C-1 / C-3** are carried into the library: `dleq::verify_dleq` keeps the limb-bound Fiat-Shamir challenge (C-1), and `oprf`/`dleq` range-check the `r`/`rinv`/`c`/`z` limbs to 128 bits (closes the C-3 residual called out above).

**Caveat (not overclaiming):** the deployed `enroll_commit_v2` bb-proof is **not** run end-to-end locally — its `assert_ca_pinned` requires a PRODUCTION Diia CA that a synthetic cert cannot satisfy (and we must not add a test CA to the pinned set nor use real PII). The enroll circuit is covered by its own `#[test]`s + the lib `h2c`/`M` tests; the locally-runnable e2e exercises node-eval + the nullifier register proof + C_r + determinism. **F4 is unchanged** (operator rainbow-table deanonymization of the deterministic enrollment leaf) — it is only mitigated once `k` is genuinely threshold/multi-operator distributed (checklist #7/#8, the next workstream). The scheme remains **EXPERIMENTAL / UNAUDITED** pending external audit (checklist #10).

Commits (branch `feat/voprf-security-fixes`): `c9d3b51`/`4f712a9` (grumpkin_voprf lib: `commit_r` + `oprf_nullify_bound`, domain-separated `C_r`), `0197f06` (enroll_commit_v2 → two-proof gate + `C_r` output), `39345a0` (oprf_nullifier rewrite over the lib + `C_r`), `affb252` (service: `C_r` cross-check + 13/8-word layouts), `ae7c0e0` (web client), `1e4fec8` (e2e). The earlier F1/F3 pin + lib extraction landed in `8da263b` / `2bc0a3a` / `a7c9131`.

---

### 2026-06-02 — Threshold OPRF (2-of-3) landed on `feat/voprf-security-fixes`

The OPRF key is now Shamir-shared across a **2-of-3 threshold**: no single party holds or reconstructs `k`. Each node `i` computes only `B_i = k_i·M` on the blinded `M`, and the register proof forms `Y = Σ λ_i·B_i` by an **in-circuit** Lagrange combine (the key is never assembled). This closes review **#7** and changes **F4**'s status.

- **#7 (threshold-hardening soundness gaps) — CLOSED.**
  - **Per-share DLEQ verification is now IN-CIRCUIT.** For each of the t=2 responders, `grumpkin_voprf::dleq::verify_dleq_share` proves `B_i = k_i·M` vs the responder's published `Kpub_i` against the **pinned GEN** (F1), with the C-1 limb binding. A faulty/malicious node whose `B_i ≠ k_i·M` is caught — live-verified by the e2e cheating-node case and the `forge-threshold-witness.mjs` `(F-share)` rejection.
  - **`combine()` index dedup enforced.** In-circuit, `select_lagrange_2of3` asserts a canonical distinct 2-of-3 responder set (`"invalid 2-of-3 responder set"` on a dup/non-canonical pair); in JS, `combine()` throws on duplicate indices. (`(F-dup)` rejection.)
  - **Session/epoch binding.** `epoch` is appended to every per-share DLEQ transcript (the 13-element `pedersen([GEN,Kpub_i,M,B_i,a1,a2,epoch])`), and the service cross-checks **(f)** `epoch == current enrollEpoch`. A stale-epoch partial fails the limb binding (`(F-epoch)` rejection).
  - **idx→Kpub bound in-circuit + self-attested combine.** `select_kpub_3` selects each responder's `Kpub` from the PUBLISHED 3-node set by index (no mislabel — `(F-kpubswap)` rejection), and `Y` is computed in-circuit with **pinned mod-N Lagrange coefficients** (no free `Y` input). The register proof self-attests the t-of-n eval; the service pins only `M`/`C_r`/the published `Kpub` set/`epoch`/the commitment (cross-checks (a)/(c)/(d)/(e)/(f)). Live-verified by the e2e **subset-determinism** (same identity → same leaf for responder subsets {1,2}, {1,3}, {2,3}) and **distinctness**, plus all four `forge-threshold-witness.mjs` rejections.

- **F4 (operator deanonymization of the deterministic leaf) — MITIGATED BY DESIGN, pending independent operators + verifiable DKG.** With 2-of-3, no single party can compute `k·H2C(id)`, so the offline rainbow-table deanonymization now requires **≥2 colluding keyholders**. **CAVEAT (operational, not a code property):** real mitigation requires the 3 nodes to be run by **INDEPENDENT operators**; the demo may co-host all 3 under one operator (which does NOT yet achieve independence — F4 is not mitigated in that configuration). Keygen is **demo-grade**: a seed-derived dealer/DKG-lite (`dkgKeygen`, restart-stable via `V3_THRESHOLD_SEED`), **not** a production verifiable DKG. So F4 is *"mitigated by design / pending independent-operator deployment + verifiable DKG,"* not fully closed.

**Still EXPERIMENTAL / UNAUDITED — out of scope here:** production **verifiable DKG** (Feldman/Pedersen commitments + complaint round) replacing the demo dealer; **independent-operator deployment** of the 3 nodes (the real F4 mitigation); **redeploy** (web + Fly: 3 node services) + an **on-device iOS** prove test; **external audit** (checklist #10). The single-key path remains only as legacy `OprfNode` (roundtrip/gating tests).

Commits (branch `feat/voprf-security-fixes`): `b33ae7a`/`8d9028d` (grumpkin_voprf lib: `verify_dleq_share` epoch-bound + pinned 2-of-3 Lagrange + `oprf_nullify_threshold` + in-circuit idx→kpub), `0a7e6f4` (oprf_nullifier → threshold 13-word ABI), `6b59ff7` (JS `dleqProveShare`/`verifyDleqShare` + combine dedup + threshold witness generator), `5964dc2` (service `ShareNode` + `makeNodes`), `735897d`/`a7b9d5a` (service: threshold register verify + published-Kpub/epoch cross-checks + seed-derived stable share set), `4a1997d`/`4f5dfd3` (web client: blind-eval fan-out + 13-word threshold witness, canonical responder order), `7330873` (e2e: fan-out + in-circuit combine + subset-determinism + cheating-node reject).

---

## 5. Path to Production-Grade — Checklist

| # | Task | Effort |
|---|------|--------|
| 1 | **Pin generator `G`** as in-circuit `global` in `oprf_nullifier`; drop `gx,gy` from ABI; add `verifyNullifierProof` G-equality + Y-binding defense-in-depth (closes F1) | S (~0.5 day + VK regen) |
| 2 | **Pin SvdW `c1..c4`** as in-circuit globals in `oprf_commitment` AND deployed `enroll_commit_v2`; drop from ABI; proof-gate reject non-canonical words (closes F3) | S–M (~1 day + VK regen; coordinate with deployed enrollment) |
| 3 | **Bind nullifier blind to enrollment blind** — export hiding commitment to `r` from `enroll_commit_v2`, reproduce in `oprf_nullifier`, or fuse blind+unblind and recompute `H2C(id)` in-circuit; add `r·rinv==1 mod N` with range-checked limbs (closes F2 + C-3 residual) | M (~2–4 days; circuit redesign + cross-circuit wiring) |
| 4 | **VK / fold key-hash regeneration** after every circuit change, using the `bb` bundled in `@aztec/bb.js` (NOT the CLI on PATH) via `scripts/crisp-fhe/regen-fold-keyhash.sh`; note `secure-8192` OOMs locally (~29 GiB → high-mem host) | M (per the bb-version memory note; easy to get wrong) |
| 5 | **On-curve / non-identity checks** for all public input points (G, Kpub, M, Y) — the MSM blackbox does not validate them (considered item; cheap belt-and-suspenders) | S |
| 6 | **Randomness hygiene** — fix modulo bias in browser blind-scalar sampling (256-bit mod (N-1)) and DLEQ nonce derivation; rejection-sample or wide-reduce (considered items; not independently exploitable today but should be closed) | S |
| 7 | **Threshold hardening** — implement per-share AND combined DLEQ verification in `combine()`, require distinct node indices, add session/epoch binding to partials; remove `kImplied` test-only path from any production build (considered items; threshold path is currently undeployed but unsafe if enabled) | M–L |
| 8 | **Real-cert binding for enrollment leaf** — keep `k` genuinely threshold-distributed, add domain separation to any cross-context-reused committed value, document RNOKPP brute-forceability (closes F4) | M |
| 9 | **Curve-param confirmation** — Grumpkin prime-order/cofactor-1 already confirmed (no cofactor/twist attack); document the canonical generator + SvdW suite as pinned constants alongside the circuits | XS (documentation) |
| 10 | **External audit** of the re-constrained circuits before any production/tally use; add the F1/F2/F3 forgery witnesses as permanent regression probes alongside `forge-nullifier-witness.mjs` | L (external) |

Effort key: XS < S < M < L (hours → days → ~week → multi-week/external).

---

## 6. Appendix — Considered, Not Confirmed (coverage)

These were investigated and **refuted, confirmed-fixed, or judged non-bearing** by the refute-by-default verification. Listed so the reader sees coverage breadth.

**Confirmed fixed / sound (no action):**
- C-1 DLEQ challenge binding present and complete (see §4).
- SvdW squareness selection (`e1,e2`/`assert_is_square`) is sound *given canonical constants* (F3 is about the constants, not the selection).
- Grumpkin is prime-order (cofactor 1); SvdW suite constants are mathematically correct — no cofactor/twist attack on M,Y.
- Deployed service uses single-key OPRF only — no node reconstructs `k`; `kImplied` is genuinely test-only and not wired into `server.mjs`.
- Verifiers fail closed: `bb.js` throws → `{ok:false, ProofRejected}`; no panic-as-accept, no DoS-as-bypass; `wordToBE32` rejects over-32-byte/non-hex words. (The "G not cross-checked" note within this dimension is the real issue, escalated and captured as **F1**.)
- Per-petition nullifier *does* fold `petition_id` + domain tag — refutes the cross-context-linkage half of the enrollment-leaf finding (F4 narrowed to operator deanonymization).

**Refuted / minor / non-independently-bearing:**
- Missing 128-bit range checks on `rinv/r` (nullifier) and `r` (commitment) — real C-3 residual, but subsumed by F2's binding fix; not independently severity-bearing.
- No client-side DLEQ verification before unblind — griefing only; deanonymization risk required a C-1 regression that did not occur.
- Public points G,Kpub,M,Y not on-curve/non-identity validated — captured as checklist item 5.
- Challenge limb decomposition `c_lo + c_hi·2¹²⁸` non-uniqueness / mod-P aliasing — the explicit `== ch == c_expected` over a `pedersen` output (< P < N) makes the practical decomposition unique; not exploitable.
- `enroll_commit_v2` messageDigest read from a free offset without attribute-OID/contentType/uniqueness check, and **not bound in-circuit to this proof's `M`/`r`/nullifier** (`signed_attrs`/`msg_digest_off` are free witnesses) — a valid Diia holder can emit a proof pairing their identity's (deterministic) nullifier with an arbitrary authenticated messageDigest. Flagged as enrollment hygiene / freshness, not in the confirmed critical set: impact is bounded because the post-F2 nullifier is deterministic per identity (no Sybil leverage from a swapped digest) and the session/challenge↔messageDigest freshness check lives service-side (`server.mjs`/`proof-gate.mjs`, spec §6). Re-confirmed during the Task 2 fusion review (commit 272eb31) — pre-existing, orthogonal to F2; revisit alongside the challenge-binding model.
- `qes_frontend` takes `msghash` as a free witness (self-asserted identity) but is **not wired into the deployed service** — prototype only.
- Blinding-scalar / DLEQ-nonce modulo bias and weak domain separation (potential HNP instance against `k`) — randomness hygiene; checklist item 6.
- Threshold: no per-share/combined DLEQ verification; `combine()` permits duplicate indices; shares lack session/epoch binding — all real but on the **undeployed** threshold path; checklist item 7.
- `is_infinite:false` hardcoded on map output; `p0==-p1`/infinity edge cases — low-probability edge, captured under on-curve/identity checks.

**Files inspected directly during this review:** `oprf_nullifier/src/main.nr` (full), `oprf_commitment/src/main.nr` (full) — both confirm the cited constraint gaps verbatim. Remaining locations (`enroll_commit_v2`, `proof-gate.mjs`, `server.mjs`, `lib.mjs`, `grumpkin.ts`, threshold) corroborated via the multi-verifier synthesis.