# Longfellow + In-Circuit P-256 OPRF Enrollment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace crisp-qes enrollment with a single in-browser **longfellow** proof that verifies a real Diia QES cert (chained to a pinned Diia CA — §8.1) and runs a verifiable **P-256 OPRF in-circuit**, yielding the same opaque 32-byte leaf `s` the existing signing/registry stack consumes.

**Architecture:** Two longfellow repos vendored as submodules under `vendor/` (Rust prover = dev target; C++ builder = build-time circuit-gen). New in-circuit gadgets (SSWU P-256 hash-to-curve, DLEQ verify, group-equation unblind) are authored in the C++ builder, serialized, and witness-filled in the Rust/WASM prover. One proof, generated after a 1-round blind-eval, covers `cert → §8.1 → RNOKPP → age → M → DLEQ → unblind → s`. Signing circuit, contracts, and vault are untouched.

**Tech Stack:** Rust (`abetterinternet/zk-cred-longfellow` fork → `alik-eth/longfellow-rs`), C++ Longfellow builder (`alik-eth/longfellow-zk`), `wasm-bindgen` + `wasm32-unknown-unknown` (browser) / `wasm32-wasip1` (Node mem-runner), Sumcheck+Ligero, RFC 9380 `P256_XMD:SHA-256_SSWU_RO_`, Fastify OPRF service, React/Vite web.

**Spec:** `docs/superpowers/specs/2026-05-31-longfellow-oprf-enrollment-design.md`

---

## Phase map (this plan details Phase 0; later phases are scoped roadmaps, each expanded into its own plan after Phase 0)

| Phase | Subsystem | Gate / output | Detailed plan |
|---|---|---|---|
| **0** | Submodule setup + WASM memory baseline spike | Vendored + building; baseline peak-memory numbers across iOS/Android/desktop; documented headroom budget | **This document** |
| 1 | C++ builder: P-256 SSWU hash-to-curve gadget + KATs | RFC 9380 P-256 vectors pass in-circuit | after Phase 0 |
| 2 | C++ builder: DLEQ verify + group-eqn unblind + leaf `s`; re-serialize circuit; re-run mem spike on the OPRF circuit | OPRF circuit builds, proves, verifies (native); **memory verdict** vs iOS budget | after Phase 1 |
| 3 | Rust witness-fill for the new regions + WASM prove/verify surface | `p7s_oprf` prove/verify in WASM; parity Rust↔C++ | after Phase 2 |
| 4 | P-256 OPRF service (blind-eval + DLEQ) + off-chain proof verify; pin real Diia CA roots | service blind-evals, verifies proof, relayer appends `s` | after Phase 3 |
| 5 | Web integration: replace `enroll_commit_v2` worker with longfellow WASM prover + P-256 `.p7s` witness builder; bound-challenge UX | end-to-end enroll → sign on Base Sepolia | after Phase 4 |

**Hard gate:** Phase 2's memory verdict decides ship-surface (all-platform vs desktop/Android-first with iOS as follow-up). No web rollout (Phase 5) before that verdict.

---

## File structure (Phase 0)

**Create:**
- `vendor/longfellow-rs` — git submodule → `https://github.com/alik-eth/longfellow-rs` (pure-Rust prover/verifier + p7s_zk + WASM harness).
- `vendor/longfellow-zk` — git submodule → `https://github.com/alik-eth/longfellow-zk` (C++ circuit-builder).
- `.gitmodules` — two new entries (created by `git submodule add`).
- `docs/specs/2026-05-31-longfellow-wasm-baseline.md` — recorded baseline spike results + headroom budget.

**No crisp-qes source code changes in Phase 0** — this phase is vendoring + measurement only.

---

## Task 0.1: Create the standalone `alik-eth/longfellow-rs` repo from the zk-eidas subtree

**Source of truth:** `alik-eth/zk-eidas`, branch `worktree-longfellow-rust-migration`, path `crates/longfellow` (preserves the 59-test p7s work, `trust_anchors.rs`, the WASM harness, and the `abetterinternet` provenance in `UPSTREAM.md`).

- [ ] **Step 1: Subtree-split the crate into a new branch (history-preserving)**

```bash
cd ~/Develop/zk-eidas
git fetch origin worktree-longfellow-rust-migration
git checkout worktree-longfellow-rust-migration
git subtree split --prefix=crates/longfellow -b longfellow-rs-export
```
Expected: a new local branch `longfellow-rs-export` whose root is the contents of `crates/longfellow`.

- [ ] **Step 2: Create the GitHub repo and push** *(outward-facing — confirm before running)*

```bash
gh repo create alik-eth/longfellow-rs --public \
  --description "Pure-Rust Longfellow ZK (ISRG fork) with eIDAS/Diia p7s circuits + in-circuit P-256 OPRF (crisp-qes)."
git push https://github.com/alik-eth/longfellow-rs.git longfellow-rs-export:main
```
Expected: `alik-eth/longfellow-rs` exists with `main` = the crate contents. Confirm `UPSTREAM.md` (abetterinternet pin `b1e3700`) is present at the repo root.

- [ ] **Step 3: Verify it builds standalone (outside the zk-eidas workspace)**

```bash
git clone https://github.com/alik-eth/longfellow-rs.git /tmp/lf-rs-check
cd /tmp/lf-rs-check
cargo build --release --features prover
cargo test --features prover -- --test-threads=1 2>&1 | tail -20
```
Expected: builds clean; p7s tests pass. If workspace-relative `path = "../..."` deps surface, fix them in the new repo (pin to crates.io versions or vendor) until standalone build is green. Then `rm -rf /tmp/lf-rs-check`.

---

## Task 0.2: Add both longfellow repos as submodules under `vendor/`

**Files:** `vendor/longfellow-rs` (new submodule), `vendor/longfellow-zk` (new submodule), `.gitmodules`.

- [ ] **Step 1: Add the Rust prover submodule**

```bash
cd /data/Develop/crisp-qes
git submodule add https://github.com/alik-eth/longfellow-rs.git vendor/longfellow-rs
```
Expected: `vendor/longfellow-rs/` populated; `.gitmodules` gains the entry.

- [ ] **Step 2: Add the C++ builder submodule**

```bash
git submodule add https://github.com/alik-eth/longfellow-zk.git vendor/longfellow-zk
```
Expected: `vendor/longfellow-zk/` populated; `.gitmodules` gains the second entry.

- [ ] **Step 3: Pin submodule SHAs and commit**

```bash
git submodule status vendor/longfellow-rs vendor/longfellow-zk
git add .gitmodules vendor/longfellow-rs vendor/longfellow-zk
git commit -m "vendor: add longfellow-rs (Rust prover) + longfellow-zk (C++ builder) submodules"
```
Expected: commit records both submodule gitlinks at fixed SHAs.

- [ ] **Step 4: Document the vendor relationship**

Add a short `vendor/README.md` stating: `longfellow-rs` is the dev target (WASM prover/verifier, consumes serialized circuits); `longfellow-zk` is build-time only (generates/serializes circuits — the Rust side cannot build circuits). Commit.

---

## Task 0.3: Reproduce the baseline WASM prove (Node WASI memory runner)

**Goal:** Confirm the existing p7s v12 circuit proves in WASM here, and capture the *native-WASM* peak memory (the floor the OPRF circuit will sit above).

**Files:** none modified — uses `vendor/longfellow-rs/wasm-harness/`.

- [ ] **Step 1: Build the wasi memory-measurement example**

```bash
cd /data/Develop/crisp-qes/vendor/longfellow-rs
cargo build --release --target wasm32-wasip1 -p longfellow \
  --example wasm_p7s_mem --features prover
```
Expected: `target/wasm32-wasip1/release/examples/wasm_p7s_mem.wasm` exists. (If the `wasm32-wasip1` target is missing: `rustup target add wasm32-wasip1`.)

- [ ] **Step 2: Run it under Node WASI and record numbers**

```bash
node --experimental-wasi-unstable-preview1 \
  wasm-harness/wasm_mem_run.mjs
```
Expected output includes `peak_wasm_memory_bytes=…`, `peak_gib=…`, `wall_clock_seconds=…`. Record these as the **Node-WASI baseline**.

---

## Task 0.4: Reproduce the baseline browser prove (Web-Worker harness) on real devices

**Goal:** Get the *browser* peak-memory + prove-time on the platforms that actually matter — especially iOS Safari, which caps the WASM memory reservation.

**Files:** none modified — uses `vendor/longfellow-rs/wasm-harness/{index.html,worker.js,pkg/}`.

- [ ] **Step 1: Build the browser WASM package (wasm-bindgen)**

```bash
cd /data/Develop/crisp-qes/vendor/longfellow-rs
# Use the project's existing build recipe for wasm-harness/pkg (wasm-pack or
# the documented cargo + wasm-bindgen-cli step). Verify wasm-harness/pkg/
# longfellow_bg.wasm is freshly rebuilt from the current sources.
ls -la wasm-harness/pkg/longfellow_bg.wasm
```
Expected: a freshly built `pkg/longfellow_bg.wasm`. (If the build recipe isn't scripted, capture the exact wasm-pack/wasm-bindgen invocation in `wasm-harness/README` while doing this.)

- [ ] **Step 2: Serve the harness over a LAN-reachable URL**

```bash
cd /data/Develop/crisp-qes/vendor/longfellow-rs/wasm-harness
python3 -m http.server 8088 --bind 0.0.0.0
```
Note the host's LAN IP so phones on the same network can reach `http://<lan-ip>:8088/`.

- [ ] **Step 3: Run on each target device and record the result line**

Open `http://<lan-ip>:8088/` (cross-origin-isolated headers may be needed for threads — if the harness uses a SharedArrayBuffer/threaded build, serve with COOP/COEP; otherwise single-thread is fine) on:
- iOS Safari (the binding constraint),
- Android Chrome,
- desktop Chrome + desktop Safari.

For each, record from the page output: `peak_wasm_memory_bytes`, `peak_gib`, `prove_seconds`, `verify_result`, `main_thread_ticks_during_prove` (liveness). iOS "ACCEPTED" with a peak under its reservation ceiling is the key datum; an iOS tab-kill is itself a result.

---

## Task 0.5: Record the baseline + compute the OPRF headroom budget

**Files:** Create `docs/specs/2026-05-31-longfellow-wasm-baseline.md`.

- [ ] **Step 1: Write the baseline doc**

Record, in a table: per-device `peak_gib`, `prove_seconds`, accept/reject, and whether iOS completed without a tab-kill. State the **iOS reservation ceiling** observed (the largest WASM memory iOS Safari grants here — compare against the crisp-qes v3 enroll cap of 832 MiB and v2 sign cap of 384 MiB already documented in memory).

- [ ] **Step 2: State the headroom budget**

Compute and write: `OPRF gadget budget ≈ iOS ceiling − baseline peak`. The added work is one extra ECDSA (cert-chain), SSWU H2C, ~3 scalar-mults, a DLEQ, and a SHA. Note explicitly that the **real** OPRF-circuit memory is measured at the end of Phase 2 by re-running Tasks 0.3–0.4 against the new serialized circuit, and that this budget is the go/no-go reference for the all-platform vs desktop/Android-first decision.

- [ ] **Step 3: Commit**

```bash
cd /data/Develop/crisp-qes
git add docs/specs/2026-05-31-longfellow-wasm-baseline.md
git commit -m "docs: longfellow WASM prove baseline + OPRF headroom budget (Phase 0 spike)"
```

---

## Phase 0 exit criteria

1. `alik-eth/longfellow-rs` exists and builds standalone with passing p7s tests.
2. Both submodules are vendored under `vendor/` and pinned in a crisp-qes commit.
3. The existing p7s circuit proves in WASM here (Node WASI **and** browser).
4. Baseline peak-memory + prove-time are recorded for iOS Safari, Android Chrome, and desktop; the iOS reservation ceiling is identified.
5. The OPRF headroom budget is written and committed — the explicit input to the Phase 2 ship-surface gate.

---

## Phases 1–5 — scoped roadmap (each expanded into its own bite-sized plan after Phase 0)

### Phase 1 — P-256 SSWU hash-to-curve gadget (C++ builder)
- **Files:** new gadget under `vendor/longfellow-zk/lib/circuits/` (alongside `ecdsa/`), reusing `lib/ec/p256.{h,cc}` + the `Logic`/`BitPlucker` SHA primitives.
- **Interface:** in-circuit `H2C_P256(msg_bytes) -> (x,y)` implementing RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` (expand_message_xmd + SSWU map_to_curve; cofactor 1).
- **Tests:** RFC 9380 Appendix J P-256 known-answer vectors, in-circuit, accept/reject.

### Phase 2 — DLEQ + unblind + leaf, re-serialize, memory verdict (C++ builder)
- **Files:** extend the p7s circuit (`lib/circuits/p7s/`) to add: DLEQ verify (`a1=z·G−c·K`, `a2=z·M−c·Y`, FS challenge over SHA-256), group-eqn unblind (`assert r·N==Y`), `s=SHA256(N.x‖N.y)` reduced into BN254; wire `trust_anchor_index` to real Diia roots. Re-serialize the circuit blob (`circuit_data` ZST).
- **Tests:** DLEQ accept/reject; unblind KAT; `s` KAT; full synthetic-cert prove/verify (native). **Re-run Tasks 0.3–0.4** → record OPRF-circuit peak memory → **ship-surface gate**.

### Phase 3 — Rust witness-fill + WASM surface (`longfellow-rs`)
- **Files:** `src/p7s_zk/{witness_fill,witness,public_inputs}.rs`, `src/js_api.rs` (add `p7s_oprf_prove`/`verify`), `circuit_data.rs` (embed new blob).
- **Tests:** Rust↔C++ parity on ≥3 fixtures; wasm-bindgen-test for the prove/verify surface.

### Phase 4 — P-256 OPRF service + real Diia CA pin (`packages/oprf`)
- **Files:** new/rewritten Fastify service: P-256 key `k`, `POST /blind-eval {M}->{Y,K,dleq}`, `POST /register {π,public}` → off-chain longfellow verify → relayer append `s`; rate-limit on blind-eval; epoch label. Pin the Diia QTSP CA P-256 keys from `docs/specs/2026-05-31-multi-country-per-circuit-design.md`.
- **Tests:** blind-eval/DLEQ KAT; proof-accept/reject; duplicate-leaf → AlreadyEnrolled.

### Phase 5 — Web integration (`packages/web`)
- **Files:** replace `src/worker/v3prove.worker.ts` enroll path with the longfellow WASM prover; new P-256 `.p7s` witness builder (replacing `p7sWitness.ts`'s enroll role); keep the bound-challenge staged UX (`V3Enroll.tsx`), challenge embeds `M`; thread `r`, `N`, leaf `s` into the unchanged vault + signing flow.
- **Tests:** unit (witness builder, challenge bytes), E2E enroll → sign on Base Sepolia; negative (bad anchor, tampered signedAttrs, swapped Y, under-18).

---

## Self-review notes
- **Spec coverage:** every spec §3–§5 component maps to a phase; §8.1 lands in Phase 2/Phase 4 (pin), OPRF gadgets in Phases 1–3, service in Phase 4, web in Phase 5, the memory risk (§8.1) front-loaded in Phase 0 + gated in Phase 2.
- **No fabricated crypto code:** Phase 0 (concrete setup/measurement) is fully bite-sized; Phases 1–5 are scoped because their gadget-level steps depend on the builder API + the Phase-0 baseline, and are written as separate plans then — per the writing-plans decomposition guidance.
- **Type consistency:** leaf `s` is a BN254-field-reduced `SHA256(N.x‖N.y)` consistently in spec §3.2/§4 and Phases 2/3/5.
