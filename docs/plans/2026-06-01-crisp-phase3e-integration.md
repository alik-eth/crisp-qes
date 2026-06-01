# CRISP-QES Phase 3e Integration Plan — monorepo submodule + locally-runnable encrypted tally

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** From a clean civic-voice checkout, build the forked E3 stack with the toolchain hard-pinned, bring up a local self-run committee, and run a scripted end-to-end **encrypted QES vote** (real vote → mask → double-vote rejection → fake-zkVM tally → `decodeTally`).

**Architecture:** The forked E3 stack stays its own repo (`alik-eth/crisp-qes-enclave`), pulled into civic-voice as a **git submodule** under `vendor/`. The *circuits/contract/SDK are already QES-correct + on-chain-validated* (Phase 3); this plan adds (a) reproducible build with `bb` pinned to the bb.js-bundled binary, and (b) the **QES plumbing** that's still pre-QES (deploy script, Rust coordination-server routes, daemon slot source, tally driver) so the local stack actually runs a QES round. Most tasks land in the **fork** (`vendor/crisp-qes-enclave/examples/CRISP`, == the `/tmp/enclave` working copy); the monorepo gets the submodule pointer + bootstrap + the E2E entrypoint.

**Tech Stack:** pnpm workspace (monorepo); Noir 1.0.0-beta.19 + `bb`/`@aztec/bb.js` **3.0.0-nightly.20260102** (use the binary bundled in bb.js — NOT the CLI on PATH); Rust + actix-web (coordination server) + Hardhat (deploy); Foundry anvil; TypeScript (SDK + daemon).

**Reference:** `docs/specs/2026-06-01-crisp-phase3e-integration.md` (this plan's spec), `docs/2026-06-01-crisp-phase3-e2e.md` (Phase 3 results), memory `reference_bb_cli_vs_bbjs_version`.

**Scope guardrails:** IN = submodule + pinned build + QES plumbing + scripted local E2E. OUT = Base Sepolia deploy, web vote UI, `PetitionRegistry.tallyMode`, Interfold prod committee, real-Diia enrollment. Do NOT modify circuit/verifier/contract LOGIC (frozen + validated); only deploy/server/daemon/build/test code.

---

## Repos & working copies

- **Monorepo:** `/data/Develop/crisp-qes` (branch `feat/crisp-fhe-tally`). Commit here for Tasks 0 + 5's monorepo bits.
- **Fork:** `alik-eth/crisp-qes-enclave` @ `main`. Working copy = `/tmp/enclave` (already pushed; commit + `git push civicvoice main --no-verify` for fork changes — the pre-push husky hook fails on pre-existing upstream lint, so `--no-verify` is expected). Once Task 0 lands the submodule, the in-monorepo path is `vendor/crisp-qes-enclave/examples/CRISP`.

> Pin the submodule to the fork commit AFTER each fork task that the monorepo E2E depends on (bump the pointer in Task 5).

---

## File structure

Monorepo (`/data/Develop/crisp-qes`):
- `.gitmodules` — add `vendor/crisp-qes-enclave` → `https://github.com/alik-eth/crisp-qes-enclave.git`.
- `scripts/crisp-fhe/bootstrap.sh` (NEW) — submodule init (recursive), resolve+pin `bb` to the bb.js-bundled binary, CRS pre-seed, beta.19 lib patch if needed, build circuits/verifier, run fork test suites.
- `scripts/crisp-fhe/bb-pinned.sh` (NEW) — wrapper that resolves the bb.js-bundled `bb` and fails loudly if a mismatched `bb` is invoked.
- `scripts/crisp-fhe/e2e-local.sh` (NEW) — the v1 done-gate E2E (Task 5).
- `docs/2026-06-01-crisp-phase3e-e2e.md` (NEW, Task 5) — the run record.

Fork (`vendor/crisp-qes-enclave/examples/CRISP`):
- `packages/crisp-contracts/deploy/crispQes.ts` (NEW) — deploy `CRISPQESProgram` + `CRISPQESVerifier`'s `HonkVerifier` (fork of `deploy/crisp.ts`).
- `packages/crisp-contracts/deploy/syncCrispEnv.ts` (MODIFY) — sync QES addresses into `enclave.config.yaml`/`server/.env`/`client/.env`.
- `scripts/crisp_deploy.sh` (MODIFY or add `crisp_qes_deploy.sh`) — invoke the QES deploy.
- `server/src/server/routes/qes.rs` (NEW) — QES routes: `/qes/broadcast`, `/qes/active-slots`, `/qes/enrollment-root`, `/qes/previous-ciphertext`.
- `server/src/server/routes/mod.rs` (MODIFY) — register the QES scope.
- `server/src/server/indexer.rs` (MODIFY) — index nullifier→{index,ciphertext} for QES rounds.
- `services/mask-daemon/src/sources.ts` (MODIFY) — point `HttpSlotSource`/`getEnrollmentRoot` at `/qes/*`.
- `tests/qes-e2e.mjs` (NEW) or extend an existing harness — the scripted local round driver.

---

## Task 0: Submodule + reproducible build with `bb` hard-pinned (monorepo)

**Files:**
- Create: `.gitmodules` entry, `scripts/crisp-fhe/bootstrap.sh`, `scripts/crisp-fhe/bb-pinned.sh`
- Test: a `verify` invocation that runs the fork's existing test suites green from the monorepo

- [ ] **Step 1: Add the submodule.**
```bash
cd /data/Develop/crisp-qes
git submodule add https://github.com/alik-eth/crisp-qes-enclave.git vendor/crisp-qes-enclave
git -C vendor/crisp-qes-enclave checkout main
git submodule update --init --recursive vendor/crisp-qes-enclave
```
Expected: `vendor/crisp-qes-enclave/examples/CRISP/...` present; `.gitmodules` has the new entry.

- [ ] **Step 2: Write `scripts/crisp-fhe/bb-pinned.sh`** — resolve the bb.js-bundled binary and exec it, so every circuit/verifier step uses the runtime-matching `bb`:
```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
# locate the bb bundled with the @aztec/bb.js the SDK uses (3.0.0-nightly.20260102)
BB="$(find "$ROOT/vendor/crisp-qes-enclave" -path '*@aztec/bb.js*/build/amd64-linux/bb' -type f 2>/dev/null | head -1)"
[ -x "$BB" ] || { echo "FATAL: bundled bb not found under @aztec/bb.js — run pnpm install in the fork first"; exit 1; }
VER="$("$BB" --version)"
case "$VER" in 3.0.0-nightly.*) ;; *) echo "FATAL: bundled bb is $VER, expected 3.0.0-nightly.* (see reference_bb_cli_vs_bbjs_version)"; exit 1;; esac
exec "$BB" "$@"
```
(Pin the exact expected version string to match the fork's `@aztec/bb.js`.)

- [ ] **Step 3: Write `scripts/crisp-fhe/bootstrap.sh`** that, from a clean checkout, makes the fork buildable:
  - `git submodule update --init --recursive` (incl. the fork's own `risc0-ethereum`).
  - `pnpm -C vendor/crisp-qes-enclave/examples/CRISP install` (provides bb.js → the bundled bb).
  - CRS: pre-seed `~/.bb-crs` from our mirror (reuse the web Dockerfile's CRS-fetch approach) OR export the redirect; document the `NODE_TLS_REJECT_UNAUTHORIZED=0` fallback.
  - Apply the beta.19 `circuits/lib` `Vec::from_slice`→`Vec::new` test patch if `grep` finds it.
  - Regenerate circuits + verifier via `scripts/crisp-fhe/bb-pinned.sh` (call the fork's `compile_circuits.sh`/`compute_vk_hash.sh` with `bb` overridden to the wrapper).

- [ ] **Step 4: Verify (the test gate).** Run the fork's existing suites from the monorepo:
```bash
bash scripts/crisp-fhe/bootstrap.sh
cd vendor/crisp-qes-enclave/examples/CRISP
( cd circuits/bin/crisp_qes && nargo test )                                  # 7 pass
( cd packages/crisp-contracts && npx hardhat test mocha tests/crisp-qes.contracts.test.ts tests/crisp-qes.onchain.test.ts )  # 13 pass
NODE_TLS_REJECT_UNAUTHORIZED=0 pnpm -C packages/crisp-sdk exec vitest --run tests/qesVote.test.ts   # 2 pass (~5min)
```
Expected: all green — proves the pinned build reproduces the validated artifacts.

- [ ] **Step 5: Commit (monorepo).** `git add .gitmodules vendor/crisp-qes-enclave scripts/crisp-fhe && git commit -m "phase3e task0: vendor crisp-qes-enclave submodule + bb-pinned reproducible build"`

---

## Task 1: QES deploy script (fork)

**Files (in `vendor/crisp-qes-enclave/examples/CRISP`):**
- Create: `packages/crisp-contracts/deploy/crispQes.ts` (fork of `deploy/crisp.ts`)
- Modify: `packages/crisp-contracts/deploy/syncCrispEnv.ts`, `scripts/crisp_deploy.sh` (add a QES path)
- Read first: `deploy/crisp.ts` (full), `deploy/syncCrispEnv.ts`, `scripts/crisp_deploy.sh`

- [ ] **Step 1: Fork `crisp.ts` → `crispQes.ts`.** Change `CRISPProgram__factory` → `CRISPQESProgram__factory`; deploy the `HonkVerifier` from `contracts/CRISPQESVerifier.sol` (+ its `ZKTranscriptLib` from the same file — note the lib FQN must be `…CRISPQESVerifier.sol:ZKTranscriptLib` to avoid the name collision with the old verifier); pass that verifier to the `CRISPQESProgram` constructor. Keep the Enclave/PoseidonT3 prerequisites + `storeDeploymentArgs`.

- [ ] **Step 2: Update `syncCrispEnv.ts`** to write the `CRISPQESProgram` address (as the e3 program) + the QES verifier into `enclave.config.yaml`, `server/.env`, `client/.env`. Keep the existing sync behavior for the other contracts.

- [ ] **Step 3: Add a deploy entry** (`scripts/crisp_qes_deploy.sh` or a flag in `crisp_deploy.sh`) that runs the Enclave/PoseidonT3 prereqs then `crispQes.ts`.

- [ ] **Step 4: Test — deploy on anvil + read back.** Start anvil, run the QES deploy, and assert: `CRISPQESProgram` deployed with the QES verifier as its `honkVerifier`, and `setEnrollmentRoot(e3Id, root)` callable by owner. (A small Hardhat script or extend `tests/`.) Run; expect the deployed program's verifier address == the deployed `CRISPQESVerifier`.

- [ ] **Step 5: Commit (fork)** + `git push civicvoice main --no-verify`.

---

## Task 2: QES coordination-server routes (fork, Rust)

**Files (in `vendor/crisp-qes-enclave/examples/CRISP`):**
- Create: `server/src/server/routes/qes.rs`
- Modify: `server/src/server/routes/mod.rs` (register scope), `server/src/server/indexer.rs` (nullifier index)
- Read first: `server/src/server/routes/voting.rs` (`broadcast_encrypted_vote`), `server/src/server/routes/state.rs` (`handle_get_previous_ciphertext`), `server/src/server/indexer.rs` (how it consumes `InputPublished`), `server/src/server/routes/rounds.rs` (handler/state patterns). MIRROR these handlers — do NOT invent actix/state-store APIs.

The legacy routes are address-keyed (`get_slot_index_from_address`). `InputPublished(e3Id, encryptedVote, index)` carries NO nullifier — so the nullifier→slot mapping must be captured at broadcast time.

- [ ] **Step 1: Add a nullifier index.** In `indexer.rs` (or the shared round state), add a per-e3 map `nullifier (bytes32) → { index: u40, ciphertext: bytes }`. Populate it when a QES vote is broadcast (Step 2), correlating the contract-assigned `index` from the `InputPublished` receipt/event with the nullifier from the broadcast payload. (Mirror how the legacy address index is maintained.)

- [ ] **Step 2: `/qes/broadcast`** (`broadcast_encrypted_vote` analog) — accept the QES `publishInput` tuple `(bytes noirProof, bytes32 nullifier, uint256 petitionId, bool isMask, bytes32 encryptedVoteCommitment, bytes encryptedVote)`, submit it to `CRISPQESProgram.publishInput`, capture the resulting index, and update the nullifier index with `{index, encryptedVote}`.

- [ ] **Step 3: `/qes/active-slots`** — return `[{ nullifier, ciphertext }]` for an e3Id from the nullifier index (the daemon's `SlotSource`).

- [ ] **Step 4: `/qes/enrollment-root`** — return the round's `enrollmentRoot` (read from `CRISPQESProgram` or config) for the daemon's `getEnrollmentRoot`.

- [ ] **Step 5: `/qes/previous-ciphertext`** (`handle_get_previous_ciphertext` analog) — given `{e3Id, nullifier}`, return the slot's current ciphertext (for building mask `previousCiphertext`).

- [ ] **Step 6: Register the scope** in `mod.rs` (`config.service(web::scope("/qes")....)`), additive — keep the legacy routes.

- [ ] **Step 7: Test.** Add Rust tests (mirror existing route tests if present) or a script smoke test: POST a QES broadcast against a locally-deployed program (Task 1), then assert `/qes/active-slots` returns the nullifier+ciphertext and `/qes/previous-ciphertext` returns it by nullifier. `cargo build` + `cargo test` for the server crate must pass. Run; expect green.

- [ ] **Step 8: Commit (fork)** + push.

---

## Task 3: Wire the masking daemon to the QES routes (fork, TS)

**Files (in `vendor/crisp-qes-enclave/examples/CRISP/services/mask-daemon`):**
- Modify: `src/sources.ts` (`HttpSlotSource`, `getEnrollmentRoot`)
- Read first: the Task 6 daemon (`src/daemon.ts`, `src/sources.ts`, `src/maskInput.ts`)

- [ ] **Step 1: Point `HttpSlotSource` at `/qes/active-slots`** (returns `{nullifier, ciphertext}[]`) and `getEnrollmentRoot` at `/qes/enrollment-root`, matching the Task 2 payload shapes. Submit masks via `/qes/broadcast` (the credential-free QES tuple from `maskInput.ts encodeQesPublishInput`), so the daemon uses the same relay path as voters (no separate on-chain signer needed locally).

- [ ] **Step 2: Test.** Extend `test/maskInput.test.ts` with a `SlotSource` test using a mocked `/qes/active-slots`/`/qes/enrollment-root` response → assert the daemon builds one mask `ProofInputs` per slot with the correct `nullifier`, `previousCiphertext`, and `enrollmentRoot`. (Proof generation stays mocked here; the real sweep runs in Task 5.) Run; expect pass.

- [ ] **Step 3: Commit (fork)** + push.

---

## Task 4: QES fake-zkVM tally driver (fork)

**Files (in `vendor/crisp-qes-enclave/examples/CRISP`):**
- Read first: the dev program server (`crates/program-server` / `e3-support-scripts-dev`) `fhe_processor`, and how the legacy flow drives a tally + posts the plaintext output back (`/state/add-result` → `handle_program_server_result`).

- [ ] **Step 1: Confirm option-count-agnostic.** Verify the dev `fhe_processor` (homomorphic BFV sum) handles `numOptions ≥ 2` unchanged (the contract's `decodeTally` already splits the plaintext into `numOptions` segments). If it hardcodes 2, parameterize it; otherwise no change — document which.

- [ ] **Step 2: Drive a QES tally.** Provide a path/script to: after the input window closes for a QES round, run the dev tally over the round's on-chain ciphertexts and post the plaintext output so `CRISPQESProgram.decodeTally(e3Id)` returns the per-option vector. Reuse the legacy driver; only the program/round wiring changes (QES program address).

- [ ] **Step 3: Test.** Local: a round with `numOptions=3`, one real vote for option 1, drive tally → `decodeTally` returns `[1,0,0]` (plus any masks = 0). Assert. Run; expect pass.

- [ ] **Step 4: Commit (fork)** + push.

---

## Task 5: Scripted local E2E — the v1 done-gate (monorepo + fork)

**Files:**
- Create (monorepo): `scripts/crisp-fhe/e2e-local.sh`, `docs/2026-06-01-crisp-phase3e-e2e.md`
- Create (fork): `tests/qes-e2e.mjs` (the round driver invoked by the script)
- Bump the submodule pointer to the latest fork commit.

- [ ] **Step 1: Write `tests/qes-e2e.mjs`** (fork) — a Node driver that, against the running local stack: creates a `numOptions=3` round, sets the enrollment root from a synthetic depth-20 tree (reuse `qesVote.test.ts` helpers), casts a real QES vote via `/qes/broadcast`, asserts `publishInput` accepted + slot created, runs one daemon mask sweep, asserts the slot ciphertext changed, attempts a double real-vote (same nullifier) → expects on-chain `SlotAlreadyVoted`, drives the tally (Task 4), asserts `decodeTally == [1,0,0]`.

- [ ] **Step 2: Write `scripts/crisp-fhe/e2e-local.sh`** (monorepo) — orchestrate: `bootstrap.sh` → bring up the local self-run stack (anvil + ciphernodes + program/coordination servers, the Phase 1 commands) with the QES contracts deployed (Task 1) → run `tests/qes-e2e.mjs` → tear down. Time-box ciphernode DKG; surface failures clearly.

- [ ] **Step 3: Run the full gate.**
```bash
cd /data/Develop/crisp-qes
bash scripts/crisp-fhe/e2e-local.sh
```
Expected: the script exits 0 with the E2E assertions all green (real vote accepted → mask changes ciphertext → double-vote rejected → tally `[1,0,0]`). This is the v1 acceptance criterion.

- [ ] **Step 4: Record + commit.** Write `docs/2026-06-01-crisp-phase3e-e2e.md` with the exact run + outcomes. Bump the submodule pointer; commit (monorepo) `phase3e task5: scripted local E2E green` and (fork) the driver. Push both.

---

## Task 6 (milestone, NOT bite-sized): next-spec handoff

Out of TDD scope — what Phase 3e v1 deliberately leaves for the follow-on (self-run testnet) spec: Base Sepolia deploy of the E3 + QES contracts, a hosted coordination service, `PetitionRegistry.tallyMode` routing, the `packages/web` desktop encrypted-vote flow, and the eventual Interfold-prod-committee migration. Capture any v1 learnings that change those.

---

## Self-review notes (author)

- **Spec coverage:** submodule + bb-pinned build (Task 0 ← spec §1), QES plumbing — deploy (Task 1), Rust routes (Task 2), daemon source (Task 3), tally driver (Task 4) ← spec §2; local self-run committee reused (Task 5 ← spec §3); local E2E done-gate (Task 5 ← spec §4). Open questions resolved: Q1 submodule path = `vendor/` (matches existing `vendor/`); Q2 bb pinning = `bb-pinned.sh` wrapper (Task 0); Q3 routes = additive `/qes/*` (Task 2 Step 6); Q4 tally option-count = Task 4 Step 1. ✔
- **Cross-repo discipline:** every fork task ends with commit + `git push civicvoice main --no-verify`; the monorepo submodule pointer is bumped only in Task 5 (after the fork work the E2E needs). The frozen circuit/verifier/contract logic is never edited (only deploy/server/daemon/build/test).
- **Highest-risk task = Task 2** (Rust routes — the least-validated surface; "read + mirror," don't invent). Tasks 1/3/4 reuse existing patterns; Task 0 hard-pins the toolchain (the known recurring regression).
