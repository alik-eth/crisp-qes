# FHE live-tally "Recalculate" — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repeatable, on-demand "Recalculate tally" button to the local demo's `/rounds` page that reveals the *current* encrypted vote counts via real threshold decryption, without closing the round.

**Architecture:** A dev-only standalone `tally-peek` Rust binary threshold-decrypts the live homomorphic sum off the E3 lifecycle (loading the 3 committee nodes' DKG share material from a copy of `.enclave/data`). The coordination server exposes an env-gated `/rounds/tally-now` that sums the current inputs and invokes the binary; the web `/rounds` page gains a "Recalculate tally" button. No on-chain writes; the natural deadline reveal is untouched.

**Tech Stack:** Rust (enclave crates: `e3-trbfv`, `e3-crypto`, `e3-keyshare`, `e3-data`, `e3-fhe-params`, `e3-bfv-client`, `e3-compute-provider`), actix-web (coordination server), React/TS (web), docker-compose-dev (podman), Foundry/anvil.

**Design:** `docs/specs/2026-06-04-fhe-live-tally-recalc-design.md`

**Guardrails (from spec):** Dev-only — gate the endpoint + binary behind `ENABLE_TALLY_PEEK=1` set only in `docker-compose.dev.yml`; never reachable on Fly/prod. No secrets logged. Fork edits under `vendor/crisp-qes-enclave` use explicit `git add <file>`, never `git add -A`. Partial-result leak is accepted for the demo and MUST be labelled in the UI.

---

## File Structure

**New:**
- `vendor/crisp-qes-enclave/examples/CRISP/server/src/bin/tally_peek.rs` — dev-only standalone binary: given `e3_id`, summed-ciphertext (hex), num_options, threshold params, and the committee data dir → loads 3 nodes' shares → threshold-decrypts → prints `{ "counts": [u64; n] }` JSON to stdout.
- `packages/web/src/lib/liveTally.ts` — `recalcTally(coordinatorUrl, roundId)` HTTP client.
- `docs/plans/2026-06-04-fhe-live-tally-recalc-plan.md` — this file.

**Modified (fork — explicit git add only):**
- `vendor/crisp-qes-enclave/examples/CRISP/program/src/lib.rs` — promote the test-only `decode_tally` to a `pub fn` so the binary and tests share one decoder.
- `vendor/crisp-qes-enclave/examples/CRISP/server/src/server/routes/rounds.rs` — add `tally_now` handler + route, env-gated.
- `vendor/crisp-qes-enclave/examples/CRISP/server/Cargo.toml` — register the `tally_peek` bin + any new deps (`e3-trbfv`, `e3-keyshare`, `e3-data`, `e3-crypto`) if not already deps.

**Modified (repo):**
- `packages/web/src/pages/Rounds.tsx` — "Recalculate tally" button + live-counts rendering + demo label.
- `docker-compose.dev.yml` — `ENABLE_TALLY_PEEK=1` on the `fhe` service env (coordination server reads it).

---

## Task 1: Runtime prototype — prove share-load + threshold-decrypt of the live sum (GATE)

**This is the spike-in-practice. Do not build Tasks 2–5 until counts come out correct.** It resolves the two open risks: (a) reading the 3 nodes' `sled` share data from a copy of `.enclave/data` while the stack runs, and (b) sourcing each node's `Cipher` password to decrypt the `SensitiveBytes` share material.

**Files:**
- Scratch: `vendor/crisp-qes-enclave/examples/CRISP/server/src/bin/tally_peek.rs` (prototype form)
- Reference: `vendor/crisp-qes-enclave/crates/trbfv/tests/integration.rs` (the exact pipeline)
- Reference: `vendor/crisp-qes-enclave/crates/keyshare/src/domain/keyshare_state.rs:74-95` (`ReadyForDecryption { sk_poly_sum, es_poly_sum }`)
- Reference: `vendor/crisp-qes-enclave/crates/keyshare/src/repo.rs` (how state is persisted/loaded)

- [ ] **Step 1: Open a round + cast votes on the running dev stack**

```bash
cd /data/Develop/crisp-qes
bash scripts/compose/open-round.sh "Cats or dogs?" "Cats,Dogs" 30
# wait ~80s for DKG, then cast 1-2 votes in-browser at http://localhost:8080/rounds
# confirm votes indexed:
curl -s -X POST http://localhost:4000/rounds/current -H 'content-type: application/json' -d '{"requesters":[]}'
```
Expected: a non-zero current round id; `get_ciphertext_inputs` will return the cast votes.

- [ ] **Step 2: Investigate the share-load + Cipher path (read, don't guess)**

Determine, from the enclave source, exactly how to reconstruct each node's `(sk_poly_sum, es_poly_sum)`:
- How `ThresholdKeyshare` loads its `ReadyForDecryption` state from the repo: read `crates/keyshare/src/repo.rs` + `crates/keyshare/src/ext.rs` for the data key/namespace and `Persistable`/`Repository` API in `crates/data/src/repository.rs`.
- How a node builds its `Cipher`: search `crates/ciphernode-builder` / `crates/entrypoint` / `examples/CRISP/scripts/dev_cipher.sh` for `Cipher::from_password` / password source. The supervisor stores net-keys/passwords in `.enclave/config` (`/data/enclave-config`).
- The per-node data namespace: each of cn1/cn2/cn3 has distinct on-disk state under `.enclave/data` (`/data/enclave-data`). Identify how a node's address/id maps to its sled tree/key prefix.

Record findings as comments at the top of `tally_peek.rs`.

- [ ] **Step 3: Snapshot the (immutable post-DKG) data dir to avoid the sled lock**

```bash
docker compose --env-file .env.dev -f docker-compose.dev.yml exec -T fhe \
  bash -lc 'rm -rf /tmp/peek-data && cp -a /data/enclave-data /tmp/peek-data && \
            rm -rf /tmp/peek-config && cp -a /data/enclave-config /tmp/peek-config && echo copied'
```
Expected: `copied`. Open sled against `/tmp/peek-data` (copy) so the live nodes keep their lock.
If sled still refuses the copy (lock file copied in), delete the copy's sled lock file and retry; document the exact step.

- [ ] **Step 4: Prototype the decrypt in `tally_peek.rs` (hardcode e3_id for now)**

Implement, mirroring `crates/trbfv/tests/integration.rs`:
1. Build `TrBFVConfig::new(params, num_parties=3, threshold)` — get `params` via `e3_fhe_params` (the round's param set), `threshold` from the committee config (confirm the dev value in Step 2).
2. Fetch current inputs: `curl http://localhost:4000` is not available from inside; instead read inputs via the coordination server's stored value OR, for the prototype, pass the summed ciphertext in. Simplest prototype: compute the sum in-process from `get_ciphertext_inputs` exported as hex — for Task 1, copy the hex of `fhe_processor` output (Step 5) in.
3. For each node id in the committee: load `(sk_poly_sum, es_poly_sum)` for `e3_id` from the copied data dir using the repo API + node `Cipher`.
4. `calculate_decryption_share(&cipher, CalculateDecryptionShareRequest { name, trbfv_config, ciphertexts: vec![sum], sk_poly_sum, es_poly_sum })` per node.
5. `calculate_threshold_decryption(CalculateThresholdDecryptionRequest { trbfv_config, d_share_polys, ciphertexts: vec![sum] })`.
6. Decode: `decode_plaintext_to_vec_u64(plaintext)` → coeffs → `decode_tally(coeffs, num_options)`.

- [ ] **Step 5: Produce the summed ciphertext to feed the prototype**

Add a temporary helper (or reuse `fhe_processor`): build `FHEInputs { ciphertexts: get_ciphertext_inputs(), params }`, call `fhe_processor(&inputs)`, print the summed-ct hex. Feed that hex into Step 4.

- [ ] **Step 6: Run and verify counts match the votes cast**

```bash
cd /data/Develop/crisp-qes/vendor/crisp-qes-enclave/examples/CRISP
docker compose ... exec -T fhe bash -lc 'cd /app/examples/CRISP && cargo run --release --bin tally_peek -- <args>'
```
Expected: printed counts equal the votes cast in Step 1 (e.g. cast 1×Cats, 1×Dogs → `[1, 1]`). Run it twice — confirm identical output (non-destructive, repeatable).

- [ ] **Step 7: Decision gate**

If counts are correct + repeatable → A-disk-copy confirmed; proceed to Task 2.
If share-loading/`Cipher` is impractical → STOP, write findings, switch to the **A-node fallback** (spec §Fallback) and re-plan Tasks 2–3 around an in-node share-on-demand handler. Either way, do not proceed silently.

- [ ] **Step 8: Commit the prototype findings**

```bash
cd /data/Develop/crisp-qes
git add vendor/crisp-qes-enclave/examples/CRISP/server/src/bin/tally_peek.rs
git commit -m "spike(fhe): prototype off-lifecycle threshold decrypt of live tally (Task 1 gate)"
```

---

## Task 2: Finalize the `tally-peek` binary (clean CLI + decode parity test)

**Files:**
- Modify: `vendor/crisp-qes-enclave/examples/CRISP/program/src/lib.rs` (promote `decode_tally` to `pub fn`)
- Modify: `vendor/crisp-qes-enclave/examples/CRISP/server/src/bin/tally_peek.rs` (finalize)
- Modify: `vendor/crisp-qes-enclave/examples/CRISP/server/Cargo.toml` (`[[bin]] name="tally_peek"`, deps)
- Test: a `#[cfg(test)]` in `program/src/lib.rs` (decode parity)

- [ ] **Step 1: Promote `decode_tally` to a shared `pub fn`**

In `examples/CRISP/program/src/lib.rs`, lift the existing test `decode_tally` (and `MAX_VOTE_BITS`) out of `mod tests` to module scope as `pub fn decode_tally(coeffs: &[u64], num_options: usize) -> Vec<u64>`. Update the test to call it. This is the single source of truth shared with the on-chain `CRISPQESProgram.decodeTally` and `packages/web/src/lib/voteTally.ts`.

- [ ] **Step 2: Verify the decoder still passes its parity test**

```bash
cd /data/Develop/crisp-qes/vendor/crisp-qes-enclave/examples/CRISP
cargo test -p crisp-program decode 2>&1 | tail -20   # use the actual program crate name from Cargo.toml
```
Expected: existing decode/tally parity test PASS (now via the public fn).

- [ ] **Step 3: Finalize the binary CLI**

`tally_peek` accepts (clap or manual args): `--e3-id <u64>`, `--sum-ct-hex <hex>` (the summed ciphertext), `--num-options <usize>`, `--data-dir <path>` (the copied `.enclave/data`), `--config-dir <path>`. It performs Task 1 Steps 4+6 (load shares, 3× share, aggregate, `decode_tally`) and prints `{"counts":[...]}` to stdout, errors to stderr + non-zero exit. No secrets in any log line.

- [ ] **Step 4: Register the bin + build**

In `examples/CRISP/server/Cargo.toml` add `[[bin]] name = "tally_peek"  path = "src/bin/tally_peek.rs"` and any missing deps. Build:
```bash
cd /data/Develop/crisp-qes/vendor/crisp-qes-enclave/examples/CRISP
cargo build --release --bin tally_peek 2>&1 | tail -20
```
Expected: clean build.

- [ ] **Step 5: Re-run end-to-end against the open round (regression of Task 1 Step 6)**

Same invocation as Task 1 Step 6 but via the finalized CLI. Expected: correct counts, JSON shape `{"counts":[...]}`.

- [ ] **Step 6: Commit**

```bash
cd /data/Develop/crisp-qes
git add vendor/crisp-qes-enclave/examples/CRISP/program/src/lib.rs \
        vendor/crisp-qes-enclave/examples/CRISP/server/src/bin/tally_peek.rs \
        vendor/crisp-qes-enclave/examples/CRISP/server/Cargo.toml
git commit -m "feat(fhe): tally-peek binary — off-lifecycle threshold decrypt + shared decode_tally"
```

---

## Task 3: Coordination-server `/rounds/tally-now` (env-gated)

**Files:**
- Modify: `vendor/crisp-qes-enclave/examples/CRISP/server/src/server/routes/rounds.rs`
- Reference: `examples/CRISP/server/src/server/repo.rs:443` (`get_ciphertext_inputs`), `:341` (`get_num_options`)
- Reference: `examples/CRISP/program/src/lib.rs::fhe_processor`

- [ ] **Step 1: Add the route (gated)**

In `rounds.rs` `setup_routes`, add `.route("/tally-now", web::post().to(tally_now))`. The handler:
1. If `std::env::var("ENABLE_TALLY_PEEK").as_deref() != Ok("1")` → return `404`/`403` (feature off). This is the prod guard.
2. `let e3_id = req.round_id;`
3. `let cts = store.e3(e3_id)…get_ciphertext_inputs().await?` (use the same repo accessor the deadline handler uses at `indexer.rs:244`).
4. `let num_options = …get_num_options().await?`.
5. Build `FHEInputs { ciphertexts: cts, params }` (params via the same `e3_fhe_params` path `rounds.rs` already uses) and `let sum = fhe_processor(&inputs);` (hex-encode).
6. Snapshot the data/config dirs to `/tmp/peek-*` (idempotent `cp -a`; shares are immutable post-DKG so re-copy is cheap/safe) and shell out: `Command::new("…/tally_peek").args([...]).output()`.
7. Parse stdout JSON `{counts}`; return `{ round_id, counts, n_votes: cts.len(), decrypted_at: <unix ts> }`. Never publish on-chain.

- [ ] **Step 2: Empty-round handling**

If `cts.is_empty()`, `fhe_processor` returns `Ciphertext::zero` → decrypts to all-zero coeffs → `counts = [0; num_options]`. Return zeros with `n_votes: 0` (HTTP 200), not an error.

- [ ] **Step 3: Build the server**

```bash
cd /data/Develop/crisp-qes/vendor/crisp-qes-enclave/examples/CRISP
cargo build --release --bin server 2>&1 | tail -20
```
Expected: clean build.

- [ ] **Step 4: Wire the env flag into compose + rebuild the fhe image**

In `docker-compose.dev.yml`, add `ENABLE_TALLY_PEEK: "1"` to the `fhe` service `environment:`. Rebuild + restart `fhe`:
```bash
cd /data/Develop/crisp-qes
docker compose --env-file .env.dev -f docker-compose.dev.yml up -d --build fhe
```

- [ ] **Step 5: Verify the endpoint against the open round**

```bash
curl -s -X POST http://localhost:4000/rounds/tally-now -H 'content-type: application/json' -d '{"round_id": <E3ID>}'
```
Expected: `{"round_id":<id>,"counts":[...],"n_votes":N,...}` matching votes cast. Hit it twice → identical (repeatable, non-destructive). With `ENABLE_TALLY_PEEK` unset → 403/404.

- [ ] **Step 6: Commit**

```bash
cd /data/Develop/crisp-qes
git add vendor/crisp-qes-enclave/examples/CRISP/server/src/server/routes/rounds.rs docker-compose.dev.yml
git commit -m "feat(fhe): coordination-server /rounds/tally-now (env-gated live tally)"
```

---

## Task 4: Web "Recalculate tally" button

**Files:**
- Create: `packages/web/src/lib/liveTally.ts`
- Modify: `packages/web/src/pages/Rounds.tsx`
- Reference: `packages/web/src/lib/voteTally.ts` (`OptionResult`, `toResults`, `winningOption`), config `fheCoordinatorUrl`

- [ ] **Step 1: Add the client lib**

```ts
// packages/web/src/lib/liveTally.ts
export type LiveTally = { roundId: number; counts: number[]; nVotes: number; decryptedAt: number };

export async function recalcTally(coordinatorUrl: string, roundId: number): Promise<LiveTally> {
    const res = await fetch(`${coordinatorUrl}/rounds/tally-now`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ round_id: roundId }),
    });
    if (!res.ok) throw new Error(`tally-now failed: ${res.status} ${await res.text()}`);
    const j = await res.json();
    return { roundId: j.round_id, counts: j.counts, nVotes: j.n_votes, decryptedAt: j.decrypted_at };
}
```

- [ ] **Step 2: Add button + state in `Rounds.tsx`**

Per open round: a **"Recalculate tally"** button → `recalcTally(config.fheCoordinatorUrl, r.e3Id)` → render `toResults(r.options, live.counts)` (reuse `voteTally.ts`) into the same results list the deadline path uses. Disable + show a spinner ("committee decrypting…") while in flight. Add a small label: **"Demo / dev tally peek — reveals the live encrypted total (a real deployment hides this until close)."** Do not touch the existing post-deadline `fetchTally` path.

- [ ] **Step 3: Build the web app**

```bash
cd /data/Develop/crisp-qes/packages/web
pnpm build:app 2>&1 | tail -20
```
Expected: `tsc --noEmit` clean + vite build success.

- [ ] **Step 4: Rebuild + restart the web container**

```bash
cd /data/Develop/crisp-qes
docker compose --env-file .env.dev -f docker-compose.dev.yml up -d --build web
```

- [ ] **Step 5: Commit**

```bash
cd /data/Develop/crisp-qes
git add packages/web/src/lib/liveTally.ts packages/web/src/pages/Rounds.tsx
git commit -m "feat(web): Recalculate tally button — live FHE counts on /rounds"
```

---

## Task 5: End-to-end demo verification

**Files:** none (verification only)

- [ ] **Step 1: Fresh round, watch the counter climb**

On the running stack: open a round (`scripts/compose/open-round.sh "Cats or dogs?" "Cats,Dogs"`), wait for DKG, then at `http://localhost:8080/rounds`:
1. Press **Recalculate** with 0 votes → expect `Cats 0 / Dogs 0`.
2. Cast 1 vote (Cats) → Recalculate → `Cats 1 / Dogs 0`.
3. Cast 1 vote (Dogs) → Recalculate → `Cats 1 / Dogs 1`.
Each press is a real threshold decryption; the round stays open throughout.

- [ ] **Step 2: Confirm parity with the eventual on-chain reveal**

Let the E3 deadline fire (or lower `E3_DURATION` for the test). After `PlaintextOutputPublished`, the on-chain `fetchTally` counts MUST equal the last live recalculation. Confirm in the UI (deadline path) and on-chain.

- [ ] **Step 3: Confirm the prod guard**

```bash
# coordination server with ENABLE_TALLY_PEEK unset → endpoint refuses
docker compose ... exec -T fhe bash -lc 'unset ENABLE_TALLY_PEEK; ...' # or test on the Fly image config
```
Expected: `/rounds/tally-now` returns 403/404 when the flag is not `1`. Verify the Fly supervisor never sets it.

- [ ] **Step 4: Final review + branch finish**

Dispatch a final code review over the whole change set, then use superpowers:finishing-a-development-branch. Update task #42's scope note if this supersedes part of it.

---

## Self-review notes

- **Spec coverage:** demo button (T4), repeatable/non-destructive (T1 S6, T3 S5, T5 S1), real threshold decrypt (T1–T3), off-lifecycle (standalone binary), empty round (T3 S2), decode parity (T2 S1–2, T5 S2), dev-only guard (T3 S1/S4, T5 S3), partial-leak label (T4 S2) — all covered.
- **Risk-gated:** Task 1 is an explicit go/no-go before the build, with a named fallback (A-node).
- **Type consistency:** `decode_tally(coeffs, num_options) -> Vec<u64>`, `recalcTally -> LiveTally{counts}`, endpoint `{round_id,counts,n_votes,decrypted_at}` used consistently across tasks.
- **Genuine unknowns** (exact keyshare repo load API + `Cipher` password source + dev committee `threshold` value) are deliberately resolved in Task 1's investigation steps rather than guessed here.
