# FHE live-tally "Recalculate" — design

**Date:** 2026-06-04
**Status:** Approved design (Approach A), post-spike. Ready for implementation plan.
**Branch:** feat/crisp-fhe-tally
**Scope:** docker-compose-dev (fully-local) demo only. NOT for the Fly/prod path.

## Goal

Give the local demo a **repeatable, on-demand "Recalculate tally" button** on `/rounds`
that reveals the *current* encrypted vote counts via **real threshold decryption** — without
closing the round, so you can vote → recalc → vote more → recalc again and watch the counts
climb. This makes FHE the visible star of the demo instead of an invisible reveal that only
fires at the E3 input deadline.

## Why this is needed (current state)

- The petition flow you sign is a **plaintext** anonymous-signature counter — not FHE.
- The FHE/Interfold tally lives at `/rounds`, is built and wired, but reveals a round's tally
  **exactly once**, at the E3 input deadline (`E3_DURATION=600` locally). No mid-round peek
  exists — by design, because producing decryption shares for the aggregate *is* the reveal.
- For a live demo nobody waits out the timer, and a silent timer reads as "nothing happening."

## Accepted trade-off (decided with user)

A repeatable live counter **leaks partial results** (you learn the running total at each
press). This is inherent to the feature and **accepted for the localhost demo**. A real
deployment would never expose this. The UI must label the round as a **demo / dev tally peek**.

## Spike findings (what makes Approach A real)

Confirmed at the code level (task #44):

1. **The threshold primitives accept an arbitrary ciphertext.** In `crates/trbfv`:
   - `calculate_decryption_share(cipher, { trbfv_config, ciphertexts, sk_poly_sum, es_poly_sum })`
     → a single node's decryption share for *any* ciphertext.
   - `calculate_threshold_decryption({ trbfv_config, d_share_polys: Vec<(PartyId, shares)>, ciphertexts })`
     → plaintext, decoded with `e3_bfv_client::decode_plaintext_to_vec_u64`.
   - End-to-end reference: `crates/trbfv/tests/integration.rs`.
2. **Each node persists the share material we need.** `ReadyForDecryption` / `Decrypting`
   keyshare states hold `sk_poly_sum: SensitiveBytes` and `es_poly_sum: Vec<SensitiveBytes>`
   (`crates/keyshare/src/domain/keyshare_state.rs:74-95`). A node needs these for *every* real
   decrypt, so they remain available after DKG. In dev we own all 3 nodes.
3. **The running sum is already available.** The coordination server indexes per-input
   ciphertexts (`repo.get_ciphertext_inputs()`), the same source the deadline handler feeds to
   the program server. The homomorphic sum is `program/src/lib.rs::fhe_processor` (`sum += ct`).
4. **Reusing the running actors does NOT work for *repeatable*.** The `ThresholdKeyshare`
   actor handles the on-chain `CiphertextOutputPublished` event and transitions
   `ReadyForDecryption → Decrypting → done` — one decrypt per E3, and it publishes on-chain.
   So we must decrypt **off the actor lifecycle**, not by re-triggering it.
5. **The node DB is `sled` (exclusive lock).** A standalone process cannot open a live
   node's DB. Mitigation: the DKG share material is **immutable after DKG**, so we operate on
   a **copy** of `.enclave/data` (stable snapshot), opened independently.

## Architecture

Three pieces; the frontend and endpoint shape are identical regardless of how the decrypt is
obtained, so the decrypt mechanism is swappable.

```
 browser /rounds "Recalculate tally"
        │  POST /rounds/tally-now { round_id }
        ▼
 coordination-server (actix)                         ── existing service
   1. cts = repo.get_ciphertext_inputs(e3_id)        ── current votes (may be empty)
   2. sum = fhe_processor({ params, ciphertexts: cts })   ── homomorphic sum
   3. counts = threshold_decrypt_snapshot(e3_id, sum) ── NEW (see below)
   4. return { round_id, counts, n_votes, decrypted_at }  ── NOT published on-chain
        │
        ▼
 threshold_decrypt_snapshot  (NEW dev-only capability — Approach A2)
   for each of the 3 committee nodes:
     load (sk_poly_sum, es_poly_sum) for e3_id        ── from a COPY of .enclave/data + node Cipher
     share = calculate_decryption_share(cipher, { ..sum.. })
   plaintext = calculate_threshold_decryption({ shares, ciphertexts: [sum] })
   counts    = decodeTally(plaintext)                 ── mirror of CRISPQESProgram.decodeTally
```

### The new decrypt capability — primary: standalone `tally-peek` binary (A-disk-copy)

A new **dev-only Rust binary** in `examples/CRISP` (e.g. `src/bin/tally_peek.rs`) that links the
enclave crates and, given an `e3_id` + a summed ciphertext (hex on stdin/arg):

1. Reads each node's keyshare state for `e3_id` from a **copy** of the persisted data dir
   (immutable post-DKG), decrypting `SensitiveBytes` with that node's `Cipher`.
2. Runs `calculate_decryption_share` per node over the summed ciphertext.
3. Runs `calculate_threshold_decryption`, decodes, prints per-option counts as JSON.

The coordination server shells out to this binary (both run inside the `fhe` container, which
already has the enclave toolchain + `/data/enclave-data`). Keeps the change additive — **no
edits to the consensus-critical ciphernode code.**

Why a copy: `sled` exclusive-locks the live node DB. The DKG shares never change after DKG, so a
`cp -a` snapshot of `.enclave/data` (taken once, refreshed if a new round's DKG runs) is a
consistent, lock-free source.

### Fallback: in-node share-on-demand (A-node)

If Task 1 shows the standalone share-loading/`Cipher` path is impractical (e.g. password
derivation or repo API too entangled, or copy-open fails), add a **dev-only** message handler to
the ciphernode that computes `calculate_decryption_share` over a supplied ciphertext using its
**in-memory** share state (no state-machine transition, no on-chain), and a coordinator that
collects the 3 shares and aggregates. More faithful (in-memory shares, no copy) but more invasive
(new event + net plumbing). Documented as fallback; not the default.

### Frontend

`packages/web/src/pages/Rounds.tsx`: add a **"Recalculate tally"** button per open round.
- `POST {fheCoordinatorUrl}/rounds/tally-now { round_id }` → render returned counts.
- Show "demo / dev tally peek — reveals the live encrypted total" label + a spinner while the
  committee decrypts.
- Keep the existing post-deadline `fetchTally` path untouched (it reads the on-chain
  `plaintextOutput`); the button is an additive live view, the round stays open.
- New lib: `packages/web/src/lib/liveTally.ts` (`recalcTally(coordinatorUrl, roundId)`).

## Data flow / correctness

- **Empty round:** `get_ciphertext_inputs` may return `[]`. `fhe_processor` over `[]` =
  `Ciphertext::zero` → decrypts to all-zero counts. The endpoint returns zeros (with `n_votes:0`),
  not an error. UI shows 0/0/0.
- **Decode parity:** counts MUST match `CRISPQESProgram.decodeTally` (Solidity) and the existing
  `voteTally.ts` decoder, so the live numbers equal the eventual on-chain reveal. Reuse the same
  decode (the program crate test already asserts this parity).
- **No on-chain writes:** `/rounds/tally-now` never calls `publishCiphertextOutput` /
  `publishPlaintextOutput`. It is read-only w.r.t. chain + E3 state; the natural deadline reveal
  still happens independently.

## Security / scope guardrails

- **Dev-only.** The endpoint + binary are gated to `NODE_ENV=development` / the compose stack.
  They MUST NOT be reachable on the Fly/prod coordination server. Add an explicit env gate
  (e.g. `ENABLE_TALLY_PEEK=1`, set only in `docker-compose.dev.yml`).
- No secrets logged. The node `Cipher` / share material is read in-process and never echoed.
- Fork edits (vendor/crisp-qes-enclave) use explicit `git add <file>`, never `git add -A`.

## Implementation plan (gated)

**Task 1 — runtime prototype (the spike-in-practice GATE).** Open a round on the dev stack,
cast 1–2 in-browser votes, then prove a standalone invocation can: load the 3 nodes' shares from
a copy of `.enclave/data`, decrypt the summed `get_ciphertext_inputs`, and produce counts that
match the votes cast. Resolves the two open risks (sled-copy access + `Cipher` password source).
If it fails, pivot to the A-node fallback before building further.

**Task 2 —** `tally-peek` binary: finalize CLI (e3_id + summed-ct in, counts JSON out), decode
parity test against `decodeTally`.

**Task 3 —** coordination-server `/rounds/tally-now`: gather inputs → sum → invoke peek → return
counts; env-gated; empty-round handling.

**Task 4 —** web `/rounds` "Recalculate tally" button + `liveTally.ts` + demo labelling.

**Task 5 —** end-to-end on the dev stack: open round → recalc shows 0 → vote → recalc shows 1 →
vote → recalc shows 2; confirm the eventual deadline on-chain tally equals the last live counts.

## Out of scope

- Prod/Fly exposure of live recalculation.
- Carry-over across rounds (the existing previous-ciphertext masking path is untouched).
- Changing the petition (plaintext signature) flow.
