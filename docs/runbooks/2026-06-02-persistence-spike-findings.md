# CRISP committee-key persistence spike — findings

**Date:** 2026-06-02
**Question:** Can the CRISP FHE backend scale to zero on Fly, or must the committee stay always-on? Specifically: do the 3 ciphernodes retain their DKG key shares across a stop→start so a ballot encrypted before sleep still decrypts after wake?

**Decision:** ✅ **Persist-to-disk → scale-to-zero is viable.** Mount `.enclave/data` on the Fly volume; do NOT purge/nuke on warm boot. Confirm with the live cross-sleep decrypt check at Task 1.5 Step 3. Fallback if that check fails: `min_machines_running = 1` (always-on) — a one-line change.

## Evidence (gathered without the full live decrypt, which is deferred to the Fly integration test)

1. **Each node has a durable, event-sourced embedded DB on disk** under `.enclave/data/cnX/`:
   - `db/db`, `db/conf`, `db/snap.0000000000000185`, `db/blobs/` (cn1 `db/blobs` ≈ 2.6 MB)
   - event logs `log.0/…` and **`log.31337/…` (keyed by chain-id 31337)** — node state is bound to the chain it ran against.
2. **`enclave nodes purge`** exists explicitly to "Purge all local ciphernode data … delete all passwords and prior ciphernode events," and **`enclave purge-all`** purges "both the local program cache and all ciphernode databases." A purge command only exists because state otherwise **persists** across restarts.
3. **`dev_cipher.sh` deliberately `rm -rf ./.enclave/data ./.enclave/config`** at the top of every dev run ("nuke past installations as we are adding these nodes to the contract"). Nuking is an explicit opt-in precisely because, without it, the persisted state would conflict with a freshly redeployed (new-address) chain. On a *warm boot against the SAME persisted anvil*, we must NOT nuke — the persisted node state matches the persisted chain.
4. **No `--seed` / deterministic-DKG flag** in the enclave CLI (checked `nodes`, `wallet`, `net`, `password` help) — so seed-derived shares (option b) are unavailable. Not needed: persist-to-disk (option a) is the built-in mechanism.

## Implications for the supervisor (Task 1.2) and Fly config (Task 1.5)

- `.enclave/data` → symlinked to the Fly `/data` volume; survives stop→start.
- `anvil --state /data/anvil-state.json` → chain (incl. ciphernode registrations + cast ballots) survives.
- **Warm boot MUST NOT** call `dev_cipher.sh`'s nuke, `enclave nodes purge`, or redeploy. It re-sets the (deterministic) node wallets and runs `enclave nodes up` against the preserved data dir.
- The chain-id-keyed log (`log.31337`) means anvil MUST keep chain-id 31337 across restarts (it does — fixed in the supervisor's `anvil` invocation).

## Residual risk + where it's resolved

- Strong but not proven that the per-round DKG *secret shares* (not just identity/registration) are in the persisted DB. The blobs DB and event-sourced model make this very likely. **Definitive confirmation = Task 1.5 Step 3** (encrypt a ballot, let the machine sleep, wake, decrypt — must succeed). If it fails, flip to `min_machines_running=1`.
