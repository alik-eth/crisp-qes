# CRISP-QES Phase 3 — masking reconciliation + multi-option encrypted tally (design)

**Status:** design (branch `feat/crisp-fhe-tally`). Resolves the one open question from the Phase 2 spike (`2026-06-01-crisp-fhe-tally-integration.md` §"Phase 2 spike"): how receipt-freeness via mask votes survives our nullifier-as-slot model. Scope set with the user 2026-06-01.

## Scope (decided 2026-06-01)

Encrypted-tally v1 for petitions that opt in (`tallyMode = encrypted`):
- **In:** vote-once **append-only** ballots; **multi-option** (2…N options, one-hot); **full receipt-freeness** via mask votes (Design **A + C** below); per-petition opt-in alongside the transparent counter.
- **Out (deferred, explicitly):** revoke / re-vote for encrypted petitions; pre-deadline immediate-coercion defense; JCJ fake-credentials. Transparent-counter petitions keep full revoke unchanged.

## The guarantee we are restoring (precise)

CRISP mask votes defeat the **cryptographic receipt**: a voter opening the *on-chain* ciphertext with their encryption randomness `r`. A third party adds `Enc(0; r_mask)` to the slot → the on-chain ciphertext changes → the voter's `r` no longer opens it and they lack `r_mask` → no verifiable opening. Masks do **not** defeat a voter who voluntarily reveals `s` and argues structurally ("it's my slot, I'm the only real voter") — that residual is JCJ territory, already roadmapped as the separate endgame. **Bar for Phase 3: restore "no verifiable on-chain opening."**

## Root cause of the Phase 2 flag

In our spliced leaf the slot key is `nullifier N = pedersen([s, petition_id, DOMAIN])`, which does **double duty**: (1) public slot key, (2) one-person-one-vote dedup token. CRISP never coupled these — its slot was a public address, decoupled from the eligibility secret. The Phase 2 splice also (mistakenly) asserted *masker* membership in the mask path. CRISP's mask path actually authenticates the **target** (the masked slot is an eligible census member), **not the masker** — masks carry no signature; anyone can mask any eligible slot.

## Design A — permissionless mask, target nullifier as public input

**Key simplification:** "the target slot exists / is eligible" is something our **contract already knows** (`voteSlots[N]` is non-empty, and it only became non-empty via a valid real-vote proof). So the circuit's mask path needs **no membership proof, no nullifier derivation, no masker secret** — it collapses to:
- `k1 == 0` (valid zero / all-zero one-hot vector — `check_coefficient_zero`, works for any `num_options`), and
- valid ciphertext addition `sum_ct = prev_ct + Enc(0)` against the **public** `prev_ct_commitment` of the existing on-chain slot (`CiphertextAddition::execute`, kept verbatim from CRISP).

The masker reads the public nullifier `N` and the public current ciphertext from chain, encrypts a fresh zero, proves the addition. Strictly **lighter than the 69k real-vote leaf**; fully permissionless and censorship-resistant; the liveness daemon needs no credential.

### The forked `crisp_qes` leaf — two modes

Real-vote mode (unchanged from the Phase 2 measurement, 69,167 gates):
- pedersen-Merkle membership of `s` against `enrollment_root`
- `nullifier == pedersen([s, petition_id, DOMAIN_PETITION_V2])`
- `check_coefficient_values_with_balance(k1, Q_MOD_T_CENTERED, balance=1, num_options)` (one-person-one-vote, one-hot over `num_options`)
- BFV commitments (STEP 1) + return tuple — **verbatim**

Mask mode (new, lighter):
- no membership, no nullifier derivation
- `check_coefficient_zero(k1, num_options)` (all-zero ballot)
- `CiphertextAddition` against public `prev_ct_commitment`
- `target_nullifier: pub Field` exposed so the contract knows which slot to update
- same return tuple shape → **`fold` linkage intact**

> Implementation note: keep this as the existing `is_mask_vote` branch but (a) remove the membership assert from the mask path, (b) add `target_nullifier` as a public input used only on the mask path. Both modes still return `pub (Field, Field, Field)`.

## Design C — masking liveness daemon (additive)

A masking daemon (relayer or ciphernode committee) sweeps zero-masks onto active slots on a schedule. **Additive to A, never a replacement:** because anyone can mask permissionlessly (A), a malicious or censoring daemon cannot selectively leave a target slot un-masked — any other party can mask it. C exists to guarantee masks *happen by default* without relying on altruistic voters, and to keep voter UX zero-effort.

- v1: single relayer daemon is acceptable *because* A backstops it. Hardening (multiple independent maskers, committee-run masking) is a follow-on.
- The daemon needs no enrolled credential (mask path is credential-free).

## Contract changes (`CRISPProgram.sol`, forked)

`voteSlots: mapping(bytes32 nullifier => SlotData)`:
- **Real vote, `N` unseen** → create slot; record `N` consumed (dedup; reject reused `N`).
- **Real vote, `N` seen** → rejected in v1 (append-only; no re-vote).
- **Mask, slot `N` must exist** → do **not** touch dedup; update ciphertext with `sum_ct`.

Route by proof shape / public inputs (real-vote proof carries membership+nullifier publics; mask proof carries `target_nullifier` + zero-vote). `verify`/`decodeTally`/RISC0 tally path kept. `decodeTally` returns a **per-option vector** of tallies (multi-option). Census root = our `EnrollmentRegistry.enrollmentRoot()`.

## Multi-option ballots

Already supported by CRISP's BFV layer — no new circuit gadgets:
- `num_options` is a public input; ballot = one-hot vector over options; `balance = 1` enforces exactly-one (or none) via `check_coefficient_values_with_balance`.
- Masks = all-zero vector (`check_coefficient_zero`) — option-count agnostic.
- `PetitionRegistry` stores `num_options` per petition; `decodeTally` emits per-option counts; threshold-disclosure policy (`threshold-only` / `full-count` / `never`) applies per the integration spec §4.
- Yes/No = 2 options; 1/2/3/… = N options. Ranked/score ballots are out of v1 scope (one-hot only).

## Known limitations (documented, not solved in v1)

1. **Immediate-coercion race.** Slots can't pre-exist (nullifiers are private until revealed), so masks only land *after* a vote. A coercer demanding proof the instant a voter votes sees an un-masked slot. CRISP has a milder version. Mitigation: masks accrue toward the deadline; the daemon (C) masks promptly after each vote. Full defense is JCJ-endgame.
2. **No encrypted-petition revoke in v1** (append-only). Transparent petitions unaffected.
3. **Single-daemon liveness** is backstopped by permissionless masking (A) but not yet by independent redundancy.
4. **Structural (non-cryptographic) receipt** — a voter revealing `s` can still argue their slot is theirs. Out of scope (JCJ).

## Phasing (Phase 3 sub-steps)

3a. **Circuit:** finalize the two-mode `crisp_qes` leaf (mask path = credential-free, `target_nullifier` public). Compile + measure both modes; confirm `fold` linkage. *(Real-vote mode already at 69k; mask mode is lighter.)*
3b. **Contract rekey:** `voteSlots` by nullifier; dedup on real votes; mask entry point requiring existing slot; multi-option `decodeTally`; census root from `EnrollmentRegistry`. Local E2E on anvil.
3c. **SDK/client:** real-vote + mask proof generation (CRISP `crisp-sdk` BFV-encrypt + our membership/nullifier inputs fused); `PetitionRegistry` `tallyMode` + `num_options`.
3d. **Masking daemon (C):** relayer service that sweeps zero-masks onto active slots.
3e. **Testnet** (Base Sepolia) with real RISC0 tally proving; committee/ops decision for production.

## Open questions to close during 3a–3b

- Exact public-input layout for the two modes (one circuit with a mode flag vs two compiled circuits) — measure both; prefer one circuit if the mask path's dead-code membership doesn't inflate gates.
- Re-vote rejection: enforce append-only in the contract (reject seen `N` on real votes) — confirm this doesn't break the `is_first_vote` logic the BFV/`fold` path expects.
- Daemon masking cadence + gas budget; how many masks per slot constitute "enough" ambiguity.
