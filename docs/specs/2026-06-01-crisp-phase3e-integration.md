# CRISP-QES Phase 3e — integration design (monorepo + locally-runnable encrypted tally)

**Status:** design (branch `feat/crisp-fhe-tally`). Follows the validated Phase 3 build (`docs/2026-06-01-crisp-phase3-e2e.md`): the forked E3 stack proves real + mask votes and they verify **on-chain** against the deployed verifier. This spec turns that ephemeral spike into a **reproducibly buildable, locally-runnable** part of the civic-voice project.

**Scope decided 2026-06-01 (with user):**
- **Ops model:** self-run committee now (local, then testnet next spec) → **Interfold-operated committee for production**. v1 here = self-run local dev committee (the existing 5-ciphernode local stack).
- **Code home:** the fork stays its **own repo** (`alik-eth/crisp-qes-enclave`); civic-voice references it as a **git submodule**; the web app will (in a later spec) talk to a deployed E3 program + coordination service — same separation the OPRF service already uses.
- **v1 boundary:** **monorepo-integrated + locally runnable only.** End state: an encrypted vote is provable + accepted against a **locally-deployed** CRISPQES stack, reproducible from a clean checkout. **OUT of v1:** Base Sepolia deploy, web vote flow, `PetitionRegistry.tallyMode` routing, real-Diia enrollment, Interfold prod committee (all follow-on).

## Goal

From a clean `git clone` of civic-voice (with submodules), a developer can: build the forked E3 circuits/verifier/contracts with the **correct toolchain pinned**, bring up a **local self-run committee + stack**, and run an **end-to-end encrypted vote** (real vote → mask → fake-zkVM tally → `decodeTally`) that uses our Diia-QES/Grumpkin enrollment eligibility. This closes the pre-QES plumbing gaps deferred as Phase 3 Task 7 "P3".

## Where this sits (architecture)

Two committees, unchanged from the integration spec: **enrollment** (our Grumpkin OPRF + ZK, already live) supplies the per-person `nullifier`; **tally** (CRISP/Interfold threshold-FHE + zkVM) homomorphically counts. This spec wires the *tally* half in locally. The nullifier is the splice point (load-bearing for tally integrity: the cleartext gate admitting one ballot per person into the blind sum).

```
civic-voice (monorepo)                      crisp-qes-enclave (submodule, our fork)
  packages/web ........ (later spec)          examples/CRISP/circuits/bin/{crisp_qes,fold}
  packages/oprf ....... enrollment committee  examples/CRISP/packages/crisp-contracts (CRISPQES*)
  packages/contracts .. EnrollmentRegistry    examples/CRISP/packages/crisp-sdk (QES inputs)
  third_party/enclave . => submodule -------\  examples/CRISP/services/mask-daemon
                                             \  + (NEW) QES deploy/server/tally plumbing
```

## What's already done (the validated fork) — do not rebuild

`alik-eth/crisp-qes-enclave` @ `main` (Phase 3 commits `48cdb23`…`f792b8c`):
- `crisp_qes` leaf (credential-free mask, 69k) + `fold` ABI (8 public inputs); circuit tests pass.
- `CRISPQESVerifier.sol` (24 inputs) regenerated with the **bb bundled in bb.js** (see `reference_bb_cli_vs_bbjs_version`).
- `CRISPQESProgram.sol` (nullifier slots, append-only `SlotAlreadyVoted`, credit-free mask, multi-option `decodeTally`); contract + on-chain-acceptance tests (13 green).
- `crisp-sdk` QES inputs + submit encoding; `services/mask-daemon` (Design C).

## What v1 adds (the integration surface)

### 1. Submodule + reproducible build
- Add `crisp-qes-enclave` as a submodule (path TBD in plan, e.g. `third_party/enclave` or `vendor/crisp-qes-enclave`), pinned to a commit.
- A `bootstrap` script that performs the two one-time fixes the spike required, so a clean checkout builds:
  - `git submodule update --init --recursive` (incl. the fork's own `risc0-ethereum` submodule).
  - Resolve `bb` to the **binary bundled in `@aztec/bb.js`** (3.0.0-nightly.20260102), NOT the CLI on PATH — for all circuit/verifier regeneration. This MUST be enforced (it was the Task 2→5 blocker).
  - CRS: reuse our existing same-origin CRS mirror (the `crs.aztec.network` cert is expired); pre-seed `~/.bb-crs` or point bb.js at our mirror.
  - The beta.19 `circuits/lib` `Vec::from_slice`→`Vec::new` test patch, if a fresh fork needs it.
- A `verify` step that runs the fork's circuit + contract + SDK test suites green from the monorepo.

### 2. QES-ify the stack plumbing (the deferred P3 — the real work)
The fork's circuits/contract/SDK/tests are QES-correct, but the surrounding *operational* code is still pre-QES (address-keyed). v1 makes the LOCAL stack actually run a QES vote:
- **Deploy script:** deploy `CRISPQESProgram` + `CRISPQESVerifier` (not the originals); pass the QES verifier to the program constructor; auto-sync the addresses into `enclave.config.yaml` / `server/.env` / `client/.env` as the existing deploy does.
- **Coordination server routes:** the vote-broadcast + previous-ciphertext routes are address-keyed (`get_slot_index_from_address`); add QES equivalents — accept/relay the QES `publishInput` tuple `(bytes, bytes32 nullifier, uint256 petitionId, bool isMask, bytes32, bytes)`, and expose a **nullifier-keyed slot enumeration** (`/qes/active-slots` → `{nullifier, ciphertext}[]`) + `/qes/enrollment-root`. (`InputPublished` does not carry the nullifier — it's only in proof public inputs — so the server must index it from the submit payload.)
- **Masking daemon source:** wire `services/mask-daemon`'s `SlotSource`/`getEnrollmentRoot` to the new `/qes/*` routes (the daemon already requires the census root on mask inputs — Phase 3 Task 7 fix).
- **Tally driver:** a QES fake-zkVM tally path so `decodeTally` returns the per-option vector locally (the program server's dev `fhe_processor` sums ciphertexts; confirm it's option-count-agnostic and drive it for a QES round).

### 3. Local self-run committee
The existing local stack (anvil + 5 ciphernodes + program/coordination servers, Phase 1) IS a self-run dev committee — v1 reuses it, pointed at the QES contracts. No new committee infra; document the bring-up as a single `make`/script target.

### 4. Local E2E acceptance (the v1 done-gate)
From a clean checkout, one command sequence:
1. bootstrap + build (correct bb pinned) + all fork tests green;
2. bring up the local self-run stack with QES contracts deployed;
3. create a `numOptions ≥ 2` round; set enrollment root from a synthetic tree;
4. cast a real QES vote (Node SDK) → `publishInput` accepted on-chain;
5. daemon mask sweep → slot ciphertext changes, plaintext invariant;
6. double-vote rejected (`SlotAlreadyVoted`);
7. drive the fake-zkVM tally → `decodeTally` returns the expected per-option vector.
Captured as a scripted, re-runnable E2E (supersedes the manual on-chain test with a live-stack run).

## Out of scope (explicit) + trajectory

- **Base Sepolia deploy** of the E3 contracts + a hosted coordination service → next spec (self-run committee on testnet).
- **Web vote flow** (`packages/web` desktop encrypted-vote UI; the ~1.5M `fold` is desktop/iOS-native only) → next spec.
- **`PetitionRegistry.tallyMode`** routing (encrypted vs transparent per petition) → next spec; design already in `…-crisp-fhe-tally-integration.md`.
- **Interfold prod committee** migration (replace self-run with their ciphernodes) → production track.
- **Real-Diia enrollment + threshold OPRF** → existing Track 1.

## Open questions to close in the plan

1. **Submodule path + build coupling** — `third_party/` vs `vendor/`; does the monorepo CI build the fork, or just consume prebuilt artifacts (VK/verifier) checked into the fork? (The `target/` VK artifacts are gitignored in the fork → CI must regenerate with the pinned bb, OR we commit the verifier `.sol` only and regenerate VKs.)
2. **bb pinning mechanism** — wrap bb invocations to always use the bb.js-bundled binary; fail loudly if a mismatched `bb` is on PATH.
3. **Coordination server: extend vs fork the routes** — add `/qes/*` alongside the legacy address-keyed ones, or replace? (Local-only v1 → additive is safer.)
4. **Tally driver option-count** — confirm the dev `fhe_processor` handles `numOptions > 2` without changes.

## Risks

- **Toolchain drift** — the bb CLI/bb.js skew already bit us; the bootstrap MUST hard-pin or this recurs on every fork update. Highest-likelihood regression.
- **Upstream fork divergence** — `gnosisguild/enclave` moves; our fork pins a commit. Re-basing onto upstream is periodic manual work (the pre-QES plumbing we add will conflict with their address-keyed code).
- **Rust plumbing surface** — the coordination/program servers are Rust; QES-ifying the routes is the largest single chunk and the least-validated so far (Phase 3 never ran the live Rust path).
