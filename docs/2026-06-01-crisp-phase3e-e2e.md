# CRISP-QES Phase 3e — Task 5: scripted local END-TO-END (encrypted-vote round)

The done-gate for Phase 3e. This composes Tasks 0–4 into ONE runnable
encrypted-vote flow on a local self-run stack: create a numOptions=3 round → set
the census enrollment root → cast a REAL QES vote (option 0) → run a mask-daemon
sweep → reject a double-vote → run the FHE tally and assert the on-chain
`decodeTally(e3Id) == [1,0,0]`.

The **durable deliverables are the scripts** (they are correct and runnable
regardless of how far any single live run gets). Every piece they drive is
already independently validated (SDK self-verify gate, on-chain acceptance gate,
mask-daemon tests, dev-tally test); Task 5 is the composition.

## One-command repro

```bash
# from the monorepo root (/data/Develop/crisp-qes), branch feat/crisp-fhe-tally
bash scripts/crisp-fhe/e2e-local.sh
```

Useful env toggles:

| env | effect |
| --- | --- |
| `SKIP_BOOTSTRAP=1` | reuse an already-built tree (skip `bootstrap.sh`) |
| `SKIP_TALLY=1`     | stop after the double-vote rejection (skip committee decryption) |
| `KEEP_STACK=1`     | leave the stack running after the driver (no teardown) |
| `COMMITTEE_KEY_TIMEOUT_S`, `TALLY_TIMEOUT_S` | time-box the two long waits |

Logs land in `scripts/crisp-fhe/.e2e-logs/<timestamp>/` (`stack.log`,
`driver.log`, `bootstrap.log`).

## What the scripts do

### `scripts/crisp-fhe/e2e-local.sh` (monorepo — orchestration)

1. `bootstrap.sh` (Task 0): pinned bb, regenerated circuit targets, builds the
   SDK / contracts / server (skippable).
2. Brings up the local self-run stack **with the QES contracts** in the
   background, in its own process group (so teardown can kill the whole tree):
   `examples/CRISP/scripts/dev_up_qes.sh`.
3. Time-boxed readiness gates: anvil RPC, `CRISPQESProgram` in
   `deployed_contracts.json`, and the coordination server answering on `:4000`.
   Each wait aborts early (with the exact unmet condition) if the stack process
   dies, so a partial run says precisely where it stopped.
4. Runs the round driver `examples/CRISP/tests/qes-e2e.mjs` (real vote → mask →
   double-vote → tally), tee-ing to `driver.log`.
5. Tears the stack down (unless `KEEP_STACK=1`).

### `examples/CRISP/scripts/dev_up_qes.sh` (fork — QES stack bring-up)

Mirrors the stock `dev.sh` (anvil + deploy + `dev_services.sh`) but swaps the
legacy `crisp_deploy.sh` (→ `CRISPProgram`) for `crisp_qes_deploy.sh` (→
`CRISPQESProgram` + `CRISPQESVerifier`, Task 1). Everything downstream — the DKG
ciphernodes, program-server, coordination-server (which carries the Task-2
`/qes/*` routes) — is the unchanged dev flow. There was no `dev:up:qes` target
before; this is the small glue the task anticipated.

### `examples/CRISP/tests/qes-e2e.mjs` (fork — the round driver)

Drives an already-running stack (RPC + coordinator via env). Stages, each logged
`STAGE n/…`, each failing with the exact stage name:

1. **create round** — `cli init -n 3` (see CLI change below). Reuses the full
   fee-quote / token-approve / `requestE3` / input-window timing in
   `server/src/cli/commands.rs::initialize_crisp_round`; only `numOptions` is now
   caller-supplied.
2. **enrollment root** — synthetic depth-20 single-leaf tree + pedersen
   (inlined from `packages/crisp-sdk/tests/qesVote.test.ts`); pins it on-chain via
   `CRISPQESProgram.setEnrollmentRoot` (owner-only; deployer = anvil[0] = our
   signer — required because `publishInput` reverts `EnrollmentRootNotSet` if it
   is zero).
3. **committee key (DKG)** — polls `getE3Stage` + the coordinator `/state/lite`
   for the BFV public key (time-boxed).
4. **real vote (option 0)** — SDK `generateCircuitInputsImpl` + `generateProof`
   (the validated QES recursive path, ~130 s), `encodeSolidityProof`, then
   `POST /qes/broadcast {round_id, encoded_proof, enrollment_root}`. Asserts the
   broadcast is accepted, the on-chain `getSlotIndex` ≥ 0, and the nullifier shows
   up in `/qes/active-slots`.
5. **mask sweep** — `MaskDaemon.fromConfig({…, once:true}).sweepRound(e3Id)` (the
   real Task-3 daemon, HTTP submitter via `/qes/broadcast`); asserts ≥ 1 slot
   masked AND the slot's ciphertext in `/qes/active-slots` **changed**.
6. **double-vote** — re-broadcast the SAME real-vote tuple (same nullifier);
   asserts the broadcast is **rejected** (on-chain `SlotAlreadyVoted`).
7. **tally** — waits for the input window to close, polls
   `enclave.getE3(e3Id).plaintextOutput`, then asserts
   `CRISPQESProgram.decodeTally(e3Id) == [1,0,0]`.

Module resolution: the driver lives at `tests/` (no local `node_modules`), so it
resolves `viem` / `@crisp-e3/sdk` / `@aztec/bb.js` by absolute path anchored at
the `crisp-sdk` package, and the mask-daemon `.ts` by absolute file URL — so it
runs from any cwd under `tsx`.

### CLI change (small glue)

`server/src/cli` `Init` gained an optional `-n/--num-options` flag (default **2**,
preserving every existing call). The QES E2E needs `numOptions=3`; the legacy CLI
hardcoded 2. This is the round-creator surface, so threading `numOptions` through
`initialize_crisp_round` is the minimal, additive way to create a 3-option round
while reusing the entire existing request flow. No server-route / contract /
circuit / verifier / daemon LOGIC was touched.

## LIVE RUN

> **Hardened-circuit re-run (1-of-N one-hot assert, 2026-06-02 00:00Z).** Added a
> structural one-hot constraint to the `crisp_qes` leaf
> (`check_at_most_one_nonzero_option`) so 1-of-N holds independent of `balance`
> (the shared value-check only caps the vote *sum* at `balance` for num_options>2 —
> upstream CRISP split-vote semantics). This shifts the recursive VK chain, so the
> fold's INSECURE key-hash global and the on-chain verifier were regenerated with
> the pinned bb (`scripts/crisp-fhe/regen-fold-keyhash.sh`):
> `CRISP_FOLD_EXPECTED_KEY_HASH_INSECURE 0x22f0b7da → 0x25e7c875`, and
> `CRISPQESVerifier.sol VK_HASH 0x0290872b → 0x123028bd` (25 inputs). **All 7 stages
> passed** against the NEW verifier — i.e. the deployed Honk verifier accepted the
> real-vote + mask fold proofs of the hardened circuit; `decodeTally == [1,0,0]`.
> Fork `df64fc00`; run log `scripts/crisp-fhe/.e2e-logs/20260601T214642Z/`.
> CAVEAT: the `_SECURE` key-hash is left STALE — the secure-8192 rebuild OOMs this
> host (~29 GiB for one N=8192 leaf compile), so it must be regenerated on a
> high-memory build host; a secure build fails the fold key-hash assert (fail-safe)
> until then. The deployed + local-E2E preset is insecure-512.
> NOTE: a prior "hardened" run was actually the OLD circuit — bootstrap's
> `git submodule update` reverted the fork to the recorded pointer, orphaning the
> hardening commit; fixed by bumping the monorepo submodule pointer.
>
> **Re-run confirmation (post security-fix ABI, 2026-06-01 20:09Z).** After the
> Phase 3 security review + fix round (FIX-A: `petition_id` bound on-chain,
> `is_mask_vote` made a public input, the publishInput tuple slimmed from the old
> 6-element `(bytes,bytes32,uint256,bool,bytes32,bytes)` to the 5-element
> `(bytes,bytes32,bool,bytes32,bytes)`), the full E2E was re-run and **all 7 stages
> passed again** against the new ABI — leaf proof now `9 public inputs`, fold
> `9 public inputs and 342 fields` on-chain, `decodeTally(e3Id=0) == [1,0,0]`.
> Run log: `scripts/crisp-fhe/.e2e-logs/20260601T195641Z/`.
>
> **Third bug the re-run surfaced (build-freshness, fixed):** the round driver
> imports `@crisp-e3/sdk` from the compiled `dist/index.js`, **not** the TS source.
> The dist built before FIX-A still emitted the old 6-element tuple, so the fixed
> 5-element server rejected every broadcast with "Invalid QES publishInput tuple" —
> identical symptom to a stale server binary, different artifact. Fix: `bootstrap.sh`
> now builds the crisp-sdk dist (`tsup --no-dts`) alongside zk-inputs, and
> `e2e-local.sh` force-rebuilds it (and asserts the stale 6-elem tuple is absent)
> before the driver runs. Commit `ba1cde7`.

<!-- FILLED IN FROM THE ACTUAL RUN BELOW -->

Stack (fresh clean-slate localhost deploy, 5-ciphernode Micro committee, real
threshold DKG with ZK proof aggregation):

- `Enclave`           = `0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0`
- `CRISPQESProgram`   = `0x7969c5eD335650692Bc04293B07F5BF2e7A673C0`
- `CRISPQESVerifier`  = `0x2bdCC0de6bE1f7D2ee689a0342D76F52E8EFABa3`

### Stage results (live, single self-run stack, e3Id=0)

| Stage | Result |
| --- | --- |
| 0. bootstrap + stack bring-up (anvil + QES deploy + 5-node DKG + coordinator) | ✅ PASS — stack came up; coordinator + 5 active ciphernodes |
| 1. create numOptions=3 round (`cli init -n 3`) | ✅ PASS — `requestE3` succeeded, e3Id=0 |
| 2. set enrollment root (on-chain `setEnrollmentRoot`) | ✅ PASS |
| 3. committee key published (DKG) | ✅ PASS — `CommitteePublished`, stage→KeyPublished (~60 s DKG) |
| 4. real vote accepted + slot created | ✅ PASS — proof ~155 s, **`/qes/broadcast` accepted, deployed Honk verifier verified the REAL proof on-chain**, `InputPublished` index 0, nullifier in `/qes/active-slots` |
| 5. mask sweep changes slot ciphertext | ✅ PASS — mask-daemon `slot_masked` (mask proof ALSO accepted on-chain), slot ciphertext changed (9242 B, differs) |
| 6. double-vote rejected (`SlotAlreadyVoted`) | ✅ PASS — second same-nullifier vote rejected (http 500, `failed_broadcast`) |
| 7. tally `decodeTally == [1,0,0]` | ✅ PASS — window closed → `CiphertextReady` → committee decrypted headlessly → `PlaintextOutputPublished` → stage `Complete`; **`decodeTally(e3Id=0) == [1,0,0]`** |

**ALL 7 STAGES PASSED on a single live self-run stack.** `bash
scripts/crisp-fhe/e2e-local.sh` exited 0 and tore the stack down cleanly.

The headline live result: **on a fully live stack (real 5-node threshold DKG with
ZK proof aggregation, no mocks), the deployed `CRISPQESVerifier` accepted BOTH a
real vote proof and a mask proof through `CRISPQESProgram.publishInput`**, the
nullifier slot was created and then re-randomized by the credential-free mask, a
double-vote was rejected by the on-chain append-only rule, and — the piece that was
deferred to Task 5 — the **committee decrypted the homomorphic tally headlessly**
and the on-chain `decodeTally` returned `[1,0,0]` for the single option-0 vote.

### Two real bugs the composition surfaced (both fixed)

1. **Coordinator tuple decode (`server/src/server/routes/qes.rs`)** — `/qes/broadcast`
   decoded the publishInput tuple with alloy `abi_decode` (the WRAPPED single-tuple
   form), but the SDK encodes it with viem `encodeAbiParameters` and the contract
   reads it with Solidity `abi.decode(data, (...))` — both the UNWRAPPED head-of-params
   form. So every real SDK-encoded broadcast was rejected with "Invalid QES publishInput
   tuple". Verified with a standalone alloy 1.0.41 probe: `abi_decode`→err,
   `abi_decode_params`→ok. Fix: one call, `abi_decode` → `abi_decode_params`. This is a
   server change (flagged), but it is a genuine correctness fix aligning the coordinator
   with BOTH the contract and the SDK; the route was non-functional without it, and it
   was never caught because `/qes/broadcast` had only ever been unit-tested with
   hand-built tuples / mocked submitters, never driven with a real SDK proof.
2. **Driver status check** — the coordinator's `VoteResponseStatus` serializes
   snake_case (`"success"`), the driver compared against `"Success"`. Driver-only fix.

### Frictions hit + how handled

- **Readiness ordering** — the coordination server answers on `:4000` BEFORE the
  ciphernodes are registered/active; `requestE3` reverts `InsufficientCiphernodes`
  until ≥3 are active. Added a `.enclave/ready`-file gate (written by `dev_cipher.sh`
  only after all ciphernodes are registered + active) ahead of the round-create stage.
- **DKG** — real 5-node threshold DKG with ZK proof aggregation took ~60 s
  (CommitteeFinalized→KeyPublished); driver polls with a time-boxed wait.
- **Proving time + load** — each fold proof is ~150 s in bb.js; under the loaded
  host (5 ciphernodes + prover, load avg ~15-25) a single proof stretched well past
  that. Both proofs still landed inside the input window (E3_DURATION=600 s).
- **Stack lifecycle** — the stack is launched in its own process group (`setsid`)
  and torn down via the group + named-process kills; the orchestration keeps it
  alive for the whole driver run.

## Files

- `scripts/crisp-fhe/e2e-local.sh` (monorepo) — orchestration + readiness gates + teardown.
- `examples/CRISP/scripts/dev_up_qes.sh` (fork) — QES stack bring-up.
- `examples/CRISP/tests/qes-e2e.mjs` (fork) — the round driver.
- `examples/CRISP/server/src/cli/{main,commands}.rs` (fork) — additive `--num-options` flag (glue).
- `examples/CRISP/server/src/server/routes/qes.rs` (fork) — coordinator decode fix
  (`abi_decode` → `abi_decode_params`); a real correctness bug the composition surfaced,
  flagged above. Without it `/qes/broadcast` rejects every real SDK-encoded vote.
