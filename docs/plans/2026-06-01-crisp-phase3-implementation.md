# CRISP-QES Phase 3 Implementation Plan — masking + multi-option encrypted tally

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up an opt-in **encrypted tally** for petitions — vote-once, multi-option (2…N, one-hot), with receipt-freeness via permissionless mask votes (Design A) + a masking-liveness daemon (Design C) — by forking CRISP's `crisp` leaf circuit + `CRISPProgram` contract + `crisp-sdk`, swapping CRISP's token-census/ECDSA eligibility for our pedersen-Merkle membership + per-petition nullifier.

**Architecture:** Work against a **pinned clone of `gnosisguild/enclave`** (the CRISP example), not a full monorepo vendoring (that is Phase 3e+). We modify three layers — the `crisp_qes` Noir leaf (already spiked, 69,167 gates), `CRISPProgram.sol`, and `crisp-sdk` — so they agree on ONE public-input ABI, then prove a real vote + a mask vote end-to-end on local anvil with dev (fake-zkVM) proofs. The slot key becomes our `bytes32 nullifier`; the mask path is credential-free (the contract already knows a slot exists); multi-option rides CRISP's existing `num_options` BFV machinery unchanged.

**Tech Stack:** Noir 1.0.0-beta.19 + Barretenberg `bb` 4.0.0-nightly (UltraHonk, BN254); Solidity ≥0.8.27 + Hardhat/Foundry; TypeScript + `@aztec/bb.js` + vitest; local anvil (Foundry). Reference: `docs/specs/2026-06-01-crisp-fhe-tally-integration.md` and `docs/specs/2026-06-01-crisp-phase3-masking-multioption-design.md`.

**Scope guardrails (from the design):** IN = vote-once append-only, multi-option one-hot, A+C masking. OUT = encrypted-petition revoke, immediate-coercion defense, JCJ, ranked/score ballots, monorepo vendoring, real RISC0 proving (dev fake-zkVM only until 3e).

**Working location:** `/tmp/enclave/examples/CRISP` (Phase 1/2 clone; re-clone + re-apply the two one-time fixes if gone — see "Environment setup"). The protected repo `/data/Develop/crisp-qes` holds only specs/plans/fixtures for this phase; the implementation lives in the clone until 3e.

---

## Environment setup (do once, before Task 0)

- [ ] **Verify or rebuild the CRISP clone.**

Run:
```bash
test -d /tmp/enclave/examples/CRISP || git clone --recurse-submodules https://github.com/gnosisguild/enclave /tmp/enclave
cd /tmp/enclave/examples/CRISP
git submodule update --init --recursive packages/crisp-contracts/lib/risc0-ethereum
# beta.19 fix already applied in Phase 1 (circuits/lib Vec::from_slice -> Vec::new in #[test] fns); re-apply if a fresh clone:
grep -rl "Vec::from_slice" circuits/lib/src 2>/dev/null && echo "RE-APPLY beta.19 lib patch (see Phase 1 report)"
test -d ~/.bb-crs && echo "SRS cached" || echo "first bb prove will need NODE_TLS_REJECT_UNAUTHORIZED=0"
nargo --version && bb --version
```
Expected: `nargo 1.0.0-beta.19`, `bb 4.0.0-nightly`, submodule present, lib patch applied.

- [ ] **Confirm the Phase 2 fork exists** at `circuits/bin/crisp_qes/` (`main.nr` + `merkle.nr`). If missing, recreate from `docs/specs/2026-06-01-crisp-fhe-tally-integration.md` §"Phase 2 spike" (full `main.nr` is captured there) + copy `merkle.nr` from `/data/Develop/crisp-qes/packages/circuit/src/merkle.nr`.

---

## File structure

In the CRISP clone (`/tmp/enclave/examples/CRISP`):
- `circuits/bin/crisp_qes/src/main.nr` — forked leaf, **two modes** (real-vote: membership+nullifier+ballot; mask: zero-vote+ct-add only). Owns the public-input ABI.
- `circuits/bin/crisp_qes/src/merkle.nr` — our pedersen-Merkle walker (copied, unchanged).
- `circuits/bin/crisp_qes/Prover.real.toml`, `Prover.mask.toml` — witness fixtures for gate/compile checks + ABI extraction.
- `packages/crisp-contracts/contracts/CRISPQESProgram.sol` — fork of `CRISPProgram.sol`: `voteSlots` keyed by `bytes32 nullifier`; append-only dedup; credit-free mask entry; public-input array rebuilt to match our circuit; multi-option `decodeTally` kept.
- `packages/crisp-contracts/contracts/CRISPQESVerifier.sol` — **regenerated** Honk verifier from our circuit VK (replaces `CRISPVerifier.sol`).
- `packages/crisp-contracts/test/CRISPQESProgram.t.*` — contract tests (real vote inserts slot + dedups; mask updates existing slot, no dedup; multi-option tally decode).
- `packages/crisp-sdk/src/circuitInputs.ts` — rewritten input builder (drop ECDSA/balance/token-merkle; add `enrollment_secret`/`merkle_path`/`nullifier`/`petition_id`; mask-mode branch).
- `packages/crisp-sdk/tests/qesVote.test.ts` — Node proving test for a real vote + a mask vote (mirrors Phase 1's `vote.test.ts`).
- `services/mask-daemon/` (new, minimal) — sweeps zero-masks onto active slots.

Reference-only in the protected repo:
- `/data/Develop/crisp-qes/packages/circuit/src/{main.nr,merkle.nr}` — our membership+nullifier source of truth (READ-ONLY here).

---

## Task 0: Establish the canonical public-input ABI (circuit ↔ verifier ↔ contract)

**Why first:** `CRISPProgram.publishInput` builds a fixed `bytes32[7]` and `honkVerifier.verify(proof, publicInputs)` checks it against a baked-in VK. Our fork changes the circuit's public inputs, so the verifier must be regenerated and the contract array rewritten to match — all three must agree before anything else compiles end-to-end. This task pins that ABI.

**Files:**
- Inspect: `/tmp/enclave/examples/CRISP/circuits/bin/crisp/src/main.nr`, `packages/crisp-contracts/contracts/CRISPProgram.sol` (the `publishInput` array, lines building `noirPublicInputs[0..6]`), `circuits/bin/crisp_qes/src/main.nr`.
- Create: `circuits/bin/crisp_qes/src/main.nr` (finalized signature), `docs/plans/abi.md` note inside the clone.

- [ ] **Step 1: Extract the real circuit's public-input order.**

Run (in the clone):
```bash
cd /tmp/enclave/examples/CRISP/circuits/bin/crisp_qes
nargo compile
# the ABI (param order + visibility + return) is in the compiled artifact:
node -e "const a=require('./target/crisp_qes.json'); console.log(JSON.stringify(a.abi.parameters.filter(p=>p.visibility==='public').map(p=>p.name)), 'return:', JSON.stringify(a.abi.return_type))"
```
Expected: the ordered list of public param names + the `(Field,Field,Field)` return. In Noir/UltraHonk, **return values are appended to the public inputs**, so the on-chain public-input vector = `[public params… , return fields…]`. Record this exact order.

- [ ] **Step 2: Define the target ABI for our fork.** Write it as a comment block at the top of `circuits/bin/crisp_qes/src/main.nr`. Target (real-vote mode), chosen to mirror CRISP's slots:

```
// PUBLIC-INPUT ABI (real-vote mode), index order the contract MUST replicate:
//   [0] prev_ct_commitment      (Field)  - previous slot ciphertext commitment (0 on first vote)
//   [1] enrollment_root         (Field)  - our EnrollmentRegistry root (was CRISP merkleRoot)
//   [2] nullifier               (Field)  - per-petition slot key (was slot_address)
//   [3] petition_id             (Field)  - binds the nullifier to this petition
//   [4] is_first_vote           (bool->Field)
//   [5] num_options             (u32->Field)
//   [6] committee_public_key    (Field)  - threaded through to the BFV/ct proof (keep CRISP's slot)
//   [.. return ..] (ct_commitment, ct_commitment_or_sum, k1_commitment)  - appended by Noir
// Mask mode reuses the same vector; nullifier[2] = the TARGET slot being masked,
// enrollment_root[1]/petition_id[3] are unused-but-present (asserted only in real-vote branch).
```

> If Step-1 extraction shows the original `crisp` leaf does NOT itself consume `committee_public_key` (it is consumed by the `user_data_encryption`/`fold` proofs, and the contract merely forwards it), keep slot [6] as a forwarded public input the leaf ignores, so the on-chain `fold` proof's public vector stays shaped as CRISP expects. Confirm against the `fold` circuit's public inputs (read `circuits/bin/crisp_fold` or `crisp-sdk/src/vote.ts` to see which proof is submitted and its public-input layout). **This confirmation is the deliverable of Task 0** — record the true on-chain (fold) public-input vector, since that, not the leaf, is what `honkVerifier.verify` checks.

- [ ] **Step 3: Commit the ABI decision** (in the clone's git) so later tasks reference one source of truth.

```bash
cd /tmp/enclave && git add examples/CRISP/circuits/bin/crisp_qes/src/main.nr && git commit -m "phase3 task0: pin crisp_qes public-input ABI"
```

---

## Task 1: Finalize the two-mode `crisp_qes` leaf circuit

**Files:**
- Modify: `circuits/bin/crisp_qes/src/main.nr`
- Create: `circuits/bin/crisp_qes/Prover.real.toml`, `circuits/bin/crisp_qes/Prover.mask.toml`
- Test: `nargo test` (in-circuit `#[test]` fns) + `bb gates`

- [ ] **Step 1: Splice the mask path to be credential-free.** In `main.nr`, change the `is_mask_vote` branch so it does NOT require membership or nullifier derivation, and add `petition_id` + the public-input order from Task 0. Apply this diff to the Phase 2 `main.nr`:

- Add `petition_id: pub Field` to the signature (after `enrollment_root`/`nullifier` per Task 0 order).
- Move the membership assert and the `valid_nullifier` so they fire **only in the real-vote branch**:

```rust
    // STEP 2 (real-vote only): enrollment membership + nullifier binding.
    // For mask votes, eligibility of the TARGET slot is enforced by the
    // contract (the slot exists only because a valid real vote created it),
    // so the mask path needs no secret.
    let computed_null = pedersen_hash([enrollment_secret, petition_id, DOMAIN_PETITION_V2]);

    // ... keep STEP 1 commitments, valid_vote, mask machinery as before ...

    if is_mask_vote == false {
        // real vote: prove membership + nullifier, then ballot validity
        let recomputed_root =
            compute_root::<TREE_DEPTH>(enrollment_secret, merkle_path, merkle_path_indices);
        assert(recomputed_root == enrollment_root);
        assert(nullifier == computed_null);
        assert(valid_vote);

        (ct_commitment, ct_commitment, k1_commitment)
    } else {
        // mask vote: zero ballot + (if updating) ciphertext addition. No secret.
        assert(valid_zero_vote);
        if is_first_vote {
            (ct_commitment, ct_commitment, k1_commitment)
        } else {
            assert(valid_prev_ct);
            assert(valid_ct_add);
            (sum_ct_commitment, ct_commitment, k1_commitment)
        }
    }
```

> Keep `enrollment_secret`, `merkle_path`, `merkle_path_indices` as private inputs (unused in the mask branch — Noir tolerates this; if the unused-witness gates bother the gate count, measure both and decide in Step 4 whether to split into two compiled circuits).

- [ ] **Step 2: Add/keep `#[test]` coverage.** Port the membership + nullifier determinism tests from `/data/Develop/crisp-qes/packages/circuit/src/main.nr` (the 6 `#[test]` fns) into `main.nr`, adapted to the new signature. Add one new test asserting a mask-mode all-zero `k1` passes `check_coefficient_zero`.

Run: `nargo test`
Expected: all tests PASS (the BFV polynomial tests may need representative constants; if BFV inputs are infeasible to hand-build in a unit test, keep the membership/nullifier tests and rely on Task 5's Node proving test for the BFV path — note this explicitly in a comment).

- [ ] **Step 3: Compile + measure both modes.**

Run:
```bash
cd /tmp/enclave/examples/CRISP/circuits/bin/crisp_qes
nargo compile
NODE_TLS_REJECT_UNAUTHORIZED=0 bb gates -b ./target/crisp_qes.json
```
Expected: compiles clean; `circuit_size` reported. Compare to Phase 2's 69,167 (real-vote). Record the number. The mask path moving membership into a branch should not increase it.

- [ ] **Step 4: Decide one-circuit-vs-two.** If the unused mask-branch witnesses materially inflate gates or complicate the witness, split into `crisp_qes_vote` and `crisp_qes_mask` packages (each compiled separately, each with its own regenerated verifier). Otherwise keep one circuit with the `is_mask_vote` flag. **Document the decision** in `main.nr`'s header comment.

- [ ] **Step 5: Commit.**

```bash
cd /tmp/enclave && git add -A examples/CRISP/circuits/bin/crisp_qes && git commit -m "phase3 task1: two-mode crisp_qes leaf (credential-free mask) + tests + gate measurement"
```

---

## Task 2: Regenerate the Honk verifier from our circuit

**Files:**
- Create: `packages/crisp-contracts/contracts/CRISPQESVerifier.sol`
- Reference: existing `packages/crisp-contracts/contracts/CRISPVerifier.sol` (the one being replaced)

> **Critical:** the on-chain-verified proof is the **`fold` proof**, not the `crisp` leaf (Phase 1 finding). The verifier we deploy must correspond to whatever proof `crisp-sdk` submits on chain. Determine from Task 0 / `crisp-sdk/src/vote.ts` which circuit's VK backs `CRISPVerifier.sol` today, and regenerate the analogous verifier for our modified pipeline.

- [ ] **Step 1: Identify the on-chain proof + its circuit.** Read `packages/crisp-sdk/src/vote.ts` (`generateProof`) and note which proof's bytes go into the contract `publishInput` payload and what its public inputs are. This is the circuit whose verifier must be regenerated (expected: `fold`, which recursively verifies `crisp` + `user_data_encryption`).

- [ ] **Step 2: Regenerate the verifier.**

Run (adapt circuit path to the on-chain proof's circuit from Step 1):
```bash
cd /tmp/enclave/examples/CRISP/circuits/bin/<on-chain-circuit>
nargo compile
NODE_TLS_REJECT_UNAUTHORIZED=0 bb write_vk -b ./target/<name>.json -o ./target --oracle_hash keccak
NODE_TLS_REJECT_UNAUTHORIZED=0 bb contract -k ./target/vk -o ./target/Verifier.sol
```
(Use the same `bb` verifier-generation invocation the CRISP repo uses — check `packages/crisp-contracts/package.json` scripts or `circuits/` README for the exact `write_vk`/`contract` flags, since `--oracle_hash keccak` and proof flavor must match what `honkVerifier.verify` expects.)
Expected: a `Verifier.sol` whose `verify(bytes,bytes32[])` matches our new public-input count.

- [ ] **Step 3: Install as `CRISPQESVerifier.sol`** (rename contract to `HonkVerifier` import-compatible, or update the import in Task 3's program). Confirm it compiles under the project's Hardhat config: `cd packages/crisp-contracts && pnpm compile` (or `hardhat compile`). Expected: compiles.

- [ ] **Step 4: Commit.** `git add` the new verifier + commit.

---

## Task 3: Fork `CRISPProgram` → `CRISPQESProgram` (nullifier slots, append-only, credit-free mask)

**Files:**
- Create: `packages/crisp-contracts/contracts/CRISPQESProgram.sol` (from `CRISPProgram.sol`)
- Reference: `packages/crisp-contracts/contracts/CRISPProgram.sol` (read in full first)

- [ ] **Step 1: Copy + rekey the slot map.** Copy `CRISPProgram.sol` → `CRISPQESProgram.sol`. In `RoundData`, change:
```solidity
    mapping(bytes32 nullifier => uint40 index) voteSlots;
```
and rename `merkleRoot` semantics to the enrollment root (keep the field name or rename to `enrollmentRoot` consistently). Update `getSlotIndex` and `_processVote` signatures from `address slotAddress` → `bytes32 nullifier`.

- [ ] **Step 2: Rewrite `publishInput` decode + public-input array** to the Task 0 ABI. Replace the decode + `noirPublicInputs` block:
```solidity
    (bytes memory noirProof, bytes32 nullifier, uint256 petitionId, bool isMask,
     bytes32 encryptedVoteCommitment, bytes memory encryptedVote) = abi.decode(
        data, (bytes, bytes32, uint256, bool, bytes32, bytes));

    (uint40 voteIndex, bytes32 prevCommitment) = _processVote(e3Id, nullifier, encryptedVoteCommitment, isMask);

    bytes32[] memory pub = new bytes32[](7); // match Task 0 order EXACTLY
    pub[0] = prevCommitment;
    pub[1] = bytes32(e3Data[e3Id].enrollmentRoot);
    pub[2] = nullifier;
    pub[3] = bytes32(petitionId);
    pub[4] = bytes32(uint256(prevCommitment == bytes32(0) ? 1 : 0)); // is_first_vote
    pub[5] = bytes32(e3Data[e3Id].numOptions);
    pub[6] = e3.committeePublicKey;
    // + append return-value public inputs if the regenerated verifier expects them (see Task 0)
    if (!honkVerifier.verify(noirProof, pub)) revert InvalidNoirProof();
```
Adjust array length + ordering to whatever Task 0 pinned (including appended return fields). **The order here MUST byte-match Task 0.**

- [ ] **Step 3: Implement append-only dedup + credit-free mask in `_processVote`:**
```solidity
  function _processVote(uint256 e3Id, bytes32 nullifier, bytes32 commitment, bool isMask)
      internal returns (uint40 voteIndex, bytes32 prevCommitment)
  {
    uint40 storedIndexPlusOne = e3Data[e3Id].voteSlots[nullifier];
    if (!isMask) {
      // REAL VOTE: append-only — reject a nullifier that already voted
      if (storedIndexPlusOne != 0) revert SlotAlreadyVoted();
      prevCommitment = bytes32(0);
      voteIndex = e3Data[e3Id].votes.numberOfLeaves;
      e3Data[e3Id].voteSlots[nullifier] = voteIndex + 1;
      e3Data[e3Id].votes._insert(uint256(commitment));
    } else {
      // MASK: slot must already exist; no dedup change
      if (storedIndexPlusOne == 0) revert SlotIsEmpty();
      voteIndex = storedIndexPlusOne - 1;
      prevCommitment = bytes32(e3Data[e3Id].votes.elements[voteIndex]);
      e3Data[e3Id].votes._update(uint256(commitment), voteIndex);
    }
  }
```
Add the `SlotAlreadyVoted` error. Keep `validate`, `decodeTally` (multi-option, unchanged), `verify`, journal encoding as-is. Set the enrollment root via the existing `setMerkleRoot` (rename to `setEnrollmentRoot`), to be wired from `EnrollmentRegistry.enrollmentRoot()` off-chain in 3e.

- [ ] **Step 4: Compile.** `cd packages/crisp-contracts && pnpm compile`. Expected: compiles; `CRISPQESProgram` imports the Task 2 verifier.

- [ ] **Step 5: Commit.**

---

## Task 4: Contract tests (real vote inserts+dedups, mask updates, multi-option decode)

**Files:**
- Create: `packages/crisp-contracts/test/CRISPQESProgram.ts` (Hardhat) — follow the existing test harness style in `packages/crisp-contracts/test/`.

- [ ] **Step 1: Write failing tests.** Using a mock Honk verifier (always-true) + mock Enclave (so `publishInput` stage/window checks pass — mirror how the existing CRISP tests stub `enclave.getE3`/`getE3Stage`), assert:
  1. real vote with fresh nullifier → slot created, `getSlotIndex(e3,nullifier) == 0`.
  2. second real vote, same nullifier → reverts `SlotAlreadyVoted` (append-only).
  3. mask on an existing slot → succeeds, `_update` called (slot index unchanged), no dedup change.
  4. mask on a non-existent nullifier → reverts `SlotIsEmpty`.
  5. `decodeTally` with `numOptions = 3` over a crafted `plaintextOutput` returns the expected 3-element vector.

- [ ] **Step 2: Run — expect FAIL** (program not wired / errors not present). `pnpm test --grep CRISPQES`.

- [ ] **Step 3: Make them pass** (fix any wiring from Task 3). Re-run — expect PASS.

- [ ] **Step 4: Commit.**

---

## Task 5: Rewrite `crisp-sdk` circuit inputs + Node proving test (real + mask)

**Files:**
- Modify: `packages/crisp-sdk/src/circuitInputs.ts` (and `types.ts` `ProofInputs` as needed)
- Read first: `packages/crisp-sdk/src/{encoding.ts,utils.ts,vote.ts,types.ts}` — do NOT invent the `zkInputsGenerator` API; adapt to what `getZkInputsGenerator().generateInputs/generateInputsForUpdate` actually return.
- Create: `packages/crisp-sdk/tests/qesVote.test.ts`

- [ ] **Step 1: Swap the eligibility/auth inputs.** In `circuitInputs.ts`, after the BFV `result` is built, REPLACE the CRISP eligibility/ECDSA assignments (the `signature`/`public_key_*`/`hashed_message`/`slot_address`/`balance`/`merkle_*` block) with our inputs:
```ts
  // CRISP-QES enrollment inputs (replace CRISP token-census + ECDSA)
  circuitInputs.enrollment_secret = proofInputs.enrollmentSecret.toString()
  circuitInputs.merkle_path = proofInputs.merklePath.map((s) => s.toString())          // [Field;20]
  circuitInputs.merkle_path_indices = proofInputs.merklePathIndices.map((i) => i.toString()) // [u1;20]
  circuitInputs.enrollment_root = proofInputs.enrollmentRoot.toString()
  circuitInputs.nullifier = proofInputs.nullifier.toString()
  circuitInputs.petition_id = proofInputs.petitionId.toString()
  circuitInputs.is_first_vote = !proofInputs.previousCiphertext
  circuitInputs.is_mask_vote = proofInputs.isMaskVote
  circuitInputs.num_options = numOptions.toString()
```
For **mask mode** (`proofInputs.isMaskVote === true`), supply dummy/zero `enrollment_secret`, `merkle_path`, `merkle_path_indices`, `enrollment_root`, `petition_id` (the circuit ignores them in the mask branch), set `nullifier` = the TARGET slot nullifier, and ensure the encoded vote is the zero vector (already `getZeroVote`). Update `ProofInputs` in `types.ts` accordingly (drop `signature`/`balance`/token `merkleProof`; add the enrollment fields). Keep the BFV `zkInputsGenerator` calls (`generateInputs` / `generateInputsForUpdate`) untouched — that machinery is unchanged.

- [ ] **Step 2: Write the Node proving test** (mirror Phase 1's `packages/crisp-sdk/tests/vote.test.ts` which proved in ~176 s). Two cases: (a) a real vote produces a valid proof whose membership+nullifier publics match; (b) a mask vote on a prior ciphertext produces a valid proof (zero ballot + ct-add). Use a small synthetic enrollment tree (single leaf, depth-20, all-zero siblings — same construction as our `packages/circuit` tests) for the membership witness.

- [ ] **Step 3: Run.**
```bash
cd /tmp/enclave/examples/CRISP/packages/crisp-sdk
NODE_TLS_REJECT_UNAUTHORIZED=0 pnpm exec vitest --run tests/qesVote.test.ts
```
Expected: both proofs generate + self-verify (allow minutes per proof; the full recursive chain incl. `fold` runs). If `fold`/verifier expects the new public-input shape, regenerate (Task 2) and align.

- [ ] **Step 4: Commit.**

---

## Task 6: Masking-liveness daemon (Design C)

**Files:**
- Create: `services/mask-daemon/` (a small Node/TS service in the clone) — `index.ts`, `package.json`.

- [ ] **Step 1: Implement the sweep.** A loop that, for an active e3Id: reads all active slots (their nullifiers + current ciphertexts) from chain/coordination server, and for each, builds a **mask** proof via the Task-5 SDK mask path and submits it through the same `POST /voting/broadcast` → `publishInput` route a voter uses. No enrolled credential needed (mask path is credential-free). Make cadence + per-sweep slot budget configurable (env).

- [ ] **Step 2: Integration smoke test.** On local anvil with one real vote present, run one daemon sweep and assert the masked slot's on-chain ciphertext commitment changed while `decodeTally` (after a forced tally) is unchanged in plaintext. (Plaintext-invariance is the receipt-freeness property.)

- [ ] **Step 3: Document** the single-daemon-backstopped-by-permissionless-masking trust note (from the design §"Design C") in the service README. Commit.

---

## Task 7: Local end-to-end (the Phase 3 acceptance gate)

- [ ] **Step 1: Bring up the stack** (Phase 1 commands) with `CRISPQESProgram` + `CRISPQESVerifier` deployed in place of the originals (adjust the deploy script's contract names). Create a round with `numOptions = 3`.
- [ ] **Step 2: Cast one real multi-option vote** via the SDK (Node), `publishInput` succeeds, slot created.
- [ ] **Step 3: Run a daemon mask sweep**, confirm the slot ciphertext changed.
- [ ] **Step 4: Attempt a double real-vote** (same nullifier) → expect `SlotAlreadyVoted` revert.
- [ ] **Step 5: Drive the (fake-zkVM) tally** and `decodeTally` → expect a 3-element vector consistent with the single cast vote (masks contributed zero).
- [ ] **Step 6: Write a short `PHASE3-E2E.md`** in the clone capturing the exact commands + outcomes, and copy it back to `/data/Develop/crisp-qes/docs/` as the phase record. Commit (in the protected repo) the e2e record + any updated fixtures.

---

## Task 8 (milestone, NOT bite-sized): Testnet + productionization (Phase 3e)

Out of TDD scope — a milestone to plan separately once 3a–3d are green:
- Real RISC0 tally proving (Boundless) instead of dev fake-zkVM.
- Wire `enrollmentRoot` live from `EnrollmentRegistry.enrollmentRoot()`; `PetitionRegistry` `tallyMode`/`num_options`; route encrypted petitions to the E3 program.
- Vendor the forked circuit/contract/SDK into the civic-voice monorepo (decide layout); CRS self-hosting (reuse our existing mirror).
- Committee/ops decision (run ciphernodes vs consume an Interfold-operated committee); multiple independent maskers.
- Desktop/iOS-native proving path (the ~1.5M `fold` is desktop/native-only per Phase 1).

---

## Self-review notes (author)

- **Spec coverage:** masking reconciliation (Tasks 0–5), A permissionless mask (Task 1 credential-free branch + Task 3 credit-free entry), C daemon (Task 6), multi-option (Tasks 0/3/4/5 `num_options`), append-only/no-revoke (Task 3 `SlotAlreadyVoted`), known-limitations carried to Task 8. ✔
- **Highest-risk unknowns, surfaced not hidden:** (1) the on-chain proof is `fold`, so the verifier/ABI work (Tasks 0/2) is the real risk, not the leaf; (2) `zkInputsGenerator` internals (Task 5 says read, don't invent); (3) whether unused mask-branch witnesses inflate gates (Task 1 Step 4 decision point). These are explicit decision points, not placeholders.
- **TDD:** contract (Task 4) and SDK (Task 5) are test-first; circuit uses `nargo test` + `bb gates`; daemon has an integration smoke test (Task 6 Step 2); Task 7 is the acceptance gate.
