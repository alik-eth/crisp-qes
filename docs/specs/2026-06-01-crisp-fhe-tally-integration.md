# CRISP / Interfold FHE encrypted-tally integration — design

**Status:** design (branch `feat/crisp-fhe-tally`). Grounded in the *actual* CRISP reference source (`gnosisguild/enclave/examples/CRISP`, read 2026-06-01), not the generic E3 mental model. **Not research — an integration of a testnet-ready stack.** The live demo's tally stays a transparent on-chain counter until this lands.

## Goal

Give petitions an **encrypted tally**: ballots stay encrypted, only the aggregate (or a "threshold reached" predicate) is revealed. Adopt CRISP (Interfold/Enclave E3) for the FHE machinery; keep **our** Diia-QES + Grumpkin-OPRF enrollment as the eligibility/Sybil layer.

## CRISP as it actually is (reference impl)

Per-vote Noir circuit (`circuits/bin/crisp/src/main.nr`) is **modular** — three separable concerns:
1. **Eligibility** (STEP 2): `merkle_root` membership of `poseidon(slot_address, balance)` in a *census* tree (token holders). Admin-set root (`CRISPProgram.setMerkleRoot`).
2. **Authentication** (ECDSA section): `validate_signature` over a message by an Ethereum key; `slot_address == derive_address(pubkey)`. One **slot per address**.
3. **Ballot + FHE** (the rest): BFV ciphertext commitments (`ct0is/ct1is`, plaintext `k1`), `check_coefficient_values_with_balance` (vote ≤ balance, `num_options`), ciphertext-addition, and **mask votes**. Heavy BFV-encryption-correctness is a separate `user_data_encryption` circuit verified **recursively in the `fold` circuit**; RISC Zero zkVM does the homomorphic sum; `CRISPProgram.verify()` checks the RISC0 proof; `decodeTally()` writes the result on-chain.

Contract (`CRISPProgram.sol`): `publishInput` decodes `(noirProof, slotAddress, encryptedVoteCommitment, encryptedVote)`, `_processVote` inserts/updates the slot's ciphertext in the votes Merkle tree keyed by `voteSlots[slotAddress]`, then `honkVerifier.verify(noirProof, [prevCommitment, merkleRoot, slotAddress, …])`.

**Coercion-resistance mechanism = mask votes** (anyone adds a zero-vote to a slot → the slot's ciphertext changes but decrypts the same → no provable receipt). *This corrects our earlier "JCJ fake-credentials" framing: CRISP achieves receipt-freeness via mask votes + encrypted tally, out of the box — JCJ is a different, heavier scheme we do not need to adopt to get receipt-freeness.*

## The reconciliation (the only real design knot)

CRISP's eligibility is an **address+balance token census authenticated by an Ethereum ECDSA signature**. Ours is a **QES-backed, operator-blind, one-person enrollment** with a per-petition nullifier — and we're **walletless** (voters have no Ethereum key; they hold the vault secret `s`). The splice:

| CRISP concept | Replace with (ours) |
|---|---|
| `slot_address` (one slot per ETH address) | **per-petition nullifier** `f(s, petition_id)` (one slot per enrolled person per petition; unlinkable across petitions) |
| census `merkle_root` = poseidon(address, balance) tree | our **EnrollmentRegistry** root (membership of `s = pedersen(OPRF(RNOKPP))`) |
| ECDSA-over-address auth + `slot==derive_address(pubkey)` | **proof-of-knowledge of `s`** + nullifier derivation (our existing sign circuit) — no wallet |
| `balance` / weighted vote | `balance = 1` (one-person-one-vote); support = 1-bit, multi-option = one-hot |

**What we keep from CRISP unchanged:** the entire BFV section — ciphertext commitments, `ciphertext_addition`, mask votes, the `user_data_encryption` + `fold` recursive encryption proof, RISC Zero tally, `decodeTally`. We only swap the *eligibility + auth + slot-key* sections. This is the same graft pattern as the OpenAC note in the roadmap: external system = the heavy privacy machinery; **we supply Sybil-resistance + operator-blindness; the nullifier is the splice point.** Crucially, our nullifier is **load-bearing for tally integrity** — it's the cleartext gate that admits exactly one ballot per person into the blind homomorphic sum.

## Concrete change set

- **Circuit** (`circuits/bin/crisp/src/main.nr`, forked into our tree): replace STEP 2 + ECDSA section with our pedersen-Merkle membership of `s` (against the EnrollmentRegistry root) + nullifier derivation; expose **nullifier** as the public "slot" input. Keep all BFV/commitment/mask-vote logic. Both ours and CRISP's are Noir/UltraHonk over BN254 → one circuit, no cross-curve recursion. (Verify `enclave_lib` BFV params + our pedersen/Grumpkin gadgets coexist.)
- **Contract** (`CRISPProgram.sol`, forked): rekey `voteSlots` from `address` → `bytes32 nullifier`; reject reused nullifier (our anti-double-vote); set census root from our `EnrollmentRegistry.enrollmentRoot()` (or read it live). Keep `verify`/`decodeTally`/RISC0 path.
- **Client/SDK**: alongside our enrollment proof, use the CRISP SDK (`crisp-sdk`) to BFV-encrypt the ballot + build circuit inputs; our worker emits the fused proof (membership + nullifier + ciphertext commitments).
- **PetitionRegistry**: petitions that opt into encrypted tally route to the CRISP E3 program instead of the transparent counter (per-petition `tallyMode`, as in the multi-option design).
- **Services / ops** (the real cost): run the E3 stack — Enclave + CRISPProgram + verifiers, a coordination server, a **ciphernode committee**, and RISC Zero proving (Boundless for prod; fake proofs in dev). Or rely on Interfold operating the committee.

## On-chain answer (for the record)
Encrypted ballots **are** on-chain (in the votes Merkle tree); the final tally is **on-chain and proven** — `verify()` checks a RISC Zero proof that the homomorphic aggregate of exactly those on-chain ciphertexts decodes to the published number, then `decodeTally()` writes it. Proven (zkVM, on-chain-verified) **and** threshold-decrypted (committee). Only individual ballots / running count stay encrypted.

## Open questions to close before coding
1. **`fold` / recursive structure** — confirm how the `user_data_encryption` proof composes with our modified `crisp` circuit (does swapping the eligibility section disturb the commitment linkage to `fold`?).
2. **`enclave_lib` BFV params** (`N`, `L`, `QIS`, …) vs our BN254 field + pedersen/Grumpkin gadgets in one circuit — gate-count + memory (mind the iOS 832 MiB floor; this circuit is heavy).
3. **Pluggability** — fork CRISP's `crisp` circuit, or author our own E3 *program* from the template? (E3 = "write your encrypted program" → likely our own program, CRISP as reference.)
4. **Ops model** — do we run ciphernodes + RISC0/Boundless, or consume an Interfold-operated committee? Cost + liveness.

## Spike results — measured 2026-06-01 (beta.19, UltraHonk `bb gates`)

Cloned `gnosisguild/enclave`, compiled the CRISP circuits on **our** toolchain (nargo 1.0.0-beta.19, bb 4.0.0-nightly). Toolchain compatibility was **easy** — the only fix was a test-only patch in `circuits/lib` (`Vec::from_slice` → `Vec::new` in 4 `#[test]` fns; removed in beta.19). Far friendlier than the noir-bignum/RSA situation.

| Circuit | Gates (`circuit_size`) | Notes |
|---|---|---|
| **`crisp` vote circuit** | **139,125** | eligibility (secp256k1 ECDSA + poseidon-Merkle) + BFV ciphertext commitments/addition + mask-vote logic. **This is where our eligibility swap lives.** |
| `crisp_fold` (recursive aggregation) | **1,508,638** | recursion: verifies the leaf proofs. Heavy by nature. |
| `user_data_encryption` (BFV leaf) | TBD | didn't cleanly build in the time-box; the BFV-encryption-correctness proof. |
| *(ours, for comparison)* membership+nullifier | ~28,000 | our existing sign circuit |
| *(ours)* `enroll_commit_v2` | ~457,000 | for scale |

**De-risk verdict on the question I set out to answer ("does the fused circuit fit?"):**
- ✅ **The part we modify fits.** The `crisp` circuit is **139k** — *lighter than our enroll circuit*. Swapping CRISP's secp256k1-ECDSA + poseidon-Merkle eligibility (~heavy) for our pedersen-Merkle membership + nullifier (~28k) keeps it the same order (~120–150k est.). It compiles on our toolchain today.
- ⚠️ **New, bigger risk surfaced: the recursion.** `crisp_fold` is **~1.5M gates**. The per-vote *on-chain* proof (`publishInput` → `honkVerifier.verify`) carries the **`crisp` circuit's** public inputs (merkleRoot, slotAddress, prevCommitment) — so the light 139k proof is plausibly the on-chain one — but the BFV-correctness path (`user_data_encryption` + the ~1.5M `fold`) is additional. **Whether that recursion runs client-side (in-browser) or server-side (coordinator/ciphernodes) is now the decisive feasibility question** — 1.5M gates in-browser would blow past our iOS 832 MiB floor; server-side keeps the client light.

**Next unknown to close (supersedes earlier "open question 1"):** trace CRISP's proving placement — does the voter's browser generate the `fold`/`user_data_encryption` proofs, or only the `crisp` leaf proof (with aggregation done by the coordination server / ciphernodes)? That single fact decides browser/iOS viability of encrypted voting.

### Proving-placement trace — answered 2026-06-01 (the decisive finding)

Read `crisp-sdk/src/vote.ts` `generateProof` (called from the React client's `useVoteCasting`). **The entire proving stack runs CLIENT-SIDE, in the voter's browser**, per vote:
1. prove `user_data_encryption_ct0` (BFV leaf)
2. prove `user_data_encryption_ct1` (BFV leaf)
3. prove `crisp` (eligibility, 139k)
4. `generateRecursiveProofArtifacts` for each of the above
5. prove `user_data_encryption` (recursively verifies ct0 + ct1)
6. prove **`fold`** (recursively verifies `user_data_encryption` + `crisp`) — **~1.5M gates**

All via `@aztec/bb.js` `UltraHonkBackend.generateProof(..., 'noir-recursive-no-zk')` in the browser. The **`fold` proof is the on-chain-submitted one** (its public inputs `[merkleRoot, slotAddress, …]` are what `publishInput` verifies).

**Consequences (honest):**
- **It cannot be moved server-side.** The proofs are over the voter's *private* inputs (the cleartext vote + signature). Delegating to a server would reveal the ballot → breaks the secret-ballot guarantee. Client-side proving is *inherent* to the privacy model.
- **iOS-in-browser ≈ infeasible.** Our enroll circuit (457k) already sits at the 832 MiB iOS Safari floor with no headroom; a **1.5M-gate recursive `fold`** (plus the BFV recursion) is several× past it. Encrypted voting on mobile Safari is almost certainly out.
- **Desktop = heavy but plausible.** Six sequential proofs incl. a 1.5M fold → multi-GB peak, likely minutes per vote. Fine for desktop, painful for UX.

**Revised verdict on encrypted tally:** it is a **desktop-only / native-app feature**, not a drop-in for the mobile-friendly flow. The transparent on-chain counter stays the default (and the mobile path); CRISP encrypted tally becomes an *opt-in, desktop-grade* mode per petition — or waits on the **iOS native-app track** (Rust prover, roadmap) to make heavy proving portable. Our eligibility swap (139k, cheap) is *not* the bottleneck; **CRISP's inherent recursive proving cost is**, and it's a client-device constraint, not something the integration can engineer away.

## Phasing
1. **Spike (local):** clone `gnosisguild/enclave`, run the CRISP example on Hardhat (fake zkVM proofs) end-to-end — baseline understanding.
2. **Eligibility swap (circuit):** fork the `crisp` circuit, replace eligibility/auth with our membership+nullifier, prove it compiles + measure gates/mem.
3. **Contract rekey:** `voteSlots` by nullifier; census = enrollment root; local E2E.
4. **Client/SDK wiring + PetitionRegistry `tallyMode`.**
5. **Sepolia/Base testnet** with real RISC0 proving; then committee/ops decision for production.
