# FHE + Identity Local E2E — Design

**Date:** 2026-06-03
**Branch:** `feat/crisp-fhe-tally`
**Status:** Design — awaiting sign-off (then → implementation plan)

## 1. Goal

Extend the local CRISP-QES end-to-end test so the vote is gated by the **real
identity/enrollment layer** driven by **synthetic certificates**, instead of the
current random-secret shortcut. Deliver **two variants**:

- **Full** (`fhe + identity`): synthetic Diia cert → real `enroll_commit_v2`
  proof → real 3-node **threshold OPRF** → on-chain **`EnrollmentRegistry`** root
  → FHE vote → mask → double-vote reject → **threshold-decrypt tally**.
- **Smoke**: the same enrollment + vote path, but **skip the ~6-min tally**
  (mirrors today's `SKIP_TALLY=1`).

The FHE-only variants (no identity) stay runnable as a fast regression.

## 2. Background — what's synthetic today

`vendor/crisp-qes-enclave/examples/CRISP/tests/qes-e2e.mjs` currently builds the
voter's eligibility from a **random** scalar:

```
s = random(); tree = buildSingleLeafTree(s); setEnrollmentRoot(e3Id, root)
```

The vote circuit (`circuits/bin/crisp_qes/src/main.nr`) only checks
`nullifier == pedersen([s, petition_id, DOMAIN])` and Merkle-membership of the
leaf in `enrollment_root`. It does **not** care how `s` was derived — so the
extension replaces "random `s` + single-leaf tree" with "`s` produced by a real
enrollment, in a tree whose root is published on-chain by the registry."

## 3. The binding (why this composes)

The vote's `enrollment_secret`/leaf is the value the OPRF service commits at
`/v3/register`, derived from the unblinded OPRF output `N`. The **exact**
derivation is taken verbatim from the canonical helper `packages/oprf/src/pedersen.ts`
(do **not** re-guess it in the new code — import/mirror it). The vote circuit
consumes that same `s`. They match by construction.

**Merkle compatibility — CONFIRMED identical** (the key correctness gate):

| Property | Service `service/merkle.mjs` | Vote circuit `crisp_qes/src/merkle.nr` |
| --- | --- | --- |
| Node hash | `pedersenHash([l,r], hashIndex:0)` | `pedersen_hash_with_separator([l,r], 0)` |
| Arity | binary | binary |
| Index semantics | `idx=1` ⇒ sibling first | `is_right` ⇒ sibling first |
| Zero subtree | `zero[i]=hash2(zero[i-1],zero[i-1])` | (same) |
| Depth | `TREE_DEPTH = 20` | `TREE_DEPTH = 20` |
| Genesis root | `0x1b49e706af69da35927cdf2b28b02fb2647245ac0ccbc376d062031185d3cd84` | (same empty tree) |

A `merklePath`/`merklePathIndices` returned by `/v3/register` will verify in the
vote circuit's `compute_root::<20>()`.

## 4. Hard constraint — two processes (bb.js split)

| Side | Package | `@aztec/bb.js` | noir |
| --- | --- | --- | --- |
| Enrollment (`enroll_commit_v2`, `oprf_nullifier`) | `packages/oprf/v3-grumpkin` | `4.0.0-nightly` | beta.19 |
| Vote (`crisp_qes`) | `vendor/.../crisp-sdk` | `3.0.0-nightly` | beta.16 |

These **cannot co-exist in one Node process**. Therefore the test is **two-phase**:

1. **Enrollment phase** — a standalone Node process in the OPRF package's 4.x env.
   Produces an **enrollment artifact JSON** (`s`, `leafIndex`, `merklePath`,
   `merklePathIndices`, `enrollmentRoot`, plus metadata) and triggers the on-chain
   `updateRoot`.
2. **Vote phase** — the existing `qes-e2e.mjs` (3.x env), which reads the artifact
   and votes with the real `s` + path + on-chain root.

The two phases communicate **only** through the artifact file + the chain — never
by sharing a bb.js instance.

## 5. The synthetic-CA gate path (new blocker)

`/v3/blind-eval` is **proof-gated**: it verifies an `enroll_commit_v2` proof
before evaluating. The **production** `enroll_commit_v2::main()` pins the **real**
Diia QTSP CA keys, so a proof built over a **synthetic** CA fails the gate (this is
the pre-existing `register-test.mjs` / `e2e-test.mjs` blocker).

**Solution (test-only):** run the gate against a **test-pinned** build of
`enroll_commit_v2` that pins the synthetic CA (the circuit already has
`test_pinned_with_synth()` / `test_synth_ca()` for its `#[test]` functions —
expose that pin as a buildable test target the service gate can load).

> **HARD SECURITY RULE.** The synthetic CA must **never** enter the production
> pinned set or any production build. The test gate must be a clearly separated,
> clearly labeled artifact, loaded only when an explicit local/test flag is set.
> The production `main()` keeps the real Diia pins untouched.

## 6. Local stack (added to the harness)

On the **same anvil** the FHE stack already runs (chainId 31337):

- **`EnrollmentRegistry`** deployed with `genesisRoot = 0x1b49e7…`,
  `genesisLeafCount = 0`, `oprfAttester = addr(V3_ATTESTER_KEY dev)`,
  `admin = anvil[0]`. (Per the prior cold-start lesson, genesisLeafCount=0 so
  there are no event-less genesis leaves.)
- **3-node OPRF threshold service** — `node packages/oprf/v3-grumpkin/service/server.mjs`
  with dev `V3_THRESHOLD_SEED` + `V3_ATTESTER_KEY` (the labeled dev fallbacks are
  fine for local; keep gitignored, never echo/commit), `PORT` (e.g. 8788). The
  service's in-memory tree is authoritative; the chain mirrors it.
- **`updateRoot` submission** — default: submit directly from the enrollment phase
  using the `attesterSig` returned by `/v3/register` (signer == registry's
  `oprfAttester`). The relayer (`packages/relayer`) is an alternative but not
  required.

No second anvil; no relayer process in the default path.

## 7. End-to-end data flow

```
ENROLLMENT PHASE (bb.js 4.x, separate process)
  1. gen synthetic cert (gen-enroll-commit-v2-witness.mjs: synth CA, RNOKPP, DOB)
  2. enroll_commit_v2: prove + verify (test-pinned synth CA gate)
        → public: M=(x,y), C_r, messageDigest
  3. POST /v3/blind-eval { M, proof, publicInputs }
        → per-share partials B_i + DLEQ + publishedKpubSet (gate verified step 2)
  4. combine 2-of-3 (pinned Lagrange) + unblind  → N
  5. derive s  (canonical pedersen.ts derivation)
  6. gen-threshold-nullifier-witness → oprf_nullifier: prove
        → public: nullifier
  7. POST /v3/register { commitment=s, enrollProof, nullifierProof, ... }
        → { leafIndex, merklePath[], merklePathIndices[], oldRoot, newRoot, attesterSig }
  8. EnrollmentRegistry.updateRoot(newRoot, [s], attesterSig)   (on-chain)
  9. write enrollment-artifact.json { s, leafIndex, merklePath, merklePathIndices,
        enrollmentRoot=newRoot }

VOTE PHASE (bb.js 3.x, qes-e2e.mjs)
 10. read enrollment-artifact.json
 11. assert on-chain EnrollmentRegistry.enrollmentRoot() == artifact.enrollmentRoot
 12. CRISPQESProgram.setEnrollmentRoot(e3Id, enrollmentRoot)
 13. vote with witness { enrollment_secret=s, merkle_path, merkle_path_indices,
        enrollment_root } → prove crisp_qes + fold → broadcast
 14. mask sweep → double-vote reject
 15. (full only) close window → threshold-decrypt → decodeTally == [1,0,0]
```

## 8. Variant switch

The harness gains one new flag; `SKIP_TALLY` keeps its meaning:

| Variant | Invocation |
| --- | --- |
| FHE + identity, **full** | `WITH_IDENTITY=1 bash scripts/crisp-fhe/e2e-local.sh` |
| FHE + identity, **smoke** | `WITH_IDENTITY=1 SKIP_TALLY=1 bash scripts/crisp-fhe/e2e-local.sh` |
| FHE only, full / smoke (regression) | (unset `WITH_IDENTITY`) — unchanged |

When `WITH_IDENTITY` is unset, `qes-e2e.mjs` falls back to the random-`s`
single-leaf tree (existing behavior preserved).

## 9. File plan

**Create**
- `scripts/crisp-fhe/enroll-synthetic.mjs` — enrollment-phase orchestrator
  (steps 1–9). bb.js 4.x. Writes the artifact; submits `updateRoot`.
- `packages/contracts/script/DeployEnrollmentRegistry.s.sol` — forge deploy
  (genesisRoot/genesisLeafCount/attester/admin from env) **if** no equivalent
  script already exists.
- A buildable **test-pinned** `enroll_commit_v2` target + a service-gate flag to
  load it (synthetic CA), test-only.

**Modify**
- `scripts/crisp-fhe/e2e-local.sh` — when `WITH_IDENTITY=1`: deploy
  `EnrollmentRegistry`, boot the OPRF service (time-boxed `/healthz` wait), run
  `enroll-synthetic.mjs`, then run the vote driver with `ENROLLMENT_FILE` set.
  Teardown also stops the OPRF service.
- `vendor/.../examples/CRISP/tests/qes-e2e.mjs` — read `ENROLLMENT_FILE`; use real
  `s`/path/root when present; assert on-chain root match; else fall back to random.

## 10. Security constraints (carry-through)

- Synthetic test CA **never** in the production pinned set / prod build (§5).
- Dev `V3_THRESHOLD_SEED`, `V3_ATTESTER_KEY`, `ADMIN_PRIVATE_KEY`: gitignored,
  never echoed/committed. Only the labeled local dev fallbacks are used here.
- No real PII (RNOKPP / DOB / real `.p7s`) — synthetic cert only.
- Fork edits via explicit `git add <files>` only, never `git add -A`.

## 11. Risks / open items

- **Exact `s` derivation** — pin verbatim from `pedersen.ts` + `server.mjs`
  `/v3/register` during implementation (two earlier readings differed on
  `[N.x,N.y]` vs `[N_hi,N_lo]`; the code is the source of truth).
- **Enroll proof cost/time** — `enroll_commit_v2` is a large circuit; the
  enrollment phase adds one (or two, with `oprf_nullifier`) heavy proofs on top of
  the 2 fold proofs. Expect the full identity run to be meaningfully longer than
  the ~12.5-min FHE-only full run. Time-box all readiness waits.
- **Service tree vs registry genesis** — both must start from `0x1b49e7…`;
  assert equality at boot.
- **bb CLI vs bb.js** — generate any circuit artifacts with the bb bundled in the
  package's `@aztec/bb.js`, not a CLI `bb` on PATH (VK-hash sensitivity).

## 12. Done = both variants green

`WITH_IDENTITY=1` full run reaches `decodeTally == [1,0,0]`; `WITH_IDENTITY=1
SKIP_TALLY=1` smoke run passes through double-vote reject. Memory
`project_fhe_backend_fly` updated with the identity-inclusive E2E status.
