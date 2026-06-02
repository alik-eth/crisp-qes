# CRISP FHE Multi-Option Voting — Demo Design (single-operator, 3-node co-hosted committee)

**Date:** 2026-06-02
**Status:** Approved (design); implementation pending
**Branch (target):** `feat/crisp-fhe-tally` (current) or a fresh `feat/fhe-multi-option-voting`

## Goal

Add **encrypted, multi-option (1-of-N) voting** to the CivicVoice demo on top of the
existing Diia-QES + Grumpkin-OPRF enrollment. A voter who is enrolled (a leaf in the
Base Sepolia `EnrollmentRegistry`) can cast a one-hot ballot on a question (e.g.
"Cats / Dogs / Both"); the ballot is **BFV-encrypted in the browser**, proven
well-formed with the `crisp_qes` Honk fold proof, verified on-chain, homomorphically
summed, and threshold-decrypted by the operator's committee into a per-option tally.

This fills the concrete gap the user hit: enrolled, but no petitions to vote on and
no option-selection UI.

## Scope decisions (locked with the user)

1. **Trust model: demo-grade, single operator.** One party (the user) runs the whole
   CRISP backend and the committee. Not a decentralized deployment.
2. **Committee: 3 co-hosted ciphernodes, decryption requires all 3.** Exercises the
   real BFV DKG + threshold-decrypt path; individual-ballot secrecy requires collusion
   of all three nodes. The nodes are still co-hosted by one operator, so this is
   "needs to compromise 3 processes," **not** independent-operator security. Independent
   operators + verifiable DKG remain tracked as tasks #23 / #27.
3. **Chain: operator-controlled persistent anvil on Fly.** Enclave is deployed
   **nowhere public** (the repo config is local-anvil only: deterministic CREATE
   addresses, `ws://localhost:8545`, `program.dev:true`). Deploying Enclave to Base
   Sepolia would be a from-scratch port + a mocked RISC-Zero verifier and would **not**
   strengthen trust (the decryption proof is dev/fake either way). So CRISP runs on an
   operator chain; **enrollment + petitions stay on Base Sepolia**. Two-chain demo.
4. **Ballot definitions: new on-chain `BallotRegistry`** on the operator chain. Stores
   `{ e3Id, question, optionLabels[], enrollmentRoot, deadline }` so labels are
   on-chain + tamper-evident (operator-written).
5. **FHE preset: `insecure-512`**, `program.dev=true` (fake RISC-Zero decryption proof
   — tally is operator-asserted, not ZK-verified). `secure-8192` is out of scope (OOMs
   locally, ~29 GiB).
6. **Proving: desktop-only.** `crisp_qes` fold proof is ~120k gates, 30–120s on desktop,
   infeasible on iOS — consistent with the enrollment prover already living at the iOS
   memory edge.

## Trust caveats (MUST be disclosed in-app + in the runbook)

- **Ballot secrecy holds against other voters and the public, but only against the
  operator if the 3 co-hosted nodes do not collude.** Since one operator hosts all
  three, this is a soft guarantee — disclose it plainly.
- **The tally is operator-asserted** (`program.dev=true` → fake decryption proof), not
  ZK-verified.
- **The operator chain is an anvil the operator controls** — operator controls
  consensus and history. The integrity-bearing artifacts a third party can still check:
  the on-chain Honk verification of each ballot's well-formedness proof, and the
  eligibility binding to the *Base Sepolia* enrollment root (which the operator does not
  control).
- Upgrade path: 3 independent-operator nodes + verifiable DKG + real RISC-Zero
  (Boundless) proving — tasks #23 / #27.

## Architecture

### Backend (operator, Fly)

```
┌────────────────────────── one Fly app (supervisor) ──────────────────────────┐
│  persistent anvil (Fly volume, --dump-state/--load-state)   chainId = <op>    │
│      │                                                                         │
│      ├─ Enclave E3 graph  (enclave, ciphernode_registry, bonding_registry,    │
│      │    slashing_manager, fee_token)        ── `pnpm evm:deploy` (unchanged) │
│      ├─ CRISPQESVerifier (Honk) + CRISPQESProgram  ── `deployQes.ts` (unchanged)│
│      ├─ BallotRegistry (NEW)                   ── new deploy step               │
│      │                                                                         │
│  3× ciphernode (cn1..cn3)  BFV DKG, insecure-512, threshold = 3-of-3 decrypt  │
│  program server  (enclave program, dev mode)                                  │
│  coordination server (Rust Actix, /qes/* routes: broadcast, active-slots,     │
│                       enrollment-root, tally)                                  │
└───────────────────────────────────────────────────────────────────────────────┘
```

- **Persistence:** anvil is ephemeral by default. We mount a Fly volume and use
  `anvil --state /data/anvil-state.json` (load on boot, dump on interval/SIGTERM) so the
  Enclave/CRISPQES/BallotRegistry deployments and all cast ballots survive restarts.
- **Packaging:** a single Fly app runs anvil + 3 nodes + program + coordination server
  under a process supervisor (adapting the existing `dev_*.sh` scripts to target the
  persistent anvil instead of an ephemeral one). Deliberately not production topology.
- **Committee/threshold:** set committee size 3 in `enclave.config.yaml`; configure the
  BFV decryption threshold so **all 3** are required. (Phase-1 task: confirm the enclave
  DKG supports n-of-n for `insecure-512`; if only t<n is available, document the actual
  threshold achieved.)

### Client (web / civicvoice)

- **Round list + ballot UI** (`packages/web`): read open rounds from `BallotRegistry`
  (operator chain) + stage from `Enclave.getE3(e3Id)`; render one-hot option cards.
- **Witness assembly:** reuse the enrolled secret + Merkle path (against the Base Sepolia
  enrollment root snapshot for the round); compute per-round nullifier
  `= pedersen([enrollment_secret, e3Id, DOMAIN_PETITION_V2])`.
- **Encrypt + prove (Web Worker):** `@crisp-e3/zk-inputs` (BFV encrypt) + bb.js
  (`crisp_qes` + fold), 30–120s, progress UI. Reuse the SDK's `generateCircuitInputs` /
  `generateProof` rather than reimplementing.
- **Submit:** `encodeSolidityProof` → coordination server `/qes/broadcast` →
  `CRISPQESProgram.publishInput(e3Id, encoded)` (Honk verify on-chain).
- **Results:** after the deadline the operator closes the round; the 3-node committee
  threshold-decrypts; web reads decoded per-option counts (`decodeTally` / coordination
  server) and renders them.

### Eligibility binding (no circuit change)

`crisp_qes` already takes `enrollment_root` + `nullifier` as **public inputs** and
proves Merkle membership in-circuit; it does **not** read `EnrollmentRegistry` on-chain.
So at round-open the operator snapshots `EnrollmentRegistry.enrollmentRoot()` from
**Base Sepolia**, stores it in `BallotRegistry`, and sets it on the E3 round. Voters
prove membership against that snapshot. Nullifier prevents double-voting per round.
Snapshot semantics: enrollments after round-open cannot vote that round (acceptable).

## Data flow

```
enroll (Base Sepolia, existing)
  → operator opens round:
        root = BaseSepolia EnrollmentRegistry.enrollmentRoot()
        BallotRegistry.createRound(e3Id, question, labels[], root, deadline)
        Enclave.requestE3(...) with numOptions = labels.length, enrollment_root = root
  → committee DKG publishes committeePublicKey
  → voter selects ONE option
  → browser: BFV-encrypt one-hot vote + crisp_qes/fold proof
  → publishInput (operator chain): Honk verify, store encrypted ballot keyed by nullifier
  → operator closes round → 3-node threshold decrypt → tally on-chain
  → web renders per-option counts
```

## Components / file map

**New:**
- `vendor/crisp-qes-enclave/examples/CRISP/packages/crisp-contracts/contracts/BallotRegistry.sol`
  (or a sibling in `packages/contracts` if we prefer Foundry — TBD in plan; default:
  alongside CRISPQES in the Hardhat package so it deploys in the same flow).
- Operator-chain Fly app: `infra/fhe-operator/` (Dockerfile + supervisor + fly.toml +
  anvil-state volume) — exact path decided in the plan.
- `packages/web/src/lib/vote.ts` — generate vote proof + submit (wraps crisp-sdk).
- `packages/web/src/lib/voteRound.ts` — read BallotRegistry + Enclave E3 state.
- `packages/web/src/workers/voteProof.worker.ts` — off-main-thread encrypt+prove.
- `packages/web/src/components/BallotSelector.tsx`, `VoteModal.tsx`, results view.

**Modified:**
- `vendor/.../examples/CRISP/enclave.config.yaml` — committee size 3, persistent-anvil RPC.
- `vendor/.../examples/CRISP/scripts/*` — supervisor that targets persistent anvil.
- `packages/web` round/petition pages — surface "Vote" rounds + option UI.
- Round-open operator script (new) reading the Base Sepolia root.

**Reused unchanged:** `crisp_qes` + `fold` circuits, `CRISPQESVerifier.sol`,
`CRISPQESProgram.sol`, crisp-sdk `vote.ts`/`circuitInputs.ts`/`encoding.ts`, the
`pnpm evm:deploy` + `deployQes.ts` toolchain.

## Plan shape (6 phases — detailed in the implementation plan)

1. **Backend infra up.** Persistent anvil + Enclave/CRISPQES deploy + 3-node committee +
   program + coordination server on Fly. Acceptance: the existing `qesVote` E2E (or a
   trimmed version) passes against the live operator stack; DKG publishes a committee key;
   a ballot proof verifies on-chain.
2. **BallotRegistry** contract + deploy + operator round-open script (snapshots Base
   Sepolia root). Acceptance: a round is created on-chain and readable.
3. **Web: round list + ballot selection UI.** Acceptance: open rounds + one-hot option
   cards render from on-chain data.
4. **Web: in-browser encrypt + `crisp_qes` proof (worker) + submit.** Acceptance: a real
   enrolled user casts a ballot that verifies on-chain and lands in the vote tree.
5. **Web: results/tally display.** Acceptance: operator closes a round, committee
   decrypts, per-option counts render.
6. **Operator runbook + trust-caveat disclosure (in-app + docs) + full E2E dry run.**

## Out of scope

- Independent-operator committee, verifiable DKG, real Boundless proving (#23/#27).
- `secure-8192` preset.
- iOS in-browser proving.
- Mask-daemon / liveness re-encryption (optional CRISP feature; not required for demo).
- On-chain ZK-verified tally (kept `program.dev=true`).
