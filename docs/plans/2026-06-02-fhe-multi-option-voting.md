# CRISP FHE Multi-Option Voting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add encrypted, multi-option (1-of-N) voting to the CivicVoice demo: an enrolled user casts a one-hot ballot that is BFV-encrypted in-browser, proven with `crisp_qes`, verified on-chain, summed homomorphically, and threshold-decrypted by a 3-node operator committee — running as one scale-to-zero Fly machine.

**Architecture:** The entire CRISP backend (persistent anvil + Enclave/CRISPQES contracts + 3 ciphernodes + program server + coordination server) runs as **one Fly machine** with a `/data` volume and scale-to-zero. A new on-chain `BallotRegistry` (Foundry, operator chain) holds round metadata. Eligibility binds to the **Base Sepolia** enrollment root (snapshotted at round-open, passed as a public input — no circuit change). The web adds round-list + one-hot ballot UI + a Web Worker that drives the existing enclave `crisp-sdk` vote path.

**Tech Stack:** Foundry (BallotRegistry), Hardhat + ethers (existing Enclave/CRISPQES deploy, unchanged), Rust (enclave nodes + coordination server, unchanged), Fly.io (single-machine + volume + scale-to-zero), React/Vite/viem (web), `@crisp-e3/zk-inputs` + bb.js (in-browser BFV + Honk proof).

**Spec:** `docs/specs/2026-06-02-fhe-multi-option-voting-demo.md`

**Branch:** `feat/crisp-fhe-tally` (current).

---

## Critical context for the implementer

- **The dev scripts assume ephemeral everything** and must NOT be reused verbatim for the deployed stack:
  - `examples/CRISP/scripts/dev_cipher.sh` does `rm -rf ./.enclave/data ./.enclave/config` on every run (fresh DKG) → would orphan ballots on a warm boot. **Warm boot must preserve `.enclave/data`.**
  - `examples/CRISP/scripts/crisp_qes_deploy.sh` runs `pnpm clean:deployments` + redeploys every run → **deploy must happen once (cold init), be skipped on warm boot.**
  - `examples/CRISP/scripts/dev_server.sh` does `rm -rf database` (coordination server re-indexes from chain — OK to keep, it self-heals).
  - `anvil` in `dev.sh`/`dev_up_qes.sh` runs with no `--state` (ephemeral) → **must use `anvil --state`.**
- **Enclave is local-anvil only** (no public deployment). chainId in dev is `31337`, mnemonic `test test test ... junk`, deployer key `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`, ciphernode keys hardcoded in `dev_cipher.sh` (cn1 `0x59c6995e...`, cn2 `0x5de4111a...`, cn3 `0x7c852118...`).
- **The web's `@crisp-qes/sdk` is the local P7S/ASN.1 parser**, NOT the enclave vote SDK. The vote path lives in `vendor/crisp-qes-enclave/examples/CRISP/packages/crisp-sdk` and must be added to the web build (Phase 4).
- **Canonical vote reference:** `vendor/crisp-qes-enclave/examples/CRISP/packages/crisp-sdk/tests/qesVote.test.ts` — mirror its `generateCircuitInputsImpl` → `generateProof` → `verifyProof` → `encodeSolidityProof` flow exactly.
- **SDK signatures (verified):**
  - `generateCircuitInputsImpl(proofInputs: ProofInputs): Promise<{ circuitInputs: any; encryptedVote: Uint8Array }>`
  - `ProofInputs = { previousCiphertext?: Uint8Array; vote: number[]; publicKey: Uint8Array; enrollmentSecret: bigint; merklePath: bigint[/*20*/]; merklePathIndices: number[/*20*/]; enrollmentRoot: bigint; nullifier: bigint; petitionId: bigint /* = e3Id */; isMaskVote: boolean }`
  - `generateProof(circuitInputs): Promise<ProofData>` ; `ProofData = { publicInputs: string[]; proof: Uint8Array; encryptedVote: Uint8Array }`
  - `encodeSolidityProof(p: ProofData, isMask = false): Hex` (encodes `(bytes noirProof, bytes32 nullifier, bool isMask, bytes32 encryptedVoteCommitment, bytes encryptedVote)`; reads `publicInputs[2]=nullifier`, `publicInputs[5]=final_ct_commitment`)
  - `decodeTally`, `verifyProof`, `getZeroVote`, `generateMerkleProof`, `generateMerkleTree`, `hashLeaf`, `MAX_VOTE_OPTIONS`, `MERKLE_TREE_MAX_DEPTH` all exported from the package index.
  - Nullifier (in-circuit) `= pedersen([enrollment_secret, petitionId(=e3Id), DOMAIN_PETITION_V2])`, `DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31` ("v2-pen-no1").
- **CRISPQESProgram on-chain ABI** (operator chain): `publishInput(uint256 e3Id, bytes encoded)`; public-input layout `[0]prev_ct_commitment [1]enrollment_root [2]nullifier [3]is_first_vote [4]num_options [5]final_ct_commitment [6]petition_id(=e3Id, contract-forced) [7]is_mask(contract-forced) [8]pk_commitment`. Getter `getEnrollmentRoot(e3Id)`. Tally via `decodeTally(e3Id)`.
- **Fork discipline:** files under `vendor/crisp-qes-enclave/` are fork work — stage with explicit `git add <file>`, NEVER `git add -A`; after fork commits, bump the monorepo submodule pointer.

## File structure

**New (main repo):**
- `packages/contracts/src/BallotRegistry.sol` — on-chain round metadata (operator chain).
- `packages/contracts/test/BallotRegistry.t.sol` — Foundry tests.
- `packages/contracts/script/DeployBallotRegistry.s.sol` — deploy to operator chain.
- `infra/fhe-operator/Dockerfile` — single-image CRISP backend.
- `infra/fhe-operator/fly.toml` — single machine + volume + scale-to-zero.
- `infra/fhe-operator/supervisor.sh` — cold-init vs warm-boot orchestration.
- `infra/fhe-operator/healthz.mjs` — readiness gate (committee key + chain sync).
- `infra/fhe-operator/open-round.mjs` — operator round-open CLI (snapshot Base Sepolia root → requestE3 → BallotRegistry.createRound).
- `infra/fhe-operator/close-round.mjs` — operator round-close CLI (trigger decrypt + tally).
- `packages/web/src/lib/voteRound.ts` — read BallotRegistry + Enclave E3 state.
- `packages/web/src/lib/vote.ts` — assemble witness + drive SDK + submit.
- `packages/web/src/lib/voteTally.ts` — read/decode tally.
- `packages/web/src/workers/voteProof.worker.ts` — off-main-thread encrypt+prove.
- `packages/web/src/components/BallotSelector.tsx` — one-hot option UI.
- `packages/web/src/components/VoteModal.tsx` — vote flow modal.
- `packages/web/src/components/RoundResults.tsx` — per-option results.
- `packages/web/src/lib/__tests__/*.test.ts` — vitest unit tests.
- `docs/runbooks/2026-06-02-fhe-operator-runbook.md` — operator ops doc.

**Modified (fork — vendor):**
- `vendor/crisp-qes-enclave/examples/CRISP/enclave.config.yaml` — committee 5→3, persistent-anvil RPC, deploy_block source.
- `vendor/crisp-qes-enclave/examples/CRISP/scripts/dev_cipher.sh` — guard the `.enclave/data` nuke behind a cold-init flag (or leave dev script alone and add a sibling `warm_cipher.sh` — see Task 1.3).

**Modified (main repo):**
- `packages/web/package.json` — add the enclave `crisp-sdk` dep + WASM assets.
- `packages/web/vite.config.ts` — WASM + worker config for bb.js/zk-inputs.
- `packages/web/src/pages/*` — surface vote rounds + entry points.

---

## Phase 1 — Backend infra (GATED by the persistence spike)

### Task 1.0: Persistence spike — does a warm restart preserve the committee key?

**This task GATES the whole scale-to-zero approach. Do it first. No code is shipped from it — it produces a decision + a short findings note.**

**Files:**
- Create: `docs/runbooks/2026-06-02-persistence-spike-findings.md`

- [ ] **Step 1: Bring the local stack up (cold) and open a round**

```bash
cd vendor/crisp-qes-enclave/examples/CRISP
pnpm dev:setup            # one-time
pnpm dev:up &             # runs dev.sh: anvil(31337) + crisp_qes deploy + dev_services
# wait for ./.enclave/ready and tcp:4000
# open an E3 round via the coordination server / cli (see scripts/cli.sh) with numOptions=3
bash ./scripts/cli.sh     # follow prompts to request an E3 round
```

- [ ] **Step 2: Capture the committee key + cast one ballot, record artifacts**

Record into the findings doc:
- `e3Id`
- `Enclave.getE3(e3Id).committeePublicKey` (hex array) — query via cast against `127.0.0.1:8545` and the `enclave` address in `enclave.config.yaml`.
- Cast one real ballot through the SDK test path (`pnpm test:sdk` runs `qesVote.test.ts`; or a one-off node script using `generateCircuitInputsImpl`+`generateProof`+`encodeSolidityProof` then `publishInput`). Save the `encryptedVote` bytes.

- [ ] **Step 3: Warm restart the ciphernodes WITHOUT nuking state**

```bash
# Kill ONLY the enclave node processes, leave anvil running:
pkill -9 -f "enclave nodes" || true
pkill -9 -f "enclave program" || true
# Do NOT remove ./.enclave/data. Restart nodes + program against the SAME data dir:
enclave nodes up -v &
enclave program start --dev true &
# wait until nodes re-sync to chain
```

- [ ] **Step 4: Verify the committee key is unchanged + the pre-restart ballot still decrypts**

In the findings doc, record PASS/FAIL for each:
- `getE3(e3Id).committeePublicKey` AFTER restart **byte-identical** to before? (PASS = persistence-via-`.enclave/data` works.)
- The pre-restart `encryptedVote` decrypts to the original vote after the committee finalizes the round (run `close-round`/decrypt path). PASS/FAIL.

- [ ] **Step 5: If FAIL — test the full-machine-restart + seed-derive fallbacks**

If Step 4 FAILED with only nodes restarted, the shares are not in `.enclave/data`. Investigate, in order, and record findings:
1. Are shares elsewhere on disk (search the enclave node home / config dir)? If so, persistence path = persist that dir too.
2. Does the enclave node CLI support a deterministic/seeded DKG (grep enclave node flags for `seed`/`deterministic`)? If yes, seed-derive (mirror `V3_THRESHOLD_SEED`).
3. If neither: **scale-to-zero is NOT viable for the committee.** Record the fallback decision: `min_machines_running = 1` (always-on) and continue the rest of the plan with that single change.

- [ ] **Step 6: Commit the findings + decision**

```bash
git add docs/runbooks/2026-06-02-persistence-spike-findings.md
git commit -m "spike: CRISP committee-key persistence across warm restart (decision: <persist-data|seed-derive|always-on>)"
```

**Decision recorded here determines Task 1.4/1.5 config.** The rest of Phase 1 assumes the chosen persistence mechanism.

---

### Task 1.1: Trim committee 5 → 3 (fork)

**Files:**
- Modify: `vendor/crisp-qes-enclave/examples/CRISP/enclave.config.yaml` (nodes section — remove cn4, cn5)
- Modify: `vendor/crisp-qes-enclave/examples/CRISP/scripts/dev_cipher.sh` (remove cn4/cn5 wallet-set + add lines)

- [ ] **Step 1: Edit `enclave.config.yaml` — keep only cn1, cn2, cn3 under `nodes:`**

Remove the `cn4:` and `cn5:` blocks. Leave cn1/cn2/cn3 (addresses `0x70997970...`, `0x3C44CdDd...`, `0x90F79bf6...`) unchanged.

- [ ] **Step 2: Edit `dev_cipher.sh` — drop cn4/cn5**

Remove the `PRIVATE_KEY_CN4`/`PRIVATE_KEY_CN5` vars, their `enclave wallet set` lines, the `CN4`/`CN5` yq reads, and the two `pnpm ciphernode:add` calls for them.

- [ ] **Step 3: Smoke-test cold up with 3 nodes**

```bash
cd vendor/crisp-qes-enclave/examples/CRISP && pnpm dev:up &
# Expect: ./.enclave/ready written, 3 ciphernodes added, DKG completes, committeePublicKey published for a requested E3.
```
Expected: round requests reach `CommitteeFinalized`/`KeyPublished` with a 3-node committee.

- [ ] **Step 4: Commit (fork — explicit add)**

```bash
git add vendor/crisp-qes-enclave/examples/CRISP/enclave.config.yaml \
        vendor/crisp-qes-enclave/examples/CRISP/scripts/dev_cipher.sh
git commit -m "crisp(fork): trim committee 5->3 for single-operator demo"
```

---

### Task 1.2: Warm-boot supervisor (cold-init vs warm-boot paths)

**Files:**
- Create: `infra/fhe-operator/supervisor.sh`

The supervisor is the container entrypoint. It distinguishes **cold init** (first boot, empty `/data`) from **warm boot** (`/data/anvil-state.json` exists).

- [ ] **Step 1: Write the supervisor**

```bash
#!/usr/bin/env bash
# infra/fhe-operator/supervisor.sh — single-machine CRISP backend orchestrator.
# Cold init: deploy Enclave+CRISPQES once, run DKG, persist state.
# Warm boot: load anvil state + .enclave/data, skip deploy/DKG-nuke, re-sync.
set -euo pipefail

DATA=/data
ANVIL_STATE="$DATA/anvil-state.json"
ENCLAVE_DATA="$DATA/enclave-data"          # persisted .enclave/data (key shares)
CRISP=/app/examples/CRISP
READY="$CRISP/.enclave/ready"

mkdir -p "$DATA"
ln -sfn "$ENCLAVE_DATA" "$CRISP/.enclave/data"   # node shares live on the volume

start_anvil() {
  # --state loads on boot if present and dumps periodically + on SIGTERM.
  anvil --host 0.0.0.0 --chain-id 31337 --block-time 1 \
        --mnemonic 'test test test test test test test test test test test junk' \
        --state "$ANVIL_STATE" --silent &
  ANVIL_PID=$!
  npx wait-on tcp:8545
}

cold_init() {
  echo "[supervisor] COLD INIT"
  start_anvil
  ( cd "$CRISP" && ./scripts/crisp_qes_deploy.sh )       # deploy ONCE
  ( cd "$CRISP" && ./scripts/dev_cipher.sh "$READY" ) &  # full DKG, writes shares to volume via symlink
  ( cd "$CRISP" && ./scripts/dev_program.sh ) &
  npx wait-on tcp:13151
  ( cd "$CRISP/server" && cargo run --release --bin server ) &
}

warm_boot() {
  echo "[supervisor] WARM BOOT"
  start_anvil
  # Re-set node wallets (deterministic keys; cheap, no DKG) but DO NOT nuke .enclave/data:
  enclave wallet set --name cn1 --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
  enclave wallet set --name cn2 --private-key 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
  enclave wallet set --name cn3 --private-key 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
  ( cd "$CRISP" && enclave nodes up -v ) &
  ( cd "$CRISP" && enclave program start --dev true ) &
  npx wait-on tcp:13151
  ( cd "$CRISP/server" && cargo run --release --bin server ) &
  echo 1 > "$READY"
}

if [ -f "$ANVIL_STATE" ]; then warm_boot; else cold_init; fi

# Readiness gate + keep PID 1 alive; forward SIGTERM so anvil dumps state.
node /app/infra/fhe-operator/healthz.mjs &
trap 'kill -TERM $ANVIL_PID 2>/dev/null || true; sleep 3; exit 0' TERM INT
wait
```

> If Task 1.0 chose **seed-derive**, replace the `enclave wallet set` block / DKG step with the seeded-DKG invocation found in the spike. If it chose **always-on**, the cold/warm split still applies but Fly keeps the machine up (Task 1.4).

- [ ] **Step 2: Commit**

```bash
git add infra/fhe-operator/supervisor.sh
git commit -m "infra(fhe): single-machine supervisor with cold-init/warm-boot paths"
```

---

### Task 1.3: Readiness gate `/healthz`

**Files:**
- Create: `infra/fhe-operator/healthz.mjs`

- [ ] **Step 1: Write the gate** — green ONLY when chain is up AND a committee key is reachable.

```js
// infra/fhe-operator/healthz.mjs — Fly health/wake gate for the CRISP backend.
import http from 'node:http'
import { JsonRpcProvider } from 'ethers'

const PORT = process.env.HEALTHZ_PORT || 8080
const RPC = 'http://127.0.0.1:8545'
const COORD = 'http://127.0.0.1:4000/healthz'  // coordination server self-check

async function ready() {
  try {
    const p = new JsonRpcProvider(RPC)
    await p.getBlockNumber()                    // anvil up
    const r = await fetch(COORD).catch(() => null)
    return !!r && r.ok                          // coordination server (and thus nodes) up
  } catch { return false }
}

http.createServer(async (_req, res) => {
  const ok = await ready()
  res.writeHead(ok ? 200 : 503, { 'content-type': 'application/json' })
  res.end(JSON.stringify({ ok }))
}).listen(PORT, () => console.log(`[healthz] :${PORT}`))
```

- [ ] **Step 2: Commit**

```bash
git add infra/fhe-operator/healthz.mjs
git commit -m "infra(fhe): /healthz readiness+wake gate (chain + coordination server)"
```

---

### Task 1.4: Container image

**Files:**
- Create: `infra/fhe-operator/Dockerfile`

- [ ] **Step 1: Write the Dockerfile** — base it on the fork's ciphernode build (`vendor/crisp-qes-enclave/crates/Dockerfile`) so the `enclave` CLI, Rust toolchain, Foundry (`anvil`), Node, and the CRISP example are all present.

```dockerfile
# infra/fhe-operator/Dockerfile — single-image CRISP backend (anvil + 3 nodes + program + coordination server).
# Build context = repo root.
FROM ghcr.io/foundry-rs/foundry:latest AS foundry
# --- base with rust + node + enclave CLI ---
FROM rust:1-bookworm AS base
RUN apt-get update && apt-get install -y curl git build-essential pkg-config libssl-dev \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs \
    && npm i -g pnpm@10.7.1 wait-on yq
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
COPY --from=foundry /usr/local/bin/cast  /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
WORKDIR /app
COPY vendor/crisp-qes-enclave /app/vendor-src
# Build the enclave CLI + ciphernode binaries from the fork:
RUN cd /app/vendor-src && cargo build --release -p enclave || true   # adjust to the real crate name
RUN cp /app/vendor-src/target/release/enclave /usr/local/bin/enclave
# CRISP example (circuits/sdk/server/contracts):
COPY vendor/crisp-qes-enclave/examples/CRISP /app/examples/CRISP
RUN cd /app/examples/CRISP && pnpm install --frozen-lockfile && pnpm dev:setup
COPY infra/fhe-operator /app/infra/fhe-operator
EXPOSE 4000 8545 8080
ENTRYPOINT ["bash", "/app/infra/fhe-operator/supervisor.sh"]
```

> Resolve the exact enclave crate name + build target during this task by reading `vendor/crisp-qes-enclave/crates/Dockerfile` and `Cargo.toml`; the `|| true` is a placeholder to be removed once the real build line is confirmed (do NOT ship with `|| true`).

- [ ] **Step 2: Build locally to validate**

```bash
cd /data/Develop/crisp-qes
docker build -f infra/fhe-operator/Dockerfile -t fhe-operator:dev .
```
Expected: image builds; `docker run --rm fhe-operator:dev which enclave anvil` prints both paths.

- [ ] **Step 3: Commit**

```bash
git add infra/fhe-operator/Dockerfile
git commit -m "infra(fhe): single-image backend (anvil+enclave+program+server)"
```

---

### Task 1.5: Fly app — volume + scale-to-zero

**Files:**
- Create: `infra/fhe-operator/fly.toml`

- [ ] **Step 1: Write fly.toml**

```toml
app = "crisp-qes-fhe"
primary_region = "fra"

[build]
  dockerfile = "Dockerfile"

[env]
  HEALTHZ_PORT = "8080"
  # Base Sepolia read endpoint for the round-open snapshot of EnrollmentRegistry root.
  BASE_SEPOLIA_RPC_URL = "https://base-sepolia-rpc.publicnode.com"
  BASE_SEPOLIA_ENROLLMENT_REGISTRY = "0x5F463C130DB79e70c3861879442857c45953505f"

[[mounts]]
  source = "fhe_data"
  destination = "/data"

[http_service]
  internal_port = 8080            # healthz gates wake; coordination server proxied separately
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0        # <-- if Task 1.0 = always-on, set to 1

  [[http_service.checks]]
    method = "GET"
    path = "/healthz"
    interval = "15s"
    timeout = "8s"
    grace_period = "120s"         # cold/warm boot can take tens of seconds

# Expose the coordination server (vote broadcast) on its own service:
[[services]]
  internal_port = 4000
  protocol = "tcp"
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0
  [[services.ports]]
    port = 443
    handlers = ["tls", "http"]

[[vm]]
  cpu_kind = "shared"
  cpus = 4
  memory_mb = 8192
```

- [ ] **Step 2: Create volume + deploy**

```bash
cd infra/fhe-operator
flyctl apps create crisp-qes-fhe || true
flyctl volumes create fhe_data --region fra --size 40 -a crisp-qes-fhe
flyctl deploy . --config fly.toml --dockerfile Dockerfile --build-context ../..
```

- [ ] **Step 3: Verify cold init → sleep → warm boot → cross-sleep decrypt**

```bash
flyctl logs -a crisp-qes-fhe         # observe COLD INIT, DKG, committeePublicKey
# open a round + cast a ballot (Task 2.3 / web), then let it idle until the machine stops:
flyctl machine list -a crisp-qes-fhe # state should become "stopped"
curl https://crisp-qes-fhe.fly.dev/healthz   # wakes machine; observe WARM BOOT in logs
# verify the round's committeePublicKey is unchanged and the pre-sleep ballot decrypts.
```
Expected: WARM BOOT path runs, committee key identical, prior ballot decrypts. (If FAIL and Task 1.0 said always-on, `min_machines_running=1` and this acceptance reduces to "stays up + decrypts".)

- [ ] **Step 4: Commit**

```bash
git add infra/fhe-operator/fly.toml
git commit -m "infra(fhe): Fly single-machine, /data volume, scale-to-zero + wake gate"
```

---

## Phase 2 — BallotRegistry + operator round tooling

### Task 2.1: `BallotRegistry.sol` + Foundry tests

**Files:**
- Create: `packages/contracts/src/BallotRegistry.sol`
- Test: `packages/contracts/test/BallotRegistry.t.sol`

- [ ] **Step 1: Write the failing test**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BallotRegistry} from "../src/BallotRegistry.sol";

contract BallotRegistryTest is Test {
    BallotRegistry reg;
    address operator = address(0xA11CE);
    address stranger = address(0xBEEF);

    function setUp() public {
        vm.prank(operator);
        reg = new BallotRegistry(operator);
    }

    function _labels() internal pure returns (string[] memory l) {
        l = new string[](3);
        l[0] = "Cats"; l[1] = "Dogs"; l[2] = "Both";
    }

    function test_createRound_storesMetadata() public {
        vm.prank(operator);
        reg.createRound(7, "Cats or dogs?", _labels(), bytes32(uint256(0x1b49)), uint64(block.timestamp + 1 days));
        BallotRegistry.Round memory r = reg.getRound(7);
        assertEq(r.question, "Cats or dogs?");
        assertEq(r.optionLabels.length, 3);
        assertEq(r.optionLabels[2], "Both");
        assertEq(r.enrollmentRoot, bytes32(uint256(0x1b49)));
        assertEq(r.numOptions, 3);
        assertTrue(r.exists);
    }

    function test_createRound_onlyOperator() public {
        vm.prank(stranger);
        vm.expectRevert(BallotRegistry.NotOperator.selector);
        reg.createRound(7, "q", _labels(), bytes32(0), uint64(block.timestamp + 1));
    }

    function test_createRound_rejectsDuplicateE3Id() public {
        vm.startPrank(operator);
        reg.createRound(7, "q", _labels(), bytes32(0), uint64(block.timestamp + 1));
        vm.expectRevert(BallotRegistry.RoundExists.selector);
        reg.createRound(7, "q2", _labels(), bytes32(0), uint64(block.timestamp + 1));
        vm.stopPrank();
    }

    function test_createRound_rejectsLessThanTwoOptions() public {
        string[] memory one = new string[](1); one[0] = "Only";
        vm.prank(operator);
        vm.expectRevert(BallotRegistry.TooFewOptions.selector);
        reg.createRound(7, "q", one, bytes32(0), uint64(block.timestamp + 1));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/contracts && forge test --match-contract BallotRegistryTest -vvv`
Expected: FAIL — `BallotRegistry` not found / does not compile.

- [ ] **Step 3: Implement `BallotRegistry.sol`**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BallotRegistry
/// @notice Operator-written round metadata for CRISP FHE multi-option voting.
///         Lives on the operator-controlled chain alongside CRISPQESProgram.
///         Holds the question + option labels + the Base Sepolia enrollment-root
///         snapshot the round is bound to, so the web can render ballots and
///         third parties can audit what was voted on.
contract BallotRegistry {
    struct Round {
        string question;
        string[] optionLabels;
        bytes32 enrollmentRoot; // snapshot of Base Sepolia EnrollmentRegistry.enrollmentRoot()
        uint64 deadline;        // unix seconds
        uint32 numOptions;
        bool exists;
    }

    address public immutable operator;
    mapping(uint256 => Round) private rounds; // e3Id => Round
    uint256[] public roundIds;

    error NotOperator();
    error RoundExists();
    error TooFewOptions();

    event RoundCreated(uint256 indexed e3Id, uint32 numOptions, bytes32 enrollmentRoot, uint64 deadline);

    constructor(address operator_) {
        operator = operator_;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    function createRound(
        uint256 e3Id,
        string calldata question,
        string[] calldata optionLabels,
        bytes32 enrollmentRoot,
        uint64 deadline
    ) external onlyOperator {
        if (rounds[e3Id].exists) revert RoundExists();
        if (optionLabels.length < 2) revert TooFewOptions();
        Round storage r = rounds[e3Id];
        r.question = question;
        for (uint256 i = 0; i < optionLabels.length; i++) r.optionLabels.push(optionLabels[i]);
        r.enrollmentRoot = enrollmentRoot;
        r.deadline = deadline;
        r.numOptions = uint32(optionLabels.length);
        r.exists = true;
        roundIds.push(e3Id);
        emit RoundCreated(e3Id, r.numOptions, enrollmentRoot, deadline);
    }

    function getRound(uint256 e3Id) external view returns (Round memory) {
        return rounds[e3Id];
    }

    function roundCount() external view returns (uint256) {
        return roundIds.length;
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/contracts && forge test --match-contract BallotRegistryTest -vvv`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/contracts/src/BallotRegistry.sol packages/contracts/test/BallotRegistry.t.sol
git commit -m "feat(contracts): BallotRegistry for FHE round metadata (operator-written)"
```

---

### Task 2.2: Deploy script for the operator chain

**Files:**
- Create: `packages/contracts/script/DeployBallotRegistry.s.sol`

- [ ] **Step 1: Write the script**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {BallotRegistry} from "../src/BallotRegistry.sol";

contract DeployBallotRegistry is Script {
    function run() external {
        // OPERATOR = the anvil deployer (0xf39F...2266) by default on the operator chain.
        address operator = vm.envAddress("BALLOT_OPERATOR");
        vm.startBroadcast();
        BallotRegistry reg = new BallotRegistry(operator);
        vm.stopBroadcast();
        // forge prints the address; record it for the web + open-round.mjs.
        // (No on-chain logging needed beyond the constructor event.)
        require(address(reg) != address(0), "deploy failed");
    }
}
```

- [ ] **Step 2: Deploy to the operator anvil (via the Fly machine's RPC or local)**

```bash
cd packages/contracts
BALLOT_OPERATOR=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
forge script script/DeployBallotRegistry.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```
Expected: prints the deployed `BallotRegistry` address. Record it as `BALLOT_REGISTRY` for Task 2.3 + Phase 3.

- [ ] **Step 3: Commit**

```bash
git add packages/contracts/script/DeployBallotRegistry.s.sol
git commit -m "feat(contracts): BallotRegistry deploy script (operator chain)"
```

---

### Task 2.3: Operator round-open CLI

**Files:**
- Create: `infra/fhe-operator/open-round.mjs`

- [ ] **Step 1: Write the round-open tool** — snapshot Base Sepolia root → `Enclave.requestE3` (numOptions) → `BallotRegistry.createRound`.

```js
// infra/fhe-operator/open-round.mjs
// Usage: node open-round.mjs --question "Cats or dogs?" --options "Cats,Dogs,Both" --hours 24
import { JsonRpcProvider, Wallet, Contract } from 'ethers'

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i >= 0 ? process.argv[i + 1] : d }

const OP_RPC = process.env.OPERATOR_RPC || 'http://127.0.0.1:8545'
const OP_KEY = process.env.OPERATOR_KEY || '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const BALLOT_REGISTRY = process.env.BALLOT_REGISTRY
const ENCLAVE = process.env.ENCLAVE_ADDRESS               // from enclave.config.yaml
const E3_PROGRAM = process.env.E3_PROGRAM_ADDRESS         // CRISPQESProgram
const BASE_RPC = process.env.BASE_SEPOLIA_RPC_URL
const BASE_ENROLL = process.env.BASE_SEPOLIA_ENROLLMENT_REGISTRY

const question = arg('question'); const options = arg('options').split(',')
const deadline = Math.floor(Date.now() / 1000) + Number(arg('hours', '24')) * 3600

// 1) snapshot Base Sepolia enrollment root
const baseProv = new JsonRpcProvider(BASE_RPC)
const enroll = new Contract(BASE_ENROLL, ['function enrollmentRoot() view returns (bytes32)'], baseProv)
const root = await enroll.enrollmentRoot()

// 2) request an E3 round on the operator chain (numOptions = options.length, enrollment_root = root)
const opProv = new JsonRpcProvider(OP_RPC)
const op = new Wallet(OP_KEY, opProv)
// NOTE: the exact requestE3 signature comes from @enclave-e3/contracts Enclave ABI +
// the CRISPQESProgram.validate params (numOptions, enrollment_root). Read the ABI and
// fill the encoded params; resolve e3Id from the requestE3 receipt event.
const enclave = new Contract(ENCLAVE, [/* Enclave.requestE3 ABI */], op)
const tx = await enclave.requestE3(/* ...params encoding numOptions + root... */)
const rcpt = await tx.wait()
const e3Id = /* parse from rcpt logs */ 0n

// 3) write BallotRegistry metadata
const reg = new Contract(BALLOT_REGISTRY, [
  'function createRound(uint256 e3Id,string question,string[] optionLabels,bytes32 enrollmentRoot,uint64 deadline)'
], op)
await (await reg.createRound(e3Id, question, options, root, deadline)).wait()
console.log(JSON.stringify({ e3Id: e3Id.toString(), root, options, deadline }))
```

> Resolve the `requestE3` ABI + `e3Id` event parse from the Enclave ABI during this task (read `node_modules/@enclave-e3/contracts` artifacts + how the reference CRISP client opens a round). Do not ship the placeholder comments — fill them.

- [ ] **Step 2: Open a real round end-to-end**

```bash
cd infra/fhe-operator
BALLOT_REGISTRY=<addr> ENCLAVE_ADDRESS=<addr> E3_PROGRAM_ADDRESS=<addr> \
BASE_SEPOLIA_RPC_URL=https://base-sepolia-rpc.publicnode.com \
BASE_SEPOLIA_ENROLLMENT_REGISTRY=0x5F463C130DB79e70c3861879442857c45953505f \
node open-round.mjs --question "Cats or dogs?" --options "Cats,Dogs,Both" --hours 24
```
Expected: prints `{e3Id, root, options, deadline}`; `BallotRegistry.getRound(e3Id)` returns the metadata; `Enclave.getE3(e3Id)` shows the round with a committee key after DKG.

- [ ] **Step 3: Commit**

```bash
git add infra/fhe-operator/open-round.mjs
git commit -m "infra(fhe): operator round-open CLI (snapshot Base root -> requestE3 -> BallotRegistry)"
```

---

## Phase 3 — Web: round list + ballot UI

### Task 3.1: `voteRound.ts` (read rounds) + tests

**Files:**
- Create: `packages/web/src/lib/voteRound.ts`
- Test: `packages/web/src/lib/__tests__/voteRound.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect, vi } from 'vitest'
import { parseRound } from '../voteRound'

describe('parseRound', () => {
  it('maps on-chain Round struct + numeric deadline to the UI shape', () => {
    const raw = {
      question: 'Cats or dogs?',
      optionLabels: ['Cats', 'Dogs', 'Both'],
      enrollmentRoot: '0x1b49',
      deadline: 1893456000n,
      numOptions: 3,
      exists: true,
    }
    const r = parseRound(42n, raw)
    expect(r.e3Id).toBe(42n)
    expect(r.options).toEqual(['Cats', 'Dogs', 'Both'])
    expect(r.numOptions).toBe(3)
    expect(r.enrollmentRoot).toBe('0x1b49')
    expect(r.isOpen(1893000000)).toBe(true)
    expect(r.isOpen(1893456001)).toBe(false)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/web && pnpm vitest run src/lib/__tests__/voteRound.test.ts`
Expected: FAIL — `parseRound` not exported.

- [ ] **Step 3: Implement `voteRound.ts`**

```ts
import { createPublicClient, http, type Address } from 'viem'

export type VoteRound = {
  e3Id: bigint
  question: string
  options: string[]
  numOptions: number
  enrollmentRoot: `0x${string}`
  deadline: bigint
  isOpen: (nowSec: number) => boolean
}

type RawRound = {
  question: string
  optionLabels: string[]
  enrollmentRoot: string
  deadline: bigint
  numOptions: number
  exists: boolean
}

export function parseRound(e3Id: bigint, raw: RawRound): VoteRound {
  return {
    e3Id,
    question: raw.question,
    options: raw.optionLabels,
    numOptions: raw.numOptions,
    enrollmentRoot: raw.enrollmentRoot as `0x${string}`,
    deadline: raw.deadline,
    isOpen: (nowSec: number) => raw.exists && BigInt(nowSec) < raw.deadline,
  }
}

const BALLOT_ABI = [
  { type: 'function', name: 'roundCount', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'roundIds', stateMutability: 'view', inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'getRound', stateMutability: 'view', inputs: [{ type: 'uint256' }],
    outputs: [{ type: 'tuple', components: [
      { name: 'question', type: 'string' }, { name: 'optionLabels', type: 'string[]' },
      { name: 'enrollmentRoot', type: 'bytes32' }, { name: 'deadline', type: 'uint64' },
      { name: 'numOptions', type: 'uint32' }, { name: 'exists', type: 'bool' },
    ] }] },
] as const

export async function fetchRounds(rpcUrl: string, ballotRegistry: Address): Promise<VoteRound[]> {
  const client = createPublicClient({ transport: http(rpcUrl) })
  const count = await client.readContract({ address: ballotRegistry, abi: BALLOT_ABI, functionName: 'roundCount' }) as bigint
  const out: VoteRound[] = []
  for (let i = 0n; i < count; i++) {
    const e3Id = await client.readContract({ address: ballotRegistry, abi: BALLOT_ABI, functionName: 'roundIds', args: [i] }) as bigint
    const raw = await client.readContract({ address: ballotRegistry, abi: BALLOT_ABI, functionName: 'getRound', args: [e3Id] }) as unknown as RawRound
    out.push(parseRound(e3Id, raw))
  }
  return out
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/web && pnpm vitest run src/lib/__tests__/voteRound.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/lib/voteRound.ts packages/web/src/lib/__tests__/voteRound.test.ts
git commit -m "feat(web): voteRound lib — read BallotRegistry rounds"
```

---

### Task 3.2: `BallotSelector` one-hot component + test

**Files:**
- Create: `packages/web/src/components/BallotSelector.tsx`
- Test: `packages/web/src/components/__tests__/BallotSelector.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { BallotSelector } from '../BallotSelector'

describe('BallotSelector', () => {
  it('selects exactly one option (one-hot) and reports its index', () => {
    const onSelect = vi.fn()
    render(<BallotSelector options={['Cats', 'Dogs', 'Both']} onSelect={onSelect} />)
    fireEvent.click(screen.getByText('Dogs'))
    expect(onSelect).toHaveBeenLastCalledWith(1)
    fireEvent.click(screen.getByText('Both'))
    expect(onSelect).toHaveBeenLastCalledWith(2)
    // only one selected at a time:
    expect(screen.getByText('Both').closest('[aria-pressed]')?.getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByText('Dogs').closest('[aria-pressed]')?.getAttribute('aria-pressed')).toBe('false')
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/web && pnpm vitest run src/components/__tests__/BallotSelector.test.tsx`
Expected: FAIL — component missing.

- [ ] **Step 3: Implement `BallotSelector.tsx`**

```tsx
import { useState } from 'react'

export function BallotSelector({ options, onSelect }: { options: string[]; onSelect: (index: number) => void }) {
  const [selected, setSelected] = useState<number | null>(null)
  return (
    <div role="radiogroup" className="ballot-selector">
      {options.map((label, i) => (
        <button
          key={i}
          type="button"
          role="radio"
          aria-pressed={selected === i}
          aria-checked={selected === i}
          className={selected === i ? 'ballot-option selected' : 'ballot-option'}
          onClick={() => { setSelected(i); onSelect(i) }}
        >
          {label}
        </button>
      ))}
    </div>
  )
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/web && pnpm vitest run src/components/__tests__/BallotSelector.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/components/BallotSelector.tsx packages/web/src/components/__tests__/BallotSelector.test.tsx
git commit -m "feat(web): one-hot BallotSelector component"
```

---

### Task 3.3: Round-list page wiring

**Files:**
- Modify: `packages/web/src/pages/*` (add a Vote rounds list; follow the existing petition-list page pattern)
- Modify: `packages/web/fly.toml` (add `VITE_OPERATOR_RPC`, `VITE_BALLOT_REGISTRY`, `VITE_COORD_URL`, `VITE_E3_PROGRAM`)

- [ ] **Step 1: Add env build-args to web fly.toml**

```toml
    VITE_OPERATOR_RPC = "https://crisp-qes-fhe.fly.dev"   # operator-chain JSON-RPC proxy (or direct anvil URL)
    VITE_BALLOT_REGISTRY = "<BallotRegistry addr>"
    VITE_E3_PROGRAM = "<CRISPQESProgram addr>"
    VITE_COORD_URL = "https://crisp-qes-fhe.fly.dev"      # coordination server (/qes/broadcast)
```

- [ ] **Step 2: Add a rounds-list view** that calls `fetchRounds(VITE_OPERATOR_RPC, VITE_BALLOT_REGISTRY)` and renders each open round with a "Vote" CTA (mirror the existing petition list component's structure + i18n usage).

- [ ] **Step 3: Manual verify** — `pnpm -C packages/web dev`, open the rounds page, confirm the round created in Task 2.3 renders with its 3 options.

- [ ] **Step 4: Commit**

```bash
git add packages/web/src/pages packages/web/fly.toml
git commit -m "feat(web): FHE voting rounds list page + env wiring"
```

---

## Phase 4 — Web: in-browser encrypt + prove + submit

### Task 4.0: Add the enclave vote SDK + circuit artifacts to the web build

**Files:**
- Modify: `packages/web/package.json`, `packages/web/vite.config.ts`
- Create: `packages/web/public/crisp/` (circuit JSON + WASM, copied from the CRISP build output)

- [ ] **Step 1: Add the dep** — workspace-link the fork's `crisp-sdk` (and its `@crisp-e3/zk-inputs` WASM) so the web imports `generateCircuitInputsImpl`, `generateProof`, `encodeSolidityProof`, `getZeroVote`, `generateMerkleProof`, `hashLeaf`.

```bash
cd packages/web
pnpm add "@crisp-e3/sdk@file:../../vendor/crisp-qes-enclave/examples/CRISP/packages/crisp-sdk" \
         "@crisp-e3/zk-inputs@file:../../vendor/crisp-qes-enclave/examples/CRISP/packages/zk-inputs"
# (resolve the exact package names from each package.json "name" field during this task)
```

- [ ] **Step 2: Configure Vite for WASM + workers** (bb.js + zk-inputs are WASM): ensure `optimizeDeps.exclude` includes the WASM packages and `worker.format = 'es'`. Copy the `crisp_qes`/`fold` circuit artifacts into `public/crisp/`.

- [ ] **Step 3: Build smoke test** — `pnpm -C packages/web build` succeeds and bundles the WASM as assets (no "cannot find module" / WASM MIME errors).

- [ ] **Step 4: Commit**

```bash
git add packages/web/package.json packages/web/pnpm-lock.yaml packages/web/vite.config.ts packages/web/public/crisp
git commit -m "build(web): wire enclave crisp-sdk + zk-inputs WASM + circuit artifacts"
```

---

### Task 4.1: `vote.ts` — witness assembly + proof + encode

**Files:**
- Create: `packages/web/src/lib/vote.ts`
- Test: `packages/web/src/lib/__tests__/vote.test.ts`

- [ ] **Step 1: Write the failing test** (pure witness-assembly logic; SDK calls mocked)

```ts
import { describe, it, expect } from 'vitest'
import { oneHotVote } from '../vote'

describe('oneHotVote', () => {
  it('builds a one-hot vector of length numOptions', () => {
    expect(oneHotVote(2, 3)).toEqual([0, 0, 1])
    expect(oneHotVote(0, 3)).toEqual([1, 0, 0])
  })
  it('rejects out-of-range selection', () => {
    expect(() => oneHotVote(3, 3)).toThrow()
    expect(() => oneHotVote(-1, 3)).toThrow()
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/web && pnpm vitest run src/lib/__tests__/vote.test.ts`
Expected: FAIL — `oneHotVote` missing.

- [ ] **Step 3: Implement `vote.ts`** (one-hot helper + the proof builder mirroring `qesVote.test.ts`)

```ts
import {
  generateCircuitInputsImpl, generateProof, encodeSolidityProof,
} from '@crisp-e3/sdk'
import type { Hex } from 'viem'

/** Build a one-hot ballot vector: 1 at `index`, 0 elsewhere. */
export function oneHotVote(index: number, numOptions: number): number[] {
  if (index < 0 || index >= numOptions) throw new Error(`option ${index} out of range 0..${numOptions - 1}`)
  return Array.from({ length: numOptions }, (_, i) => (i === index ? 1 : 0))
}

export type VoteWitness = {
  optionIndex: number
  numOptions: number
  publicKey: Uint8Array            // committee BFV pk (from Enclave.getE3(e3Id).committeePublicKey)
  enrollmentSecret: bigint
  merklePath: bigint[]             // length 20
  merklePathIndices: number[]      // length 20
  enrollmentRoot: bigint
  nullifier: bigint
  e3Id: bigint
}

/** Encrypt + prove a real (non-mask) ballot. Returns the ABI-encoded payload for publishInput. */
export async function buildVotePayload(w: VoteWitness): Promise<{ encoded: Hex; nullifier: bigint }> {
  const vote = oneHotVote(w.optionIndex, w.numOptions)
  const { circuitInputs } = await generateCircuitInputsImpl({
    vote,
    publicKey: w.publicKey,
    enrollmentSecret: w.enrollmentSecret,
    merklePath: w.merklePath,
    merklePathIndices: w.merklePathIndices,
    enrollmentRoot: w.enrollmentRoot,
    nullifier: w.nullifier,
    petitionId: w.e3Id,            // contract forces pub[6] = e3Id
    isMaskVote: false,
  })
  const proof = await generateProof(circuitInputs)
  return { encoded: encodeSolidityProof(proof, false), nullifier: w.nullifier }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/web && pnpm vitest run src/lib/__tests__/vote.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/lib/vote.ts packages/web/src/lib/__tests__/vote.test.ts
git commit -m "feat(web): vote witness assembly + crisp_qes proof builder"
```

---

### Task 4.2: Proof Web Worker

**Files:**
- Create: `packages/web/src/workers/voteProof.worker.ts`

- [ ] **Step 1: Write the worker** — runs `buildVotePayload` off the main thread, posts progress + result.

```ts
/// <reference lib="webworker" />
import { buildVotePayload, type VoteWitness } from '../lib/vote'

self.onmessage = async (e: MessageEvent<VoteWitness>) => {
  try {
    ;(self as DedicatedWorkerGlobalScope).postMessage({ type: 'progress', stage: 'proving' })
    const result = await buildVotePayload(e.data)
    ;(self as DedicatedWorkerGlobalScope).postMessage({ type: 'done', ...result })
  } catch (err) {
    ;(self as DedicatedWorkerGlobalScope).postMessage({ type: 'error', message: (err as Error).message })
  }
}
```

- [ ] **Step 2: Manual verify** — a throwaway harness page posts a witness, the worker returns `{type:'done', encoded}` in 30–120s on desktop without freezing the UI.

- [ ] **Step 3: Commit**

```bash
git add packages/web/src/workers/voteProof.worker.ts
git commit -m "feat(web): off-main-thread vote proof worker"
```

---

### Task 4.3: `VoteModal` — flow + submit

**Files:**
- Create: `packages/web/src/components/VoteModal.tsx`
- Modify: round-list page (open the modal from the "Vote" CTA)

- [ ] **Step 1: Implement the modal** — selects an option (BallotSelector), loads the committee pk from `Enclave.getE3(e3Id)`, loads the enrolled secret + Merkle path (reuse the existing enrollment storage + `generateMerkleProof` against the round's `enrollmentRoot`), computes the nullifier, dispatches the worker, shows progress, then submits `encoded` to `POST {VITE_COORD_URL}/qes/broadcast` (falls back to a direct `CRISPQESProgram.publishInput` write via viem if the coordination server is unavailable).

- [ ] **Step 2: Manual E2E** — as a real enrolled user, cast a ballot: worker proves, `/qes/broadcast` submits, `publishInput` verifies on-chain (Honk), the ballot lands in the vote tree (`InputPublished` event). Confirm a second vote with the same nullifier is rejected.

- [ ] **Step 3: Commit**

```bash
git add packages/web/src/components/VoteModal.tsx packages/web/src/pages
git commit -m "feat(web): VoteModal — select, prove (worker), submit to CRISPQESProgram"
```

---

## Phase 5 — Web: results / tally

### Task 5.1: `voteTally.ts` + test

**Files:**
- Create: `packages/web/src/lib/voteTally.ts`
- Test: `packages/web/src/lib/__tests__/voteTally.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest'
import { toResults } from '../voteTally'

describe('toResults', () => {
  it('zips option labels with decoded counts', () => {
    expect(toResults(['Cats', 'Dogs', 'Both'], [4n, 7n, 1n])).toEqual([
      { label: 'Cats', count: 4n }, { label: 'Dogs', count: 7n }, { label: 'Both', count: 1n },
    ])
  })
  it('throws on length mismatch', () => {
    expect(() => toResults(['A'], [1n, 2n])).toThrow()
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/web && pnpm vitest run src/lib/__tests__/voteTally.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `voteTally.ts`**

```ts
export type OptionResult = { label: string; count: bigint }

export function toResults(labels: string[], counts: bigint[]): OptionResult[] {
  if (labels.length !== counts.length) throw new Error('labels/counts length mismatch')
  return labels.map((label, i) => ({ label, count: counts[i] }))
}

/** Read the decoded tally for a finished round from CRISPQESProgram.decodeTally(e3Id). */
export async function fetchTally(
  readContract: (args: { functionName: string; args: unknown[] }) => Promise<unknown>,
  e3Id: bigint,
): Promise<bigint[]> {
  const raw = await readContract({ functionName: 'decodeTally', args: [e3Id] })
  return (raw as bigint[]).map((x) => BigInt(x))
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/web && pnpm vitest run src/lib/__tests__/voteTally.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/web/src/lib/voteTally.ts packages/web/src/lib/__tests__/voteTally.test.ts
git commit -m "feat(web): voteTally decode helpers"
```

---

### Task 5.2: `RoundResults` view + close-round tool

**Files:**
- Create: `packages/web/src/components/RoundResults.tsx`
- Create: `infra/fhe-operator/close-round.mjs`

- [ ] **Step 1: Write `close-round.mjs`** — after the deadline, drive the committee decrypt + on-chain tally publish for an `e3Id` (mirror the reference close/decrypt path the coordination server exposes; resolve exact calls from `server/src/server/routes/qes.rs` + the enclave decrypt flow during this task).

```js
// infra/fhe-operator/close-round.mjs — Usage: node close-round.mjs --e3 <id>
// 1) ensure block.timestamp > deadline; 2) trigger the FHE aggregation + committee
//    threshold-decrypt; 3) publish the plaintext tally so decodeTally(e3Id) returns counts.
// Fill the exact coordination-server endpoints / contract calls from qes.rs.
```

- [ ] **Step 2: Implement `RoundResults.tsx`** — calls `fetchTally` + `toResults`, renders per-option counts as a simple bar list; shows "Tally pending" until the round is decrypted.

- [ ] **Step 3: Manual E2E** — close the Task-2.3 round, run `close-round.mjs`, confirm `RoundResults` renders the per-option counts matching the ballots cast.

- [ ] **Step 4: Commit**

```bash
git add packages/web/src/components/RoundResults.tsx infra/fhe-operator/close-round.mjs
git commit -m "feat(web+infra): round results view + operator close-round/decrypt tool"
```

---

## Phase 6 — Disclosure, runbook, full dry run

### Task 6.1: In-app trust-caveat disclosure

**Files:**
- Modify: `VoteModal.tsx` + `RoundResults.tsx` (add a persistent disclosure banner)
- Add i18n strings (en + uk) following the existing i18next setup.

- [ ] **Step 1: Add the banner** — text (en): *"Demo voting. Ballots are encrypted, but the tally is run by a single operator (3 co-hosted nodes) and is not independently verifiable. Do not cast sensitive votes."* Add the uk translation alongside.

- [ ] **Step 2: Manual verify** — banner shows in the vote flow + results, both locales.

- [ ] **Step 3: Commit**

```bash
git add packages/web/src/components/VoteModal.tsx packages/web/src/components/RoundResults.tsx packages/web/src/i18n
git commit -m "feat(web): trust-caveat disclosure on FHE voting (en+uk)"
```

---

### Task 6.2: Operator runbook

**Files:**
- Create: `docs/runbooks/2026-06-02-fhe-operator-runbook.md`

- [ ] **Step 1: Write the runbook** — cover: deploy (`flyctl deploy` + volume), cold-init vs warm-boot behavior, opening a round (`open-round.mjs`), closing/decrypting (`close-round.mjs`), the persistence mechanism chosen in Task 1.0, the scale-to-zero wake latency, recovery if `/data` is lost (all rounds void), and the explicit trust caveats from the spec. Record the deployed addresses (BallotRegistry, Enclave, CRISPQESProgram, chainId).

- [ ] **Step 2: Commit**

```bash
git add docs/runbooks/2026-06-02-fhe-operator-runbook.md
git commit -m "docs: FHE operator runbook"
```

---

### Task 6.3: Full E2E dry run

- [ ] **Step 1: Cold deploy** the Fly machine; confirm COLD INIT logs + committee key published.
- [ ] **Step 2: Open a round** (`open-round.mjs`, 3 options).
- [ ] **Step 3: Let the machine scale to zero**; confirm `stopped`.
- [ ] **Step 4: As a real enrolled user**, open the web rounds page (wakes the machine — observe WARM BOOT + "warming up" UI), cast a ballot; confirm on-chain `publishInput` verify + `InputPublished`.
- [ ] **Step 5: Cast a second distinct ballot** from a different enrolled identity; confirm both land; confirm a double-vote (same nullifier) is rejected.
- [ ] **Step 6: Close + decrypt** (`close-round.mjs`); confirm `RoundResults` shows correct per-option counts.
- [ ] **Step 7: Verify cross-sleep integrity** — confirm a ballot cast before a sleep still decrypted correctly after a wake (the Task 1.0 guarantee, end-to-end).
- [ ] **Step 8: Bump the vendor submodule pointer** for all fork commits and record final addresses in the runbook + `reference_live_demo_state` memory.

```bash
git add vendor/crisp-qes-enclave
git commit -m "crisp: bump fork pointer to committee-trim + FHE voting backend"
```

---

## Self-review notes

- **Spec coverage:** single-operator + 3-node committee (Tasks 1.0–1.5, 6.1), operator-controlled chain w/ scale-to-zero + wake (1.2–1.5), persistence gate (1.0), BallotRegistry (2.1–2.3), eligibility via Base Sepolia root snapshot (2.3, 4.1), in-browser BFV+proof in a worker desktop-only (4.0–4.3), tally/results (5.1–5.2), trust disclosure + runbook (6.1–6.2), full E2E incl. cross-sleep decrypt (6.3). All spec sections map to tasks.
- **Known fill-ins flagged for the implementer (NOT silent placeholders):** the exact `Enclave.requestE3` ABI + `e3Id` event parse (Task 2.3), the close/decrypt endpoints in `server/src/server/routes/qes.rs` (Task 5.2), the enclave crate build line + share-persistence mechanism (Tasks 1.0/1.4), and the exact `@crisp-e3/*` package names (Task 4.0). Each is called out in-task with the precise file to read to resolve it, because these live in the unbuilt fork and must be read at implementation time rather than guessed.
- **Type consistency:** `VoteRound`, `VoteWitness`, `ProofData`, `oneHotVote`, `parseRound`, `toResults`, `fetchTally` names used consistently across tasks; `petitionId === e3Id` invariant honored everywhere; nullifier read from `publicInputs[2]` per the SDK.
