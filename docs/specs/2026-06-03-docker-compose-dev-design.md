# docker-compose-dev — fully-local CRISP-QES stack (design)

**Date:** 2026-06-03 · **Branch:** `feat/crisp-fhe-tally` · **Status:** approved, → plan

## Goal

One `docker compose up` that stands up the **entire** CRISP-QES system on localhost —
enrollment + FHE voting + web — so a developer can **enroll with a real Diia QES**
and **cast an in-browser vote**, fully offline. No Fly, no prod services.

Why local is the clean path: every container is built from source, so it already
includes the recent fixes (coordinator CORS, OPRF historical-root `?root`); a real
QES works against the **default** enroll gate (pins the real Diia CAs); and only
the blinded `M` + ZK proof ever leave the browser (operator-blind), all on localhost.

## Architecture — 5 services, one local chain (anvil, chainId 31337)

| Service | Build context | Role | Host ports |
| --- | --- | --- | --- |
| **fhe** | `vendor/crisp-qes-enclave/examples/CRISP/fly-operator/Dockerfile` | supervisor: anvil + Enclave + CRISPQES{Program,Verifier} + 3 ciphernodes/DKG + coordination-server + program-server | `8545` (rpc), `4000` (coordinator) |
| **init** | `foundry` image (no build) | one-shot: wait for anvil → deploy EnrollmentRegistry + BallotRegistry from a fixed deployer key (deterministic addrs) | — |
| **oprf** | `packages/oprf/v3-grumpkin/Dockerfile` | enrollment OPRF threshold service; **default real-Diia gate**; `RPC_URL=http://fhe:8545`, `ENROLLMENT_REGISTRY=<det>`, dev `V3_THRESHOLD_SEED`/`V3_ATTESTER_KEY` | `8788` |
| **relayer** | `packages/relayer/Dockerfile` | submits attester `updateRoot` for enrollment (funded anvil key) | `8787` |
| **web** | `packages/web/Dockerfile` (Caddy) | the app + 128 MiB CRS; `VITE_*` baked to `localhost:<mapped>` | `8080` → 80 |

The OPRF, relayer, and the FHE round all target the **same** anvil; enrollment leaves
land in the EnrollmentRegistry on chainId 31337, and the FHE round pins a snapshot of
that root.

## Networking + addressing

- **Inter-service** (compose network): services reach each other by name —
  `oprf`/`relayer`/`init` → `http://fhe:8545`.
- **Browser** (runs on the host): the web's `VITE_*` URLs must be **host-reachable**,
  i.e. `http://localhost:8545|4000|8788|8787`, not compose-internal names. anvil +
  the coordinator already serve `0.0.0.0` and (post-fix) send permissive CORS.
- **Deterministic addresses** (so they can be baked into the web build args, which
  Vite resolves at build time):
  - `CRISPQESProgram` — already deterministic on the FHE anvil: `0x7969c5eD335650692Bc04293B07F5BF2e7A673C0`.
  - `EnrollmentRegistry`, `BallotRegistry` — `init` deploys them from a **dedicated
    deployer key as its first two txs** (nonce 0, 1) → `CREATE` addresses are
    deterministic and precomputable (`cast compute-address`). These constants are
    baked into the web build + passed to `oprf`/`relayer` env.

## Enroll → open-round → vote flow

1. `docker compose up` — stack comes up; `init` deploys the registries; `oprf` syncs.
2. Open `http://localhost:8080` → **enroll with your QES** (real passkey + Diia cert).
   Web → `oprf` `/v3/blind-eval` (real-Diia gate) → `/v3/register` → `relayer`
   `updateRoot` → leaf in EnrollmentRegistry; vault wrapped via WebAuthn PRF.
3. **Open a round** (operator action, after enrollment so the pinned root contains
   you): `docker compose run --rm open-round "Question?" "A,B,C"` — snapshots the
   current EnrollmentRegistry root, `requestE3` → committee DKG, `setEnrollmentRoot`,
   `BallotRegistry.createRound`.
4. **Vote** in-browser: `getVoteEnrollment` (unlock vault + `?root` historical path
   against the round's pinned root) → prove (v3 worker, ~90s) → `/qes/broadcast` →
   on-chain slot on the local anvil.

A round can't be auto-opened at boot (it must pin a root that already contains the
voter), so step 3 is an explicit operator command — this is the accepted UX.

## Components to create

- `docker-compose.dev.yml` (repo root) — the 5 services + an `open-round` run-target,
  a named volume for the FHE anvil state, healthchecks + `depends_on` ordering.
- `scripts/compose/init.sh` — wait-for-anvil + forge-deploy the two registries from
  the fixed key (idempotent: skip if code already present at the deterministic addr).
- `scripts/compose/open-round.sh` — thin wrapper over the existing
  `fly-operator/open-round.sh` pointed at the compose `fhe` service.
- `.env.dev` (committed, **dev-only non-secret** values: dev seeds, deployer key =
  anvil[0], deterministic addresses) consumed by compose. No real secrets.
- `docs/runbooks/docker-compose-dev.md` — the 4-step flow above + troubleshooting.

## Reused as-is (no new Dockerfiles)

All four service Dockerfiles already exist and are used in prod deploys. Compose only
adds orchestration + env wiring + the init/open-round steps.

## Risks / must-verify during build

- **COOP/COEP**: the web `Caddyfile` must send `Cross-Origin-Opener-Policy:
  same-origin` + `Cross-Origin-Embedder-Policy: require-corp` (bb.js threaded WASM /
  SharedArrayBuffer for in-browser proving). Verify/add.
- **FHE image build is heavy** (~minutes, full enclave multi-stage) — one-off; cache
  layers. Acceptable for a dev compose.
- **Deterministic-address assumption**: holds only if `init` deploys the registries
  from a key whose nonce starts at 0 in this compose (dedicated key, not anvil[0]
  which the FHE supervisor also uses). Use a dedicated funded dev key.
- **DKG needs the fhe service always-on** (no Fly autostop here — fine in compose).
- **Real-cert eligibility**: the user's Diia cert must chain to a pinned Diia CA; if
  not, enroll fails closed (documented).
- **Secrets**: only dev/non-secret values committed (`.env.dev`); never real keys/PII.

## Done

`docker compose -f docker-compose.dev.yml up` brings the stack healthy; a developer
can enroll with a real QES at `localhost:8080`, run the `open-round` command, and
cast an in-browser vote that lands on the local anvil — fully offline.
