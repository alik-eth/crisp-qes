# Runbook — fully-local CRISP-QES (`docker-compose-dev`)

Enroll with a **real Diia QES** and cast an **in-browser vote**, entirely on
localhost — no Fly, no prod. Spec: `docs/specs/2026-06-03-docker-compose-dev-design.md`.

## Prereqsuites
- Docker / Podman + compose, ~8 GB free for the FHE image, `foundry` (`cast`) on
  the host (for `open-round.sh`).

## 1. Bring it up
```bash
# one-time/host prereq: build the v3 vote worker bundle (needs the vendored fork's
# v3 toolchain, which isn't inside the slim web image — it's COPY'd in pre-built).
pnpm -C packages/web build:voteworker

docker compose --env-file .env.dev -f docker-compose.dev.yml up --build
```
First run builds the FHE image (~minutes) + downloads the 128 MiB CRS into the web
image. Services + host ports:

| service | port | what |
| --- | --- | --- |
| fhe | 8545 (rpc), 4000 (coordinator) | anvil + Enclave + CRISPQES + DKG + servers |
| oprf | 8788 | enrollment OPRF (real-Diia gate, `?root` path) |
| relayer | 8789 | submits enrollment `updateRoot` |
| web | **8080** | the app + CRS |

`init` (one-shot) deploys EnrollmentRegistry + BallotRegistry at the deterministic
addrs in `.env.dev`, then exits.

## 2. Enroll with your QES
Open **http://localhost:8080**, go through enrollment with your passkey + Diia
cert. Operator-blind: only the blinded `M` + ZK proof leave the browser; your
RNOKPP / DOB / `.p7s` never do. (Your cert must chain to a pinned Diia CA — the
same set production uses; otherwise enroll fails closed.)

## 3. Open a round (operator, AFTER enrolling)
A round pins a snapshot of the enrollment root, so open it once your leaf is in:
```bash
bash scripts/compose/open-round.sh "Cats or dogs?" "Cats,Dogs,Both"
```
This pins the local EnrollmentRegistry root, `requestE3` (committee DKG, ~60–80s),
`setEnrollmentRoot`, and `createRound`.

## 4. Vote
Back at http://localhost:8080 → the round appears → pick an option → **Vote
(in-browser)**. It unlocks your vault, fetches the historical path against the
round's pinned root (`?root`), proves the fold in the v3 worker (~90s), and
broadcasts → a slot lands on the local anvil.

## Teardown
```bash
docker compose --env-file .env.dev -f docker-compose.dev.yml down -v   # -v also drops the anvil volume
```

## Podman / Fedora notes (validated on podman 5.8 rootless, SELinux enforcing)
- Pre-pull base images so podman's short-name resolution doesn't block a non-TTY
  build: `podman pull docker.io/library/caddy:2-alpine docker.io/library/ubuntu:24.04`.
- Bind-mounts use `:z` (SELinux relabel); `init` copies the read-only contracts to
  a writable `/tmp` before `forge` (avoids rootless write-perm issues on the mount).
- `oprf`/`relayer` have `restart: unless-stopped` because podman-compose doesn't
  honour `init`'s `service_completed_successfully`; they self-heal once the
  registry is deployed (may log one `enrollmentRoot returned 0x` crash first).

## Notes / troubleshooting
- **Deterministic addresses** assume a fresh chain. After `down -v`, addresses are
  stable; if you reset only the chain (not the volume), re-run `init`.
- **DKG** needs the `fhe` service running continuously (no autostop here).
- **Synthetic-cert variant**: set `ENROLL_GATE_CIRCUIT` on the `oprf` service to a
  synth-CA build (`build-synthca-circuit.mjs`) to test without a real Diia cert.
- **Dev keys** in `.env.dev` are localhost-only test keys (anvil[0] + a throwaway
  deployer); the OPRF dev threshold seed/attester key use the service's built-in
  dev fallbacks and are never committed.
