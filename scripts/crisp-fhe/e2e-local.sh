#!/usr/bin/env bash
#
# Phase 3e Task 5 — scripted local END-TO-END for CRISP-QES.
#
# One command that:
#   1. bootstraps the vendored fork (scripts/crisp-fhe/bootstrap.sh — pinned bb,
#      regenerated circuit targets, builds the SDK/contracts/server),
#   2. brings up the local self-run stack WITH the QES contracts in the background
#      (examples/CRISP/scripts/dev_up_qes.sh = anvil + crisp_qes_deploy.sh +
#       dev_services.sh: ciphernodes/DKG + program-server + coordination-server),
#   3. waits (time-boxed) for the stack to be ready (anvil RPC, QES deploy, the
#      coordination server, and the DKG committee key),
#   4. runs the round driver examples/CRISP/tests/qes-e2e.mjs (real vote → mask →
#      double-vote → tally),
#   5. tears the stack down.
#
# Known frictions (Phase 1): committee DKG ~60s, each QES fold proof ~130s, and a
# constrained harness may GC long-lived background processes. This script keeps
# the stack in ONE background process group and time-boxes every wait so a partial
# run still reports exactly how far it composed. Logs go to a timestamped dir.
#
# Usage:
#   bash scripts/crisp-fhe/e2e-local.sh                 # full run incl. tally
#   SKIP_BOOTSTRAP=1 bash scripts/crisp-fhe/e2e-local.sh  # reuse a built tree
#   SKIP_TALLY=1   bash scripts/crisp-fhe/e2e-local.sh     # stop after double-vote
#   KEEP_STACK=1   bash scripts/crisp-fhe/e2e-local.sh     # don't teardown at end

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
FORK="$ROOT/vendor/crisp-qes-enclave"
CRISP="$FORK/examples/CRISP"

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
COORDINATOR_URL="${COORDINATOR_URL:-http://127.0.0.1:4000}"
STACK_READY_TIMEOUT_S="${STACK_READY_TIMEOUT_S:-300}"
COMMITTEE_KEY_TIMEOUT_S="${COMMITTEE_KEY_TIMEOUT_S:-180}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="$ROOT/scripts/crisp-fhe/.e2e-logs/$TS"
mkdir -p "$LOG_DIR"
STACK_LOG="$LOG_DIR/stack.log"
DRIVER_LOG="$LOG_DIR/driver.log"

STACK_PGID=""

log()  { echo "[e2e $(date -u +%H:%M:%S)] $*"; }
die()  { echo "[e2e FATAL] $*" >&2; exit 1; }

teardown() {
  if [[ "${KEEP_STACK:-}" == "1" ]]; then
    log "KEEP_STACK=1 — leaving the stack running (logs: $STACK_LOG)"
    return
  fi
  log "Tearing down the local stack…"
  # Kill the whole process group started for the stack, plus the named processes
  # the dev scripts spawn (anvil + enclave nodes/program + the cargo server).
  if [[ -n "$STACK_PGID" ]]; then kill -TERM "-$STACK_PGID" 2>/dev/null || true; fi
  pkill -9 -f "enclave nodes"   2>/dev/null || true
  pkill -9 -f "enclave program" 2>/dev/null || true
  pkill -9 -f "enclave start"   2>/dev/null || true
  pkill -9 -f "target/debug/server" 2>/dev/null || true
  pkill -9 -f "bin server"      2>/dev/null || true
  pkill -9 -f "anvil"           2>/dev/null || true
  # identity layer: the OPRF threshold service (WITH_IDENTITY=1)
  if [[ -n "${OPRF_PID:-}" ]]; then kill "$OPRF_PID" 2>/dev/null || true; fi
  pkill -9 -f "service/server.mjs" 2>/dev/null || true
  sleep 1
  log "Teardown complete."
}
trap teardown EXIT INT TERM

# ── 1. bootstrap ────────────────────────────────────────────────────────────
if [[ "${SKIP_BOOTSTRAP:-}" == "1" ]]; then
  log "SKIP_BOOTSTRAP=1 — skipping bootstrap.sh"
else
  log "Bootstrapping the fork (pinned bb, circuit targets, builds)… → $LOG_DIR/bootstrap.log"
  bash "$SCRIPT_DIR/bootstrap.sh" >"$LOG_DIR/bootstrap.log" 2>&1 \
    || die "bootstrap.sh failed (see $LOG_DIR/bootstrap.log)"
  log "Bootstrap OK."
fi

# FORCE-rebuild the cli + coordination-server binaries from the CURRENT source.
# Critical: dev_server.sh runs `cargo run --bin server`, but after a git checkout /
# submodule bump the source mtime can be OLDER than a previously-built binary, so
# cargo serves a STALE binary (this bit us: a pre-FIX-A server with the old 6-elem
# publishInput tuple rejected the new 5-elem encoding → "Invalid QES publishInput
# tuple"). Removing the binaries forces cargo to rebuild from the committed source.
log "Force-rebuilding cli + server binaries from current source (cargo build)…"
rm -f "$CRISP/target/debug/cli" "$CRISP/target/debug/server"
( cd "$CRISP/server" && cargo build --bin cli --bin server ) >"$LOG_DIR/server-build.log" 2>&1 \
  || die "cli/server build failed (see $LOG_DIR/server-build.log)"
[[ -x "$CRISP/target/debug/server" ]] || die "server binary not produced (see $LOG_DIR/server-build.log)"

# FORCE-rebuild the crisp-sdk dist/ from current source, same staleness trap as
# the server: the driver imports @crisp-e3/sdk from dist/index.js (not the TS
# source), so a dist built before a vote.ts change silently emits the OLD
# publishInput tuple (this caused "Invalid QES publishInput tuple" at broadcast —
# stale 6-elem dist vs fixed 5-elem server). --no-dts skips the broken .d.ts emit.
log "Force-rebuilding crisp-sdk dist from current source (tsup --no-dts)…"
( cd "$CRISP/packages/crisp-sdk" && pnpm exec tsup --no-dts ) >"$LOG_DIR/sdk-build.log" 2>&1 \
  || die "crisp-sdk dist build failed (see $LOG_DIR/sdk-build.log)"
grep -q "bytes, bytes32, uint256, bool" "$CRISP/packages/crisp-sdk/dist/index.js" \
  && die "crisp-sdk dist still has the STALE 6-element publishInput tuple (see $LOG_DIR/sdk-build.log)"
[[ -f "$CRISP/packages/crisp-sdk/dist/index.js" ]] || die "crisp-sdk dist/index.js not produced (see $LOG_DIR/sdk-build.log)"

# ── 2. bring up the QES stack (background, own process group) ─────────────────
log "Bringing up the QES stack (dev_up_qes.sh) in the background… → $STACK_LOG"
# setsid puts the stack in its own process group so teardown can kill the tree.
setsid bash -c "cd '$CRISP' && exec bash ./scripts/dev_up_qes.sh" >"$STACK_LOG" 2>&1 &
STACK_PID=$!
STACK_PGID="$(ps -o pgid= "$STACK_PID" 2>/dev/null | tr -d ' ')"
log "Stack launched (pid=$STACK_PID pgid=${STACK_PGID:-?})."

# ── 3. wait for readiness (time-boxed) ───────────────────────────────────────
wait_for() { # <desc> <timeout_s> <cmd...>
  local desc="$1" timeout="$2"; shift 2
  local deadline=$(( $(date +%s) + timeout ))
  log "Waiting for: $desc (≤ ${timeout}s)…"
  while (( $(date +%s) < deadline )); do
    if ! kill -0 "$STACK_PID" 2>/dev/null; then
      die "stack process exited early while waiting for: $desc (see $STACK_LOG)"
    fi
    if "$@" >/dev/null 2>&1; then log "  ready: $desc"; return 0; fi
    sleep 4
  done
  return 1
}

rpc_up()    { cast block-number --rpc-url "$RPC_URL"; }
deploy_up() {
  python3 - "$CRISP/packages/crisp-contracts/deployed_contracts.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    a=d.get("localhost",{}).get("CRISPQESProgram",{}).get("address")
    sys.exit(0 if a else 1)
except Exception:
    sys.exit(1)
PY
}
# Server-up probe: we only need the coordination server to ANSWER (it's listening),
# not to return 2xx — a fresh server has no rounds, so /state/lite{round_id:0} 500s
# and /qes/enrollment-root 404s. So: succeed if curl gets ANY HTTP status back.
coord_up()  {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$COORDINATOR_URL/qes/enrollment-root" -H 'Content-Type: application/json' -d '{"round_id":0}' 2>/dev/null)"
  [[ -n "$code" && "$code" != "000" ]]
}
# Ciphernodes-active gate: dev_cipher.sh writes ./.enclave/ready ONLY after all
# ciphernodes are registered + active (numActiveOperators >= committee size).
# requestE3 reverts InsufficientCiphernodes until then, so the round-create stage
# MUST wait for this — the coordinator answering on :4000 happens earlier.
ciphernodes_ready() { [[ -f "$CRISP/.enclave/ready" ]]; }

if command -v cast >/dev/null 2>&1; then
  wait_for "anvil RPC ($RPC_URL)" "$STACK_READY_TIMEOUT_S" rpc_up \
    || die "anvil RPC not up within ${STACK_READY_TIMEOUT_S}s (see $STACK_LOG)"
else
  log "WARN: 'cast' not on PATH — skipping explicit RPC readiness probe."
fi

wait_for "CRISPQESProgram deployed (deployed_contracts.json)" "$STACK_READY_TIMEOUT_S" deploy_up \
  || die "QES deploy did not complete within ${STACK_READY_TIMEOUT_S}s (see $STACK_LOG)"

# The coordination server starts after the program-server (wait-on tcp:13151) and
# the ciphernodes; it may legitimately take a while.
wait_for "coordination server ($COORDINATOR_URL)" "$STACK_READY_TIMEOUT_S" coord_up \
  || die "coordination server not reachable within ${STACK_READY_TIMEOUT_S}s (see $STACK_LOG)"

# Ciphernodes registered + active (else requestE3 reverts InsufficientCiphernodes).
wait_for "ciphernodes active (.enclave/ready)" "$STACK_READY_TIMEOUT_S" ciphernodes_ready \
  || die "ciphernodes not active within ${STACK_READY_TIMEOUT_S}s (see $STACK_LOG)"

log "Stack is up (ciphernodes active). Logs: $STACK_LOG"

# ── 3b. IDENTITY LAYER (WITH_IDENTITY=1): synthetic-cert threshold enrollment ─
# Deploy EnrollmentRegistry on the local anvil, boot the 3-node OPRF threshold
# service (synth-CA gate), enroll a SYNTHETIC cert (enroll proof -> threshold
# blind-eval -> oprf_nullifier proof -> /v3/register), publish the root on-chain
# via the attester-signed updateRoot, and hand the vote driver the REAL leaf.
ENROLLMENT_FILE=""
if [[ "${WITH_IDENTITY:-}" == "1" ]]; then
  OPRF_DIR="$ROOT/packages/oprf/v3-grumpkin"
  SYNTH_JSON="$OPRF_DIR/circuits/enroll_commit_v2_synthca/target/enroll_commit_v2_synthca.json"
  # Canonical depth-20 zero-tree root (service/merkle.mjs) + dev attester addr
  # (= address of the OPRF service's dev V3_ATTESTER_KEY fallback).
  GENESIS_ROOT="0x1b49e706af69da35927cdf2b28b02fb2647245ac0ccbc376d062031185d3cd84"
  DEV_ATTESTER="0xbcD7A4C1e3946c0BaaAC68E0D9A774D3d712f357"
  DEPLOY_KEY="${IDENTITY_DEPLOY_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}" # anvil[0]
  OPRF_PORT="${OPRF_PORT:-8788}"
  OPRF_URL="http://127.0.0.1:${OPRF_PORT}"
  ENROLLMENT_FILE="$LOG_DIR/enrollment-artifact.json"
  command -v forge >/dev/null 2>&1 || die "forge required for WITH_IDENTITY (EnrollmentRegistry deploy)"

  log "[identity] building synth-CA enroll circuit…"
  ( cd "$OPRF_DIR" && node build-synthca-circuit.mjs ) >"$LOG_DIR/identity-build.log" 2>&1 \
    || die "synth-CA circuit build failed (see $LOG_DIR/identity-build.log)"

  log "[identity] deploying EnrollmentRegistry on anvil…"
  ENROLL_REG="$(cd "$ROOT/packages/contracts" && \
    ENROLL_ATTESTER="$DEV_ATTESTER" ENROLL_GENESIS_ROOT="$GENESIS_ROOT" \
    forge script script/DeployEnrollmentRegistry.s.sol \
      --rpc-url "$RPC_URL" --private-key "$DEPLOY_KEY" --broadcast 2>"$LOG_DIR/identity-deploy.log" \
    | awk '/EnrollmentRegistry deployed:/{print $NF}' | tail -1)"
  [[ "$ENROLL_REG" =~ ^0x[0-9a-fA-F]{40}$ ]] || { cat "$LOG_DIR/identity-deploy.log" >&2; die "EnrollmentRegistry deploy failed (addr='$ENROLL_REG')"; }
  log "  EnrollmentRegistry=$ENROLL_REG"

  log "[identity] booting 3-node OPRF threshold service (:$OPRF_PORT)…"
  ( cd "$OPRF_DIR" && \
    ENROLL_GATE_CIRCUIT="$SYNTH_JSON" CHAIN_ID=31337 ENROLLMENT_REGISTRY="$ENROLL_REG" \
    PORT="$OPRF_PORT" HOST=127.0.0.1 \
    exec node service/server.mjs ) >"$LOG_DIR/oprf-service.log" 2>&1 &
  OPRF_PID=$!
  oprf_deadline=$(( $(date +%s) + 60 ))
  until curl -fsS "$OPRF_URL/healthz" >/dev/null 2>&1; do
    kill -0 "$OPRF_PID" 2>/dev/null || { cat "$LOG_DIR/oprf-service.log" >&2; die "OPRF service exited early"; }
    (( $(date +%s) < oprf_deadline )) || die "OPRF /healthz not ready in 60s (see $LOG_DIR/oprf-service.log)"
    sleep 2
  done
  log "  OPRF service ready."

  log "[identity] enrolling synthetic cert (enroll proof -> threshold -> /v3/register)…"
  ( cd "$OPRF_DIR" && OPRF_URL="$OPRF_URL" ENROLLMENT_OUT="$ENROLLMENT_FILE" \
    node enroll-synthetic.mjs ) >"$LOG_DIR/identity-enroll.log" 2>&1 \
    || { tail -25 "$LOG_DIR/identity-enroll.log" >&2; die "synthetic enrollment failed (see $LOG_DIR/identity-enroll.log)"; }

  log "[identity] publishing enrollment root on-chain (attester-signed updateRoot)…"
  read -r NEW_ROOT LEAF_S ATT_SIG < <(python3 - "$ENROLLMENT_FILE" <<'PY'
import json,sys
a=json.load(open(sys.argv[1]))
print(a["enrollmentRoot"], a["newCommitments"][0], a["attesterSig"])
PY
)
  cast send "$ENROLL_REG" "updateRoot(bytes32,bytes32[],bytes)" \
    "$NEW_ROOT" "[$LEAF_S]" "$ATT_SIG" \
    --private-key "$DEPLOY_KEY" --rpc-url "$RPC_URL" >"$LOG_DIR/identity-updateroot.log" 2>&1 \
    || { cat "$LOG_DIR/identity-updateroot.log" >&2; die "updateRoot failed (see $LOG_DIR/identity-updateroot.log)"; }
  ONCHAIN_ROOT="$(cast call "$ENROLL_REG" "enrollmentRoot()(bytes32)" --rpc-url "$RPC_URL" 2>/dev/null)"
  [[ "$ONCHAIN_ROOT" == "$NEW_ROOT" ]] || die "on-chain root ($ONCHAIN_ROOT) != enrolled root ($NEW_ROOT)"
  log "  on-chain enrollmentRoot == enrolled root; vote will use the REAL enrollment leaf."
fi

# ── 4. run the round driver ──────────────────────────────────────────────────
PROGRAM_ADDR="$(python3 - "$CRISP/packages/crisp-contracts/deployed_contracts.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(d["localhost"]["CRISPQESProgram"]["address"])
PY
)"
log "Running the round driver (qes-e2e.mjs) against e3 program $PROGRAM_ADDR…"
log "  driver log → $DRIVER_LOG (this includes ~2 fold proofs, ~130s each)"

set +e
( cd "$CRISP/packages/crisp-sdk" && \
  NODE_TLS_REJECT_UNAUTHORIZED=0 \
  RPC_URL="$RPC_URL" \
  COORDINATOR_URL="$COORDINATOR_URL" \
  E3_PROGRAM_ADDRESS="$PROGRAM_ADDR" \
  CLI_BIN="$CRISP/target/debug/cli" \
  COMMITTEE_KEY_TIMEOUT_S="$COMMITTEE_KEY_TIMEOUT_S" \
  SKIP_TALLY="${SKIP_TALLY:-}" \
  ENROLLMENT_FILE="${ENROLLMENT_FILE:-}" \
  DUMP_WITNESS="${DUMP_WITNESS:-}" \
  DUMP_WITNESS_ONLY="${DUMP_WITNESS_ONLY:-}" \
  node --import tsx "$CRISP/tests/qes-e2e.mjs" 2>&1 | tee "$DRIVER_LOG" )
DRIVER_RC=${PIPESTATUS[0]}
set -e 2>/dev/null || true

if [[ "$DRIVER_RC" -eq 0 ]]; then
  log "DRIVER PASSED — CRISP-QES local E2E composed end-to-end."
else
  log "DRIVER exited rc=$DRIVER_RC — see which STAGE failed in $DRIVER_LOG"
fi

log "Logs for this run: $LOG_DIR"
exit "$DRIVER_RC"
