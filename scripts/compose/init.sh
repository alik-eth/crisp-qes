#!/usr/bin/env bash
# docker-compose-dev init: deploy EnrollmentRegistry + BallotRegistry onto the
# local FHE anvil from a dedicated deployer key (nonce 0/1 => deterministic
# addrs the web build + oprf/relayer env already pin). Runs once (foundry image,
# /contracts bind-mounted). Idempotent: skips if the registry is already there.
set -euo pipefail

RPC="${RPC_URL:-http://fhe:8545}"
: "${DEPLOYER_KEY:?}" "${DEPLOYER_ADDR:?}" "${ANVIL0_KEY:?}" "${ANVIL0_ADDR:?}"
: "${ENROLLMENT_REGISTRY:?}" "${BALLOT_REGISTRY:?}" "${ENROLL_ATTESTER:?}" "${GENESIS_ROOT:?}"

echo "[init] waiting for anvil at $RPC …"
until cast block-number --rpc-url "$RPC" >/dev/null 2>&1; do sleep 2; done
echo "[init] anvil up."

if [ "$(cast code "$ENROLLMENT_REGISTRY" --rpc-url "$RPC" 2>/dev/null)" != "0x" ]; then
  echo "[init] registries already deployed — nothing to do."
  exit 0
fi

echo "[init] funding deployer $DEPLOYER_ADDR …"
cast send "$DEPLOYER_ADDR" --value 10ether --private-key "$ANVIL0_KEY" --rpc-url "$RPC" >/dev/null

# Stage the (read-only, bind-mounted) contracts into a writable in-container dir
# so forge can write its cache/out/broadcast without touching the host mount
# (avoids rootless-podman/SELinux write-permission issues on the bind-mount).
echo "[init] staging contracts to /tmp/contracts …"
rm -rf /tmp/contracts && cp -a /contracts /tmp/contracts
cd /tmp/contracts
echo "[init] deploying EnrollmentRegistry (nonce 0) …"
ENROLL_ATTESTER="$ENROLL_ATTESTER" ENROLL_GENESIS_ROOT="$GENESIS_ROOT" \
  forge script script/DeployEnrollmentRegistry.s.sol \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast >/tmp/enroll.log 2>&1 \
  || { cat /tmp/enroll.log; exit 1; }

echo "[init] deploying BallotRegistry (nonce 1) …"
BALLOT_OPERATOR="$ANVIL0_ADDR" \
  forge script script/DeployBallotRegistry.s.sol \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast >/tmp/ballot.log 2>&1 \
  || { cat /tmp/ballot.log; exit 1; }

# Verify they landed at the deterministic addresses the rest of the stack pins.
[ "$(cast code "$ENROLLMENT_REGISTRY" --rpc-url "$RPC")" != "0x" ] || { echo "[init] EnrollmentRegistry NOT at $ENROLLMENT_REGISTRY"; exit 1; }
[ "$(cast code "$BALLOT_REGISTRY"     --rpc-url "$RPC")" != "0x" ] || { echo "[init] BallotRegistry NOT at $BALLOT_REGISTRY"; exit 1; }
echo "[init] OK — EnrollmentRegistry=$ENROLLMENT_REGISTRY BallotRegistry=$BALLOT_REGISTRY"
