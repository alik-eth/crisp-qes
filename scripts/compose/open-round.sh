#!/usr/bin/env bash
# Open an FHE voting round on the docker-compose-dev stack. Run on the HOST
# (needs `cast` + `docker compose`) AFTER you've enrolled, so the pinned root
# contains your leaf.
#
#   bash scripts/compose/open-round.sh "Cats or dogs?" "Cats,Dogs,Both" [days]
set -euo pipefail

Q="${1:?question required}"
OPTS="${2:?comma-separated options required}"
DAYS="${3:-30}"
N="$(awk -F, '{print NF}' <<<"$OPTS")"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
set -a; . "$ROOT/.env.dev"; set +a
RPC="http://localhost:8545"
COMPOSE=(docker compose --env-file "$ROOT/.env.dev" -f "$ROOT/docker-compose.dev.yml")

# Pin the LOCAL EnrollmentRegistry root (the eligible set, incl. your enrollment).
PINNED="$(cast call "$ENROLLMENT_REGISTRY" "enrollmentRoot()(bytes32)" --rpc-url "$RPC")"
echo "[open-round] pinning local enrollment root $PINNED  (numOptions=$N)"

# requestE3 via the enclave cli INSIDE the fhe container.
E3ID="$("${COMPOSE[@]}" exec -T fhe bash -lc \
  "cd /app/examples/CRISP && ./target/release/cli init -n $N 2>/dev/null | tail -1" | tr -dc '0-9')"
echo "[open-round] e3Id=$E3ID (committee DKG starting)"

cast send "$CRISP_QES_PROGRAM" "setEnrollmentRoot(uint256,uint256)" "$E3ID" "$PINNED" \
  --private-key "$ANVIL0_KEY" --rpc-url "$RPC" >/dev/null
NOW="$(cast block latest --rpc-url "$RPC" -f timestamp)"
DEADLINE="$((NOW + DAYS * 86400))"
cast send "$BALLOT_REGISTRY" "createRound(uint256,string,string[],bytes32,uint64)" \
  "$E3ID" "$Q" "[$OPTS]" "$PINNED" "$DEADLINE" \
  --private-key "$ANVIL0_KEY" --rpc-url "$RPC" >/dev/null

echo "[open-round] round $E3ID open. DKG takes ~60-80s; then vote at http://localhost:8080"
