#!/usr/bin/env bash
# Resolve and exec the `bb` binary bundled with @aztec/bb.js inside the vendored
# fork, NOT the `bb` on PATH (which is a 4.x CLI). The verifier/recursive-VK and
# fold key-hash artifacts are bb-version-sensitive; using the 4.x CLI reintroduces
# the Phase 3 fold key-hash mismatch. The bundled binary must be 3.0.0-nightly.*.
# See memory: reference_bb_cli_vs_bbjs_version.
set -euo pipefail
# Resolve repo root from THIS script's location, not the CWD. This script is run
# from inside the submodule (where `git rev-parse --show-toplevel` would wrongly
# return the submodule root), so anchor on scripts/crisp-fhe/ -> repo root (../..).
# readlink -f follows symlinks so a PATH shim (ln -s .../bb-pinned.sh shim/bb)
# still anchors on the real script location.
SELF="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
ROOT="$(cd "$SELF/../.." && pwd)"
BB="$(find "$ROOT/vendor/crisp-qes-enclave" -path '*@aztec/bb.js*/build/amd64-linux/bb' -type f 2>/dev/null | head -1)"
[ -x "$BB" ] || { echo "FATAL: bundled bb not found — run pnpm install in the fork first (scripts/crisp-fhe/bootstrap.sh)"; exit 1; }
VER="$("$BB" --version)"
case "$VER" in
  3.0.0-nightly.*) ;;
  *) echo "FATAL: bundled bb is $VER, expected 3.0.0-nightly.* (see reference_bb_cli_vs_bbjs_version)"; exit 1;;
esac
exec "$BB" "$@"
