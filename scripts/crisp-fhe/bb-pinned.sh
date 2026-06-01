#!/usr/bin/env bash
# Resolve and exec the `bb` binary bundled with @aztec/bb.js inside the vendored
# fork, NOT the `bb` on PATH (which is a 4.x CLI). The verifier/recursive-VK and
# fold key-hash artifacts are bb-version-sensitive; using the 4.x CLI reintroduces
# the Phase 3 fold key-hash mismatch. The bundled binary must be EXACTLY the
# nightly the fork's @aztec/bb.js resolves to — VKs are nightly-DATE-sensitive,
# so a wildcard 3.0.0-nightly.* could silently ship a mismatched verifier
# (adversarial review FIX-B #14 / #19). See memory: reference_bb_cli_vs_bbjs_version.
set -euo pipefail

# The exact @aztec/bb.js version the fork (examples/CRISP/packages/crisp-sdk)
# depends on. Keep in lock-step with that package.json.
BB_PIN="3.0.0-nightly.20260102"

# Resolve repo root from THIS script's location, not the CWD. This script is run
# from inside the submodule (where `git rev-parse --show-toplevel` would wrongly
# return the submodule root), so anchor on scripts/crisp-fhe/ -> repo root (../..).
# readlink -f follows symlinks so a PATH shim (ln -s .../bb-pinned.sh shim/bb)
# still anchors on the real script location.
SELF="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
ROOT="$(cd "$SELF/../.." && pwd)"

# #19: resolve the bb deterministically. Prefer the pnpm content-addressed path
# for the EXACT pinned version (one canonical location); fall back to a path
# glob but ERROR if more than one bb build dir matches (nondeterministic).
PINNED_DIR="$ROOT/vendor/crisp-qes-enclave/node_modules/.pnpm/@aztec+bb.js@${BB_PIN}/node_modules/@aztec/bb.js"
BB="$PINNED_DIR/build/amd64-linux/bb"
if [ ! -x "$BB" ]; then
  # Fallback: scan, but require a UNIQUE match so the result is deterministic.
  mapfile -t _CANDS < <(find "$ROOT/vendor/crisp-qes-enclave" -path '*@aztec/bb.js*/build/amd64-linux/bb' -type f 2>/dev/null | sort)
  if [ "${#_CANDS[@]}" -eq 0 ]; then
    echo "FATAL: bundled bb not found (expected @aztec/bb.js@${BB_PIN}) — run pnpm install in the fork first (scripts/crisp-fhe/bootstrap.sh)"; exit 1
  elif [ "${#_CANDS[@]}" -gt 1 ]; then
    echo "FATAL: multiple bundled bb binaries found (nondeterministic) — refusing to guess:"; printf '  %s\n' "${_CANDS[@]}"; exit 1
  fi
  BB="${_CANDS[0]}"
fi
[ -x "$BB" ] || { echo "FATAL: bundled bb not executable: $BB"; exit 1; }

# #14: pin the EXACT version; reject any other nightly date.
VER="$("$BB" --version)"
if [ "$VER" != "$BB_PIN" ]; then
  echo "FATAL: bundled bb is '$VER', expected EXACTLY '$BB_PIN' (VKs are nightly-date-sensitive; see reference_bb_cli_vs_bbjs_version)"; exit 1
fi
exec "$BB" "$@"
