#!/usr/bin/env bash
# Phase 3e Task 0 — make a clean checkout of the vendored CRISP-QES encrypted-tally
# fork reproducibly buildable, with the bb toolchain HARD-PINNED to the bb binary
# bundled with @aztec/bb.js 3.0.0-nightly (NOT the 4.x `bb` CLI on PATH).
#
# What it does:
#   1. recursively init submodules (incl. the fork's own risc0-ethereum)
#   2. pnpm install at the fork's pnpm-workspace root (provides bb.js + bundled bb)
#   3. pre-seed / sanity-check the bb CRS cache (~/.bb-crs)
#   4. apply the beta.19 `Vec::from_slice` test patch IF present
#   5. regenerate the gitignored circuit target/*.json (crisp_qes leaf, fold, and
#      the threshold user_data_encryption trio) + recursive VKs using the PINNED bb,
#      so the SDK proving path (which imports those target JSONs) is reproducible
#   6. VERIFY the regenerated fold key-hash is consistent with the COMMITTED
#      CRISPQESVerifier.sol VK_HASH (we do NOT regenerate/overwrite the committed
#      verifier — it was generated in Phase 3 with the bundled bb, commit 6a464ee1).
#
# The committed CRISPQESVerifier.sol (24 public inputs) + qes-onchain.json fixture
# are intentionally NOT regenerated; the on-chain & contract Hardhat tests consume
# them as-is. The real proof that the pin is correct is the SDK proving test in
# qesVote.test.ts (leaf -> fold via bb.js).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
FORK="$ROOT/vendor/crisp-qes-enclave"
CRISP="$FORK/examples/CRISP"
BB_PINNED="$SCRIPT_DIR/bb-pinned.sh"

echo "==> [1/6] git submodule update --init --recursive"
git -C "$ROOT" submodule update --init --recursive

echo "==> [2/6] pnpm install at fork workspace root ($FORK)"
# The fork's pnpm-workspace.yaml lives at $FORK and references examples/CRISP/*;
# install must run at the workspace root so the lockfile + bb.js resolve correctly.
pnpm -C "$FORK" install

# Build the workspace TS deps that the QES test gate consumes via their dist/:
#   - @enclave-e3/contracts  -> dist/tasks/utils.js  (imported by crisp-contracts
#     hardhat.config.ts; pnpm compile = hardhat compile + tsc)
#   - @crisp-e3/zk-inputs    -> dist/index.js        (imported transitively by the
#     crisp-sdk QES proving test)
# Without these, the contract tests and SDK test fail at module-resolution time.
echo "    building @enclave-e3/contracts (hardhat compile + tsc)..."
pnpm -C "$FORK/packages/enclave-contracts" compile
echo "    building @crisp-e3/zk-inputs..."
pnpm -C "$CRISP/packages/crisp-zk-inputs" build

# Locate the bundled bb (also validates the pin) and build a PATH shim dir whose
# `bb` is the pinned 3.0.0-nightly binary, so the fork's own scripts (which call a
# bare `bb`) use it instead of the 4.x CLI.
"$BB_PINNED" --version >/dev/null
SHIM_DIR="$(mktemp -d)"
trap 'rm -rf "$SHIM_DIR"' EXIT
ln -sf "$BB_PINNED" "$SHIM_DIR/bb"
echo "    pinned bb: $("$BB_PINNED" --version)"

echo "==> [3/6] CRS cache sanity-check (~/.bb-crs)"
if [ ! -f "$HOME/.bb-crs/bn254_g1.dat" ]; then
  echo "    WARNING: ~/.bb-crs not pre-seeded. bb will fetch from crs.aztec.network."
  echo "    That cert is expired; if download fails, re-run with NODE_TLS_REJECT_UNAUTHORIZED=0"
  echo "    (and/or set a curl insecure fallback). On this host the CRS is normally pre-seeded."
else
  echo "    CRS present: $(du -h "$HOME/.bb-crs/bn254_g1.dat" | cut -f1) bn254_g1.dat"
fi

echo "==> [4/6] beta.19 Vec::from_slice test patch (if present)"
# beta.19 nargo dropped Vec::from_slice. The enclave circuit lib uses it in #[test]
# fns at $FORK/circuits/lib/src/math/{safe,helpers}.nr (NOT under examples/CRISP).
# Rewrite each `let [mut ]NAME = Vec::from_slice(&?[a,b,..]);` to
# `let mut NAME = Vec::new(); NAME.push(a); ...`. Idempotent: a no-op once patched.
HITS="$(grep -rl "Vec::from_slice" "$FORK/circuits/lib/src" "$CRISP/circuits/lib/src" 2>/dev/null || true)"
if [ -n "$HITS" ]; then
  echo "    found Vec::from_slice in:"; echo "$HITS" | sed 's/^/      /'
  python3 - "$HITS" <<'PY'
import re, sys, pathlib
pat = re.compile(r'^(\s*)let\s+(?:mut\s+)?(\w+)\s*=\s*Vec::from_slice\(&?\[([^\]]*)\]\);\s*$', re.M)
def repl(m):
    indent, name, items = m.group(1), m.group(2), m.group(3)
    elems = [e.strip() for e in items.split(',') if e.strip()]
    out = [f"{indent}let mut {name} = Vec::new();"]
    out += [f"{indent}{name}.push({e});" for e in elems]
    return "\n".join(out)
total = 0
for f in [a for a in sys.argv[1:] if a]:
    for f2 in f.split("\n"):
        f2 = f2.strip()
        if not f2: continue
        p = pathlib.Path(f2)
        new, n = pat.subn(repl, p.read_text())
        if n:
            p.write_text(new); total += n
            print(f"    patched {f2}: {n} site(s)")
print(f"    Vec::from_slice patch total: {total} site(s)")
PY
  REMAIN="$(grep -rl "Vec::from_slice" "$FORK/circuits/lib/src" "$CRISP/circuits/lib/src" 2>/dev/null || true)"
  [ -z "$REMAIN" ] || { echo "FATAL: Vec::from_slice still present after patch in: $REMAIN"; exit 1; }
else
  echo "    none found — no patch needed."
fi

echo "==> [5/6] regenerate gitignored circuit target/*.json + recursive VKs (PINNED bb)"
# Prepend the shim dir so the fork's compile_circuits.sh picks up the pinned bb.
# compile_circuits.sh writes the *non-QES* CRISPVerifier.sol (23 inputs); it does
# NOT touch the committed CRISPQESVerifier.sol. We snapshot CRISPQESVerifier.sol
# and assert it is byte-identical afterwards as a guardrail.
QES_VERIFIER="$CRISP/packages/crisp-contracts/contracts/CRISPQESVerifier.sol"
QES_SHA_BEFORE="$(sha256sum "$QES_VERIFIER" | cut -d' ' -f1)"
( cd "$CRISP" && PATH="$SHIM_DIR:$PATH" bash ./scripts/compile_circuits.sh )
QES_SHA_AFTER="$(sha256sum "$QES_VERIFIER" | cut -d' ' -f1)"
if [ "$QES_SHA_BEFORE" != "$QES_SHA_AFTER" ]; then
  echo "FATAL: committed CRISPQESVerifier.sol was modified by compile_circuits.sh — aborting"
  exit 1
fi
echo "    committed CRISPQESVerifier.sol unchanged (guardrail OK)"

echo "==> [6/6] verify fold key-hash consistency (PINNED bb)"
# compute_vk_hash recomputes the fold's expected member key-hash from the recursive
# VKs just regenerated. It must match one of the globals baked into fold/src/main.nr.
COMPUTED="$( cd "$CRISP" && PATH="$SHIM_DIR:$PATH" bash ./scripts/compute_vk_hash.sh | tr -d '[:space:]' )"
echo "    compute_vk_hash -> $COMPUTED"
if grep -q "${COMPUTED#0x}" "$CRISP/circuits/bin/fold/src/main.nr"; then
  echo "    MATCH: computed key-hash is present in fold/src/main.nr globals."
else
  echo "    WARNING: computed key-hash $COMPUTED not found verbatim in fold/src/main.nr."
  echo "    (Inspect CRISP_FOLD_EXPECTED_KEY_HASH_{INSECURE,SECURE}.) The SDK proving"
  echo "    test is the authoritative gate — run it next."
fi

echo
echo "Bootstrap complete. Next, run the VERIFY gate:"
echo "  ( cd $CRISP/circuits/bin/crisp_qes && nargo test )                       # 7 passing"
echo "  ( cd $CRISP/packages/crisp-contracts && npx hardhat test mocha tests/crisp-qes.contracts.test.ts tests/crisp-qes.onchain.test.ts )  # 13 passing"
# vitest binary lives in crisp-sdk/node_modules/.bin — run from that package dir.
echo "  ( cd $CRISP/packages/crisp-sdk && NODE_TLS_REJECT_UNAUTHORIZED=0 pnpm exec vitest --run tests/qesVote.test.ts )  # 2 passing (~5 min)"
