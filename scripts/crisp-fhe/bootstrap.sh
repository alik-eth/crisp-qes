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

echo "==> [5/6] regenerate circuit target/*.json + recursive VKs + REGEN-AND-VALIDATE on-chain verifier (PINNED bb)"
# Prepend the shim dir so the fork's compile_circuits.sh picks up the pinned bb.
# compile_circuits.sh REGENERATES the fold Solidity verifier FROM the fold circuit
# (crisp_fold.json -> bb write_solidity_verifier) into
#   circuits/bin/fold/target/CRISPVerifier.sol
# and copies it to packages/crisp-contracts/contracts/CRISPVerifier.sol.
#
# FIX-B #6/#9: the on-chain verifier the contracts actually deploy is the COMMITTED
# CRISPQESVerifier.sol. A clean checkout, a wrong/wildcard bb, or a stale commit
# could ship a verifier that DOES NOT match the circuit, silently. So after the
# regen we COMPARE the freshly-generated verifier against the committed
# CRISPQESVerifier.sol and FAIL LOUDLY on any byte difference. This is ABI-agnostic:
# whatever verifier ABI the fork currently ships, the committed copy must equal a
# fresh regen-from-circuit with the pinned bb.
QES_VERIFIER="$CRISP/packages/crisp-contracts/contracts/CRISPQESVerifier.sol"
[ -f "$QES_VERIFIER" ] || { echo "FATAL: committed CRISPQESVerifier.sol missing at $QES_VERIFIER"; exit 1; }

( cd "$CRISP" && PATH="$SHIM_DIR:$PATH" bash ./scripts/compile_circuits.sh )

# compile_circuits.sh emits the regenerated verifier to two places; prefer the
# target/ copy (the raw write_solidity_verifier output it then license-headers +
# copies). We compare the contracts-folder copy, which has the SAME license header
# + prettier pass applied as the committed CRISPQESVerifier.sol, so a byte compare
# is apples-to-apples.
REGEN_VERIFIER="$CRISP/packages/crisp-contracts/contracts/CRISPVerifier.sol"
[ -f "$REGEN_VERIFIER" ] || { echo "FATAL: compile_circuits.sh did not produce $REGEN_VERIFIER"; exit 1; }

REGEN_SHA="$(sha256sum "$REGEN_VERIFIER" | cut -d' ' -f1)"
COMMITTED_SHA="$(sha256sum "$QES_VERIFIER" | cut -d' ' -f1)"
echo "    regen   verifier sha256: $REGEN_SHA  ($REGEN_VERIFIER)"
echo "    commit  verifier sha256: $COMMITTED_SHA  ($QES_VERIFIER)"
if [ "$REGEN_SHA" != "$COMMITTED_SHA" ]; then
  echo "FATAL: regenerated fold verifier does NOT match the committed CRISPQESVerifier.sol."
  echo "       The committed on-chain verifier is STALE or was built with a different bb."
  echo "       Diff (regen vs committed):"
  diff -u "$QES_VERIFIER" "$REGEN_VERIFIER" | head -40 || true
  echo "       Refusing to proceed — a mismatched verifier must not ship silently."
  exit 1
fi
echo "    OK: regenerated fold verifier is byte-identical to committed CRISPQESVerifier.sol"

echo "==> [6/6] VALIDATE fold key-hash consistency (PINNED bb) — FAIL on mismatch"
# compute_vk_hash recomputes the fold's expected member key-hash from the recursive
# VKs just regenerated with the pinned bb. The fold circuit BINDS this value via the
# globals in fold/src/main.nr (the default/insecure preset uses INSECURE). If the
# computed hash matches NEITHER global, the deployed fold verifier is built against a
# different inner-VK set than the circuit expects → proofs will be rejected on-chain.
# FIX-B #6/#9: this is now a HARD FAILURE, not a warning.
COMPUTED="$( cd "$CRISP" && PATH="$SHIM_DIR:$PATH" bash ./scripts/compute_vk_hash.sh | tr -d '[:space:]' )"
echo "    compute_vk_hash -> $COMPUTED"
FOLD_MAIN="$CRISP/circuits/bin/fold/src/main.nr"
EXP_INSECURE="$(grep -A1 'CRISP_FOLD_EXPECTED_KEY_HASH_INSECURE' "$FOLD_MAIN" | grep -oE '0x[0-9a-fA-F]+' | head -1)"
EXP_SECURE="$(grep -A1 'CRISP_FOLD_EXPECTED_KEY_HASH_SECURE' "$FOLD_MAIN" | grep -oE '0x[0-9a-fA-F]+' | head -1)"
echo "    fold/main.nr INSECURE expected: $EXP_INSECURE"
echo "    fold/main.nr SECURE   expected: $EXP_SECURE"
# Normalise (lowercase, strip 0x, drop leading zeros) for a robust compare.
norm() { printf '%s' "${1#0x}" | tr 'A-F' 'a-f' | sed 's/^0*//'; }
C_N="$(norm "$COMPUTED")"
if [ "$C_N" = "$(norm "$EXP_INSECURE")" ]; then
  echo "    MATCH: computed key-hash == CRISP_FOLD_EXPECTED_KEY_HASH_INSECURE (default preset)."
elif [ "$C_N" = "$(norm "$EXP_SECURE")" ]; then
  echo "    MATCH: computed key-hash == CRISP_FOLD_EXPECTED_KEY_HASH_SECURE."
else
  echo "FATAL: computed fold key-hash $COMPUTED matches NEITHER global in fold/src/main.nr."
  echo "       The recursive VKs (built with the pinned bb) are inconsistent with the"
  echo "       fold circuit's expected inner-VK binding. A mismatched fold verifier must"
  echo "       not ship. Regenerate fold globals (pnpm compute:vk-hash in examples/CRISP)"
  echo "       or check the bb pin (scripts/crisp-fhe/bb-pinned.sh)."
  exit 1
fi

echo
echo "Bootstrap complete. Next, run the VERIFY gate:"
echo "  ( cd $CRISP/circuits/bin/crisp_qes && nargo test )                       # 7 passing"
echo "  ( cd $CRISP/packages/crisp-contracts && npx hardhat test mocha tests/crisp-qes.contracts.test.ts tests/crisp-qes.onchain.test.ts )  # 13 passing"
# vitest binary lives in crisp-sdk/node_modules/.bin — run from that package dir.
echo "  ( cd $CRISP/packages/crisp-sdk && NODE_TLS_REJECT_UNAUTHORIZED=0 pnpm exec vitest --run tests/qesVote.test.ts )  # 2 passing (~5 min)"
