#!/usr/bin/env bash
#
# Regenerate the fold key-hash constants (CRISP_FOLD_EXPECTED_KEY_HASH_{INSECURE,
# SECURE}) and the on-chain fold verifier after a change to the recursive inner
# circuits (crisp_qes leaf and/or the threshold BFV circuits).
#
# WHY: bootstrap.sh only *validates* the fold key-hash globals against a fresh
# compute_vk_hash (and dies on mismatch); it never rewrites them. So any change to
# crisp_qes (which shifts crisp_key_hash) requires regenerating BOTH preset globals
# and the deployed verifier. The two presets correspond to:
#   - INSECURE: configs/default = insecure-512  (the local/dev + current deploy preset)
#   - SECURE:   configs/default = secure-8192   (production BFV params, N=8192; heavy)
#
# Everything runs with the PINNED bb (recursive VK + Honk verifier are
# nightly-date-sensitive — see memory reference_bb_cli_vs_bbjs_version).
#
# The SECURE detour flips configs/default + committee parity matrices via
# build:circuits, then RESTORES the committed insecure-512 files (trap-guarded so a
# failed/OOM secure build cannot leave the tree on secure params).
#
# Output: patched circuits/bin/fold/src/main.nr + regenerated CRISP{,QES}Verifier.sol.
# It does NOT commit — review `git -C vendor/... diff` then commit explicitly.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FORK="$ROOT/vendor/crisp-qes-enclave"
CRISP="$FORK/examples/CRISP"
BBPIN="$ROOT/scripts/crisp-fhe/bb-pinned.sh"

FOLD_MAIN="$CRISP/circuits/bin/fold/src/main.nr"
CONFIG_DEFAULT="$FORK/circuits/lib/src/configs/default/mod.nr"
COMMITTEE_ACTIVE="$FORK/circuits/lib/src/configs/committee/active.nr"
PARITY_DIR="$FORK/circuits/lib/src/configs/committee/micro"
REGEN_VERIFIER="$CRISP/packages/crisp-contracts/contracts/CRISPVerifier.sol"
QES_VERIFIER="$CRISP/packages/crisp-contracts/contracts/CRISPQESVerifier.sol"

step() { echo "=== [$(date -u +%H:%M:%S)] $* ==="; }
die()  { echo "[regen FATAL] $*" >&2; exit 1; }

# Pinned-bb PATH shim (same mechanism as bootstrap.sh).
"$BBPIN" --version >/dev/null || die "pinned bb not resolvable (run bootstrap/pnpm install first)"
SHIM="$(mktemp -d)"; ln -sf "$BBPIN" "$SHIM/bb"; export PATH="$SHIM:$PATH"
step "pinned bb: $(bb --version)"

# Back up the preset-managed files so the SECURE detour is fully reversible.
BK="$(mktemp -d)"
cp "$CONFIG_DEFAULT"               "$BK/default_mod.nr"
cp "$COMMITTEE_ACTIVE"             "$BK/active.nr"
cp "$PARITY_DIR/parity_insecure.nr" "$BK/parity_insecure.nr"
cp "$PARITY_DIR/parity_secure.nr"   "$BK/parity_secure.nr"

restore_preset_files() {
  step "restoring committed insecure-512 preset files"
  cp "$BK/default_mod.nr"        "$CONFIG_DEFAULT"
  cp "$BK/active.nr"             "$COMMITTEE_ACTIVE"
  cp "$BK/parity_insecure.nr"   "$PARITY_DIR/parity_insecure.nr"
  cp "$BK/parity_secure.nr"     "$PARITY_DIR/parity_secure.nr"
}
cleanup() { rm -rf "$SHIM"; }
trap 'restore_preset_files; cleanup' EXIT

compute_hash() { ( cd "$CRISP" && bash ./scripts/compute_vk_hash.sh | tr -d '[:space:]' ); }
compile_all()  { ( cd "$CRISP" && bash ./scripts/compile_circuits.sh ); }

# ── 1. INSECURE (current default): recursive VKs + compute V_INS ──────────────
step "INSECURE build (compile_circuits.sh, pinned bb)"
compile_all >/dev/null 2>&1 || die "insecure compile_circuits.sh failed"
V_INS="$(compute_hash)"
case "$V_INS" in 0x*) ;; *) die "could not compute INSECURE key-hash (got '$V_INS')";; esac
echo "    V_INS = $V_INS"

# ── 2. SECURE: flip preset → build → recursive VKs → compute V_SEC ────────────
step "SECURE preset flip (build:circuits --preset secure-8192 --committee micro)"
( cd "$FORK" && pnpm build:circuits --preset secure-8192 --committee micro --skip-vk --skip-utils-patch ) \
  || die "build:circuits secure-8192 failed (preset not flipped)"
step "SECURE compile_circuits.sh (crisp_qes/fold/threshold under secure, pinned bb)"
compile_all || die "secure compile_circuits.sh failed (likely OOM at N=8192 bb write_vk)"
V_SEC="$(compute_hash)"
case "$V_SEC" in 0x*) ;; *) die "could not compute SECURE key-hash (got '$V_SEC')";; esac
echo "    V_SEC = $V_SEC"

# ── 3. restore insecure preset (also via trap, but do it now for the rebuild) ──
restore_preset_files
trap 'cleanup' EXIT   # preset files restored; keep only shim cleanup from here

# ── 4. patch fold/main.nr with both constants ────────────────────────────────
step "patch fold/main.nr key-hash globals"
python3 - "$FOLD_MAIN" "$V_INS" "$V_SEC" <<'PY'
import re, sys
path, vi, vs = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
def setglobal(s, name, val):
    pat = re.compile(r'(CRISP_FOLD_EXPECTED_KEY_HASH_' + name + r':\s*Field\s*=\s*)0x[0-9a-fA-F]+', re.S)
    s2, n = pat.subn(lambda m: m.group(1) + val, s)
    if n != 1:
        raise SystemExit(f"expected exactly 1 {name} global, patched {n}")
    return s2
s = setglobal(s, 'INSECURE', vi)
s = setglobal(s, 'SECURE',   vs)
open(path, 'w').write(s)
print(f"    set INSECURE={vi}")
print(f"    set SECURE  ={vs}")
PY

# ── 5. rebuild insecure + regenerate verifier with the new fold constants ─────
step "rebuild insecure + regenerate fold verifier (compile_circuits.sh)"
compile_all >/dev/null 2>&1 || die "final insecure compile_circuits.sh failed"
[ -f "$REGEN_VERIFIER" ] || die "compile_circuits.sh did not produce CRISPVerifier.sol"

# Copy the freshly-generated verifier into the DEPLOYED CRISPQESVerifier.sol.
cp "$REGEN_VERIFIER" "$QES_VERIFIER"

# ── 6. validate: compute_vk_hash must equal the INSECURE global we just wrote ──
step "validate"
C="$(compute_hash)"
NEW_INS="$(grep -A1 'CRISP_FOLD_EXPECTED_KEY_HASH_INSECURE' "$FOLD_MAIN" | grep -oE '0x[0-9a-fA-F]+' | head -1)"
VKH="$(grep -oE 'VK_HASH = 0x[0-9a-fA-F]+' "$QES_VERIFIER" | grep -oE '0x[0-9a-fA-F]+' | head -1)"
NPI="$(grep -oE 'NUMBER_OF_PUBLIC_INPUTS = [0-9]+' "$QES_VERIFIER" | grep -oE '[0-9]+' | head -1)"
echo "    recomputed key-hash         : $C"
echo "    fold INSECURE global         : $NEW_INS"
echo "    new CRISPQESVerifier VK_HASH : $VKH | inputs $NPI"
[ "$C" = "$NEW_INS" ] || die "post-regen mismatch: compute_vk_hash ($C) != fold INSECURE global ($NEW_INS)"
echo
echo "REGEN OK."
echo "  V_INS = $V_INS"
echo "  V_SEC = $V_SEC"
echo "  CRISPQESVerifier VK_HASH = $VKH ($NPI inputs)"
echo "Review + commit: fold/src/main.nr, CRISPQESVerifier.sol, CRISPVerifier.sol"
