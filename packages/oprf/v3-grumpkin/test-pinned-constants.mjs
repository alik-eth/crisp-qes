// Regression test for the F1 + F3 pinned-constant security fixes.
//
// After the grumpkin_voprf library extraction, BOTH attacks are STRUCTURALLY
// IMPOSSIBLE rather than merely asserted-away inside a standalone circuit:
//   F1 (DLEQ generator substitution): GEN is the library's pinned global
//      (params::GEN_X/GEN_Y). It is NOT a circuit input, so oprf_nullifier's ABI
//      has no gx/gy to substitute -- the G' = (k')^-1*Kpub forgery is unexpressible.
//   F3 (non-canonical SvdW suite): c1..c4 are library globals (params::SVDW_C1..C4)
//      consumed by h2c. They are NOT inputs to enroll_commit_v2, so there is no
//      c1..c4 to swap for a non-canonical suite -- the forgery is unexpressible.
//
// The retired standalone commitment circuit (and its forge-f3-* probes) are
// gone; this harness now (a) ASSERTS the attacks are unexpressible by checking
// the compiled ABIs carry no gx/gy (nullifier) and no c1..c4 (enroll), and
// (b) runs the lib's `nargo test` (grumpkin_voprf) which covers SvdW pinning +
// the DLEQ/C_r binding, plus enroll_commit_v2's own #[test]s.
//
// Exits nonzero on ANY deviation, so CI catches a regression that re-introduces
// a forgeable input. Run:  node test-pinned-constants.mjs  (cwd = v3-grumpkin)

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));
const CIRCUITS = join(ROOT, "circuits");
const LIB = join(ROOT, "lib-noir", "grumpkin_voprf");

let failures = 0;
const log = (s) => console.log(s);
const fail = (s) => { console.error("  FAIL: " + s); failures++; };
const pass = (s) => console.log("  ok:   " + s);

// Compiled-ABI param names for a circuit (from its target JSON).
function abiParamNames(circuit) {
    const j = JSON.parse(
        readFileSync(join(CIRCUITS, circuit, "target", `${circuit}.json`), "utf8"),
    );
    return j.abi.parameters.map((p) => p.name);
}

// `nargo test` in a package dir. Returns true if ALL tests pass.
function nargoTest(cwd) {
    try {
        execFileSync("nargo", ["test"], { cwd, stdio: "pipe" });
        return true;
    } catch {
        return false;
    }
}

// Assert NONE of `forbidden` appear in the circuit's compiled-ABI inputs.
function assertNoInputs(name, circuit, forbidden) {
    let params;
    try {
        params = abiParamNames(circuit);
    } catch (e) {
        fail(`${name}: could not read ${circuit} ABI (compile it first): ${e.message}`);
        return;
    }
    const present = forbidden.filter((f) => params.includes(f));
    if (present.length === 0) {
        pass(`${name}: ${circuit} ABI has no [${forbidden.join(", ")}] input (closed by construction)`);
    } else {
        fail(`${name}: ${circuit} ABI re-introduced forgeable input(s): ${present.join(", ")}`);
    }
}

// F1 — oprf_nullifier: the DLEQ base GEN is the lib's pinned global, NOT an input.
// A substituted-generator forgery needs gx/gy inputs; assert they are absent.
log(`\n[F1] (oprf_nullifier — pinned GEN in grumpkin_voprf; no attacker-suppliable base)`);
assertNoInputs("F1", "oprf_nullifier", ["gx", "gy"]);

// F3 — enroll_commit_v2: the SvdW suite c1..c4 are lib globals, NOT inputs.
// A non-canonical-suite forgery needs c1..c4 inputs; assert they are absent.
log(`\n[F3] (enroll_commit_v2 — pinned SvdW c1..c4 in grumpkin_voprf; no suite inputs)`);
assertNoInputs("F3", "enroll_commit_v2", ["c1", "c2", "c3", "c4"]);

// Library coverage: grumpkin_voprf's tests pin SvdW (h2c) + GEN (dleq) + the F2
// C_r binding. enroll_commit_v2's own #[test]s cover the Diia chain + C_r anchor.
log(`\n[lib] grumpkin_voprf nargo test (SvdW/GEN pinning + DLEQ/C_r binding)`);
if (nargoTest(LIB)) pass("grumpkin_voprf nargo test passed");
else fail("grumpkin_voprf nargo test FAILED (pinning/binding regression)");

log(`\n[circuit] enroll_commit_v2 nargo test (Diia chain + C_r anchor)`);
if (nargoTest(join(CIRCUITS, "enroll_commit_v2"))) pass("enroll_commit_v2 nargo test passed");
else fail("enroll_commit_v2 nargo test FAILED");

if (failures > 0) {
    console.error(`\n${failures} check(s) FAILED.`);
    process.exit(1);
}
console.log("\nAll pinned-constant security checks passed (F1 + F3 closed by construction).");
