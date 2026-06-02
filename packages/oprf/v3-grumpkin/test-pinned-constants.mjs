// Regression test for the F1 + F3 pinned-constant security fixes.
//
// For each circuit: build the HONEST witness and assert `nargo execute` ACCEPTS,
// then build a FORGERY witness and assert `nargo execute` REJECTS. Exits nonzero
// on ANY deviation (honest rejected OR forgery accepted), so CI catches a
// regression that re-opens the under-constraint.
//
//   F1  oprf_nullifier   : generator substitution (G' = k'^-1 * Kpub).
//   F3  oprf_commitment  : non-canonical SvdW suite constants.
//   F3  enroll_commit_v2 : its production main() is unreachable via `nargo
//                          execute` (needs a real Diia-pinned-CA signature over a
//                          PII leaf cert), so the SvdW-pinning gate is exercised
//                          via the in-circuit #[test]s (assert_canonical_svdw):
//                          test_svdw_canonical_ok (accept) +
//                          test_svdw_forged_constants_fail / _tampered_c4_fail
//                          (reject). We run `nargo test` and require all pass.
//
// Run:  node test-pinned-constants.mjs   (cwd = packages/oprf/v3-grumpkin)

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));
const CIRCUITS = join(ROOT, "circuits");

let failures = 0;
const log = (s) => console.log(s);
const fail = (s) => { console.error("  FAIL: " + s); failures++; };
const pass = (s) => console.log("  ok:   " + s);

// Run a generator script (writes the target circuit's Prover.toml).
function gen(script, env = {}) {
    execFileSync("node", [join(ROOT, script)], {
        cwd: ROOT, stdio: "pipe", env: { ...process.env, ...env },
    });
}

// `nargo execute` in a circuit dir. Returns true if the witness solved.
function nargoExecute(circuit) {
    try {
        execFileSync("nargo", ["execute"], {
            cwd: join(CIRCUITS, circuit), stdio: "pipe",
        });
        return true;
    } catch {
        return false;
    }
}

// `nargo test` in a circuit dir. Returns true if ALL tests pass.
function nargoTest(circuit) {
    try {
        execFileSync("nargo", ["test"], {
            cwd: join(CIRCUITS, circuit), stdio: "pipe",
        });
        return true;
    } catch {
        return false;
    }
}

// Generic accept/reject check for an execute-based circuit.
function checkExecuteCircuit(name, circuit, honestGen, forgeryGen) {
    log(`\n[${name}] (${circuit})`);
    gen(honestGen);
    if (nargoExecute(circuit)) pass("honest witness ACCEPTED");
    else fail("honest witness was REJECTED (expected accept)");
    gen(forgeryGen);
    if (!nargoExecute(circuit)) pass("forgery witness REJECTED");
    else fail("forgery witness was ACCEPTED (under-constraint re-opened!)");
}

// F1 — oprf_nullifier: generator substitution.
checkExecuteCircuit(
    "F1", "oprf_nullifier",
    "gen-nullifier-witness.mjs", "forge-f1-nullifier-witness.mjs",
);

// F3 — oprf_commitment: non-canonical SvdW constants.
checkExecuteCircuit(
    "F3", "oprf_commitment",
    "gen-commitment-witness.mjs", "forge-f3-commitment-witness.mjs",
);

// F3 — enroll_commit_v2: SvdW pinning via in-circuit tests (main() unreachable).
log(`\n[F3] (enroll_commit_v2 — in-circuit #[test] gate; main() needs real PII cert)`);
if (nargoTest("enroll_commit_v2")) {
    pass("nargo test passed (incl. test_svdw_canonical_ok + forged/tampered should_fail)");
} else {
    fail("nargo test FAILED (F3 pinning regression: a forged-constant test no longer rejects, or honest no longer accepts)");
}

// Restore honest witnesses so a developer's working tree is left consistent.
gen("gen-nullifier-witness.mjs");
gen("gen-commitment-witness.mjs");

if (failures > 0) {
    console.error(`\n${failures} check(s) FAILED.`);
    process.exit(1);
}
console.log("\nAll pinned-constant security checks passed (F1 + F3).");
