// F2 ADVERSARIAL REGRESSION GUARD against the NEW two-proof oprf_nullifier.
//
// The DEPLOYED oprf_nullifier (8-word ABI: public kpx,kpy,yx,yy,mx,my,c_r;
// private r,rinv,c,z limbs -- NO gx,gy,c_expected) composes
// grumpkin_voprf::oprf::oprf_nullify_bound, which:
//   * asserts commit_r(r) == c_r   (cross-proof shared-r binding; F2)
//   * asserts r*N == Y             (group-eq unblind binding; F2)
// so a register proof can no longer free `r`/`rinv` away from the enroll blind.
//
// HISTORY: the analogous forgery (rinv = 2*r^-1, free r = (2*r^-1)^-1 so r*N==Y
// still holds) was ACCEPTED by the PRE-FIX standalone oprf_nullifier -- see
// Task 1's evidence (it minted a distinct nullifier N = 2*k*H2C(id) for one
// identity, the F2 Sybil hole). On the two-proof circuit that escape is closed:
// `r` is pinned to the enroll proof via c_r = commit_r(r), so a forger cannot
// also satisfy r*N==Y with a mismatched rinv.
//
// This script builds TWO F2 forgeries and asserts the circuit REJECTS BOTH:
//   (V1) honest r + honest c_r=commit_r(r) (commit_r assert PASSES), but
//        rinv = 2*r^-1 != r^-1  -> MUST fail the group-eq assert "F2: r*N != Y".
//   (V2) honest r + honest rinv=r^-1, but c_r = commit_r(r)+1 (wrong-r commit)
//        -> MUST fail "c_r mismatch (r != enroll r)" (the cross-proof binding).
// Exits NONZERO if either forgery is NOT rejected (regression guard).

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Fn, N, G, hashToCurve, scalarLimbs, oprfEval, dleqProve, commitR } from "./lib.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const NULLIFIER_DIR = join(HERE, "circuits", "oprf_nullifier");
const PROVER_TOML = join(NULLIFIER_DIR, "Prover.toml");

const RNOKPP = new TextEncoder().encode("1234567890");
const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;
const r = det("crisp-qes-test-r"); // the SAME blind that formed M (enroll's r)
const k = det("crisp-qes-node-secret-k");
const t = det("crisp-qes-dleq-nonce-t");

const Kpub = G.multiply(k);
const M = hashToCurve(RNOKPP).multiply(r); // honest M = r*H2C(id)
const Y = oprfEval(k, M); // Y = k*M
const { c, z } = await dleqProve(k, Kpub, M, Y, t);
const rinvHonest = Fn.inv(Fn.create(r)); // r^-1
const rinvForged = Fn.mul(rinvHonest, 2n); // 2*r^-1 != r^-1 (still invertible, <N)
const crHonest = await commitR(r); // commit_r(r) the enroll proof publishes

const aff = (P) => P.toAffine();
const Ka = aff(Kpub), Ma = aff(M), Ya = aff(Y);
const cL = scalarLimbs(c), zL = scalarLimbs(z), rL = scalarLimbs(r);

// Write the 8-word two-proof ABI Prover.toml with the given (rinv, c_r).
function writeToml(rinvScalar, cr, banner) {
    const riL = scalarLimbs(rinvScalar);
    writeFileSync(
        PROVER_TOML,
        `# ${banner}
kpx = "${Ka.x}"
kpy = "${Ka.y}"
yx = "${Ya.x}"
yy = "${Ya.y}"
mx = "${Ma.x}"
my = "${Ma.y}"
c_r = "${cr}"
r_lo = "${rL.lo}"
r_hi = "${rL.hi}"
rinv_lo = "${riL.lo}"
rinv_hi = "${riL.hi}"
c_lo = "${cL.lo}"
c_hi = "${cL.hi}"
z_lo = "${zL.lo}"
z_hi = "${zL.hi}"
`,
    );
}

// Run `nargo execute`; return { rejected, out } (rejected = nonzero exit).
function nargoExecute() {
    const res = spawnSync("nargo", ["execute"], { cwd: NULLIFIER_DIR, encoding: "utf8" });
    return { rejected: res.status !== 0, out: (res.stdout || "") + (res.stderr || "") };
}

let failures = 0;
function expectReject(label, expectedMsg) {
    const { rejected, out } = nargoExecute();
    const trippedExpected = out.includes(expectedMsg);
    if (rejected && trippedExpected) {
        console.log(`  [REJECTED] ${label} -> tripped: "${expectedMsg}"`);
    } else if (rejected) {
        console.log(`  [REJECTED] ${label} (but expected "${expectedMsg}"; check the assert)`);
        console.log(out.split("\n").filter((l) => /assert|Failed|constraint/i.test(l)).slice(0, 4).join("\n"));
        failures++;
    } else {
        console.error(`  [ACCEPTED] ${label} -> F2 REGRESSION: the forgery was NOT rejected!`);
        failures++;
    }
}

console.log("F2 adversarial re-verify against the two-proof oprf_nullifier:\n");

// V1 — honest c_r (commit_r passes), forged rinv = 2*r^-1 -> group-eq must fail.
writeToml(rinvForged, crHonest, "F2 V1 forgery: rinv = 2*r^-1, honest c_r");
expectReject("V1 rinv = 2*r^-1 (honest c_r)", "F2: r*N != Y");

// V2 — honest rinv = r^-1, wrong c_r = commit_r(r)+1 -> commit_r bind must fail.
writeToml(rinvHonest, crHonest + 1n, "F2 V2 forgery: honest rinv, c_r = commit_r(r)+1");
expectReject("V2 c_r = commit_r(r)+1 (honest rinv)", "c_r mismatch (r != enroll r)");

if (failures > 0) {
    console.error(`\n${failures} F2 forgery/forgeries NOT properly rejected.`);
    process.exit(1);
}
console.log("\nBoth F2 forgeries REJECTED by the two-proof oprf_nullifier (F2 closed, live-verified).");
