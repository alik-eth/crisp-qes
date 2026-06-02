// Threshold /v3/register test for the v3 Grumpkin VOPRF service (build/unaudited).
//
// The deployed register path is the 2-of-3 THRESHOLD flow: the enroll proof gates
// blind-eval and publishes C_r; the threshold oprf_nullifier proof self-attests
// the per-share DLEQs + Lagrange combine; the service cross-checks (a) M,
// (c) commitment, (d) C_r, (e) the published Kpub set, (f) epoch.
//
// WHAT RUNS LOCALLY vs WHAT IS BLOCKED:
//   * Full e2e (a REAL enroll bb-proof through POST /v3/register) is BLOCKED: the
//     deployed enroll_commit_v2 asserts a PRODUCTION-pinned Diia CA that a
//     synthetic cert cannot satisfy (no test CA in the prod set, no real PII).
//     This is pre-existing (same as F2), not threshold-specific.
//   * So we test the threshold register layer that IS runnable:
//       (1) the threshold node set boots (3 distinct published Kpub, indices 1-3);
//       (2) verifyThresholdNullifierProof cross-checks (a)/(c)/(d)/(e)/(f) reject
//           with the right codes, cheap-FIRST (before the wasm verify), incl. the
//           NEW (e) wrong-Kpub-set and (f) wrong-epoch negatives -- via a fake gate;
//       (3) the threshold nullifier WITNESS shape solves: gen-threshold-nullifier-
//           witness.mjs -> nargo execute -> THR_NULLIFIER (cross-language).
//
// Run with cwd in v3-grumpkin:  node service/register-test.mjs

import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildApp } from "./server.mjs";
import {
    THRESHOLD_NULLIFIER_WORD_COUNT,
    extractThresholdNullifierPublics,
    verifyThresholdNullifierProof,
} from "./proof-gate.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const NULLIFIER_DIR = join(ROOT, "circuits", "oprf_nullifier");

const THR_NULLIFIER = "0x15f45ee3ae19caac1503058be2fd8108e26b93b2a943efd45ed9dfd0b7fbfc58";
const ATTESTER_KEY =
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

let failures = 0;
function check(name, cond, extra) {
    const tag = cond ? "PASS" : "FAIL";
    if (!cond) failures++;
    console.log(`  [${tag}] ${name}${extra ? "  — " + extra : ""}`);
}

const h = (v) => "0x" + v.toString(16).padStart(64, "0");

async function main() {
    console.log("v3 Grumpkin THRESHOLD /v3/register test (build, unaudited)\n");

    // — (1) Threshold node set boots with 3 distinct published Kpub ──────────
    console.log("[node set]");
    const fakeGate = { _ran: false, async verify() { this._ran = true; return false; } };
    const app = await buildApp({ gate: fakeGate, nullifierGate: fakeGate, attesterKey: ATTESTER_KEY, logger: false });
    const health = (await app.inject({ method: "GET", url: "/healthz" })).json();
    check("healthz publishes a 3-node Kpub set", health.publishedKpubSet?.length === 3,
        `len=${health.publishedKpubSet?.length}`);
    check("published indices are 1,2,3",
        health.publishedKpubSet?.map((p) => p.i).join(",") === "1,2,3");
    check("published Kpub are distinct",
        new Set(health.publishedKpubSet?.map((p) => p.Kpub_i)).size === 3);
    check("healthz exposes the threshold epoch", typeof health.thresholdEpoch === "string");
    await app.close();

    // — (2) verifyThresholdNullifierProof cross-checks (fake gate) ───────────
    console.log("\n[cross-checks (a)/(c)/(d)/(e)/(f)]");
    // synthetic 13-word public set + matching expected values.
    const W = Array.from({ length: 13 }, () => h(0n));
    W[0] = h(11n); W[1] = h(12n);                 // M
    W[2] = h(21n); W[3] = h(22n);                 // Kpub1
    W[4] = h(41n); W[5] = h(42n);                 // Kpub2
    W[6] = h(61n); W[7] = h(62n);                 // Kpub3
    W[8] = h(1n); W[9] = h(2n);                   // idx1, idx2
    W[10] = h(0x1234n);                           // epoch
    W[11] = h(0x2dc4n);                           // c_r
    W[12] = h(0x15f4n);                           // nullifier
    check("threshold layout is 13 words", THRESHOLD_NULLIFIER_WORD_COUNT === 13);
    const ex = extractThresholdNullifierPublics(W);
    check("extractor reads M/Kpub-set/idx/epoch/c_r/nullifier",
        ex.M.x === 11n && ex.Kpub1.x === 21n && ex.Kpub2.x === 41n && ex.Kpub3.x === 61n
        && ex.idx1 === 1n && ex.idx2 === 2n && ex.epoch === 0x1234n && ex.cr === 0x2dc4n
        && ex.nullifier === 0x15f4n);

    const KSET = [{ x: 21n, y: 22n }, { x: 41n, y: 42n }, { x: 61n, y: 62n }];
    const base = {
        proof: "0x00", publicInputs: W, expectedM: { x: 11n, y: 12n },
        publishedKpubSet: KSET, expectedEpoch: 0x1234n, expectedCr: 0x2dc4n,
        expectedCommitment: 0x15f4n,
    };
    const fg = { _ran: false, async verify() { this._ran = true; return false; } };

    let r = await verifyThresholdNullifierProof({ ...base, gate: fg, expectedM: { x: 99n, y: 12n } });
    check("(a) wrong M => NullifierMismatchedM [HARD identity binding]", r.code === "NullifierMismatchedM");
    r = await verifyThresholdNullifierProof({ ...base, gate: fg, expectedCommitment: 0x9999n });
    check("(c) wrong commitment => NullifierMismatchedCommitment", r.code === "NullifierMismatchedCommitment");
    r = await verifyThresholdNullifierProof({ ...base, gate: fg, expectedCr: 0x9999n });
    check("(d) wrong c_r => NullifierMismatchedCr", r.code === "NullifierMismatchedCr");
    r = await verifyThresholdNullifierProof({
        ...base, gate: fg,
        publishedKpubSet: [{ x: 21n, y: 22n }, { x: 999n, y: 42n }, { x: 61n, y: 62n }],
    });
    check("(e) wrong Kpub set => NullifierMismatchedKpubSet", r.code === "NullifierMismatchedKpubSet");
    r = await verifyThresholdNullifierProof({ ...base, gate: fg, expectedEpoch: 0x9999n });
    check("(f) wrong epoch => NullifierMismatchedEpoch", r.code === "NullifierMismatchedEpoch");
    check("cross-checks reject BEFORE the wasm verify (cheap-first)", fg._ran === false);

    fg._ran = false;
    r = await verifyThresholdNullifierProof({ ...base, gate: fg });
    check("all cross-checks pass => crypto verify runs", fg._ran === true);
    check("crypto false => ProofRejected", r.code === "ProofRejected");

    // — (3) Threshold nullifier witness shape solves to THR_NULLIFIER ────────
    console.log("\n[witness shape: gen-threshold-nullifier-witness.mjs -> nargo execute]");
    let executed = null;
    try {
        execFileSync("node", ["gen-threshold-nullifier-witness.mjs"], { cwd: ROOT, stdio: "pipe" });
        const out = execFileSync("nargo", ["execute"], { cwd: NULLIFIER_DIR, encoding: "utf8" });
        const m = out.match(/Circuit output:\s*(0x[0-9a-fA-F]+)/);
        executed = m ? m[1] : null;
    } catch (e) {
        executed = `ERROR: ${(e.message || "").slice(0, 120)}`;
    }
    check("threshold nullifier nargo execute == THR_NULLIFIER", executed === THR_NULLIFIER,
        `got ${executed}`);

    console.log("\nNOTE: full e2e (real enroll bb-proof) is blocked by the production Diia CA pin");
    console.log("      (pre-existing, not threshold-specific) -- see the file header.");

    console.log("");
    if (failures === 0) {
        console.log("ALL RUNNABLE THRESHOLD REGISTER CHECKS PASS");
        process.exit(0);
    } else {
        console.log(`${failures} CHECK(S) FAILED`);
        process.exit(1);
    }
}

main().catch((e) => {
    console.error("register-test crashed:", e);
    process.exit(1);
});
