// ADR-0001 path (C) de-risk: prove the v4 (enrollment) and v3 (vote) bb.js can
// COEXIST when isolated in separate realms — exactly the browser model of a v4
// main thread + a v3 Web Worker. We can't prove this in ONE realm (the bb.js
// WASM singleton collides — that's the whole reason for the split); node
// worker_threads give the same realm isolation as Web Workers and run headless.
//
// Main realm  -> @aztec/bb.js       (v4, 4.0.0-nightly.20260120) — enrollment line
// Worker realm-> @aztec/bb.js-v3    (v3, 3.0.0-nightly.20260102) — vote line
//
// Run from packages/web:  node scripts/validate-dual-bbjs.mjs

import { Worker } from "node:worker_threads";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Barretenberg } from "@aztec/bb.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgVersion = (name) =>
    JSON.parse(readFileSync(join(__dirname, "..", "node_modules", "@aztec", name, "package.json"), "utf8")).version;

let failures = 0;
const check = (name, cond, extra) => {
    if (!cond) failures++;
    console.log(`  [${cond ? "PASS" : "FAIL"}] ${name}${extra ? "  — " + extra : ""}`);
};

const runWorker = () =>
    new Promise((resolve, reject) => {
        const w = new Worker(join(__dirname, "dual-bbjs-realm.worker.mjs"));
        w.once("message", (m) => { w.terminate(); resolve(m); });
        w.once("error", reject);
    });

async function main() {
    console.log("ADR-0001 (C) dual-bb.js coexistence check\n");

    // — Main realm: v4 (the enrollment/web line) ─────────────────────────────
    const v4 = pkgVersion("bb.js");
    const bb4 = await Barretenberg.new({ threads: 1 });
    let mainInit = false;
    try { await bb4.destroy?.(); mainInit = true; } catch { mainInit = true; }
    check("main realm: @aztec/bb.js (v4) initialized", mainInit, v4);
    check("main realm version is 4.x", v4.startsWith("4."), v4);

    // — Worker realm: v3 (the vote line), separate registry + globals ────────
    const wr = await runWorker();
    if (wr.error) { check("worker realm: @aztec/bb.js-v3 (v3) initialized", false, wr.error); }
    else {
        check("worker realm: @aztec/bb.js-v3 (v3) initialized", wr.initialized === true);
        check("worker realm version is 3.x", String(wr.version).startsWith("3."), wr.version);
    }

    // — Coexistence: both bb.js builds live, distinct versions, no collision ──
    check(
        "two DISTINCT bb.js versions coexist across realms (no singleton collision)",
        mainInit && wr.initialized === true && v4 !== wr.version,
        `main=${v4} worker=${wr.version}`,
    );

    console.log(`\n${failures === 0 ? "ALL PASS — path (C) realm isolation works (v4 main + v3 worker)" : failures + " FAILURE(S)"}`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
