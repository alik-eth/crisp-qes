// SKELETON — DO NOT RUN UNTIL #30 (v2 circuit) COMMITS AND #33 (v2 web)
// has at least scaffolded a prove worker bundling the v2 circuit.
//
// v2 browser/WASM prover benchmark via Playwright. Mirrors `web-prove.mjs`
// from the MVP bench but targets the v2 web app's prove worker URL +
// the v2 witness shape.
//
// Three operating modes (in priority order):
//
//   1. **Against the MVP live web app + circuit-URL interception
//      (current default while v2 web is in #33).** The MVP prove worker
//      already accepts an arbitrary `circuitUrl` — it just fetch()'s and
//      hands the JSON to `UltraHonkBackend(circuit.bytecode, ...)`. We
//      route the request to serve the v2 ACIR JSON from local disk, then
//      post a {type:"prove", witness, circuitUrl} with the v2 witness
//      shape. The worker has no idea it's a different circuit — bb.js
//      doesn't care. This gets us a real-browser, real-COOP/COEP,
//      real-bb.js-wasm prove number BEFORE v2 web deploys.
//
//   2. **Against the live v2 web app (preferred once it exists).** Once
//      #33 + #34 ship at https://crisp-qes-web.fly.dev, point
//      --url at it and drop --interceptCircuit; the bench self-detects
//      and falls back to its own scraping.
//
//   3. **Against a self-hosted vite preview** (--url=http://localhost:4173).
//
// In all three modes the witness is constructed in Node (same synthetic
// `end_to_end_sanity_at_depth20` shape as `v2-native-prove.mjs`).

import { readFileSync, writeFileSync } from "node:fs";
import { chromium, firefox } from "playwright";
import { BarretenbergSync } from "@aztec/bb.js";

function arg(name, fallback) {
    const m = process.argv.find((a) => a.startsWith(`--${name}=`));
    return m ? m.slice(name.length + 3) : fallback;
}

const RUNS = parseInt(arg("runs", "3"), 10);
const BROWSER = arg("browser", "chromium");
const URL_BASE = arg("url", "https://crisp-qes-web.fly.dev");
const COMMIT = arg("commit", "");
const CPU_THROTTLE = parseFloat(arg("cpuThrottle", "1"));
const INTERCEPT_CIRCUIT = arg("interceptCircuit", "true") === "true";
const V2_CIRCUIT_PATH = arg("v2Circuit", "/data/Develop/crisp-qes/packages/circuit/target/crisp_qes_v2_circuit.json");
const V2_CIRCUIT_URL = "/crisp_qes_v2_circuit.json";

// TREE_DEPTH = 20, DOMAIN_PETITION_V2 — match packages/circuit/src/main.nr.
const TREE_DEPTH = 20;
const DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31n;

function toFieldHex(v) { return "0x" + v.toString(16).padStart(64, "0"); }
function bigintToBE32(v) {
    const out = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    return out;
}
function be32ToBigint(b) {
    let v = 0n;
    for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]);
    return v;
}

// -- 1. Synthetic witness inputs (same as v2-native-prove.mjs).
const api = await BarretenbergSync.initSingleton();
function pedersenHashFields(fields) {
    const inputs = fields.map(bigintToBE32);
    const { hash } = api.pedersenHash({ inputs, hashIndex: 0 });
    return be32ToBigint(hash);
}
const ENROLLMENT_SECRET = 0x42n;
const PETITION_ID = 999n;
const PATH = Array(TREE_DEPTH).fill(0n);
const INDICES = Array(TREE_DEPTH).fill(0);
let cur = ENROLLMENT_SECRET;
for (let i = 0; i < TREE_DEPTH; i++) {
    const left = INDICES[i] === 0 ? cur : PATH[i];
    const right = INDICES[i] === 0 ? PATH[i] : cur;
    cur = pedersenHashFields([left, right]);
}
const ENROLLMENT_ROOT = cur;
const NULLIFIER = pedersenHashFields([ENROLLMENT_SECRET, PETITION_ID, DOMAIN_PETITION_V2]);
const witnessInputs = {
    enrollment_secret: toFieldHex(ENROLLMENT_SECRET),
    merkle_path: PATH.map(toFieldHex),
    merkle_path_indices: INDICES.map((i) => i.toString(10)),
    petition_id: toFieldHex(PETITION_ID),
    enrollment_root: toFieldHex(ENROLLMENT_ROOT),
    nullifier: toFieldHex(NULLIFIER),
};
console.log("[setup] synthetic v2 witness ready");

// -- 2. Locate the live v2 worker bundle URL.
// (Same scraping pattern as web-prove.mjs.) The v2 web app must expose
// a worker at /assets/prove.worker-*.js that accepts
// {type:"prove", witness, circuitUrl} and replies {type:"done", proofBytes,
// publicInputs} — exactly the MVP protocol.
let WORKER_URL;
try {
    const indexHtml = await (await fetch(URL_BASE + "/")).text();
    const indexJsMatch = indexHtml.match(/\/assets\/index-[A-Za-z0-9_-]+\.js/);
    if (!indexJsMatch) throw new Error("could not find index-*.js asset URL");
    const indexJs = await (await fetch(URL_BASE + indexJsMatch[0])).text();
    const workerMatch = indexJs.match(/prove\.worker-[A-Za-z0-9_-]+\.js/);
    if (!workerMatch) throw new Error("could not find prove.worker-*.js URL");
    WORKER_URL = "/assets/" + workerMatch[0];
    console.log(`[setup] worker URL: ${WORKER_URL}`);
} catch (e) {
    console.error(`[setup] could not auto-detect worker URL at ${URL_BASE}: ${e.message}`);
    console.error("[setup] pass --url=<v2-web-base> once the v2 web app deploys.");
    process.exit(1);
}

// -- 3. Launch browser.
const launcher = BROWSER === "firefox" ? firefox : chromium;
const browser = await launcher.launch({ headless: true });
const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
const page = await ctx.newPage();

// Intercept the circuit URL fetch so the production worker (which
// expects /crisp_qes_circuit.json on the MVP host) actually receives
// the v2 ACIR JSON. bb.js doesn't care which circuit it gets — it
// just takes the bytecode field and feeds it to UltraHonkBackend.
if (INTERCEPT_CIRCUIT) {
    const v2CircuitBody = readFileSync(V2_CIRCUIT_PATH);
    await ctx.route("**/crisp_qes_circuit.json", (route) =>
        route.fulfill({
            status: 200,
            contentType: "application/json",
            body: v2CircuitBody,
        }),
    );
    await ctx.route("**/crisp_qes_v2_circuit.json", (route) =>
        route.fulfill({
            status: 200,
            contentType: "application/json",
            body: v2CircuitBody,
        }),
    );
    console.log(`[setup] route-intercepting circuit fetches → ${V2_CIRCUIT_PATH}`);
}
let cdp = null;
if (BROWSER === "chromium") {
    cdp = await ctx.newCDPSession(page);
    if (CPU_THROTTLE > 1) {
        await cdp.send("Emulation.setCPUThrottlingRate", { rate: CPU_THROTTLE });
        console.log(`[setup] CPU throttled ${CPU_THROTTLE}x (note: workers may not be affected)`);
    }
    await cdp.send("Performance.enable");
}

await page.goto(URL_BASE + "/", { waitUntil: "domcontentloaded" });
const env = await page.evaluate(() => ({
    userAgent: navigator.userAgent,
    hardwareConcurrency: navigator.hardwareConcurrency,
    crossOriginIsolated: globalThis.crossOriginIsolated,
    deviceMemory: navigator.deviceMemory ?? null,
}));
console.log("[env]", env);

function stats(arr) {
    const sorted = [...arr].sort((a, b) => a - b);
    const n = sorted.length;
    const mean = arr.reduce((a, b) => a + b, 0) / n;
    const variance = arr.reduce((a, b) => a + (b - mean) ** 2, 0) / n;
    const median = n % 2 === 0 ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2 : sorted[(n - 1) / 2];
    return {
        n,
        mean: +mean.toFixed(2),
        median: +median.toFixed(2),
        min: +sorted[0].toFixed(2),
        max: +sorted[n - 1].toFixed(2),
        stddev: +Math.sqrt(variance).toFixed(2),
    };
}

const records = [];
for (let i = 0; i < RUNS; i++) {
    if (i > 0) await page.goto(URL_BASE + "/", { waitUntil: "domcontentloaded" });

    const result = await page.evaluate(async ({ witness, workerUrl, circuitUrl }) => {
        const w = new Worker(workerUrl, { type: "module" });
        const t0 = performance.now();
        let tProving = null;
        const events = [];
        const done = await new Promise((resolve, reject) => {
            w.addEventListener("message", (ev) => {
                const m = ev.data;
                const at = performance.now();
                if (m && m.type === "stage") {
                    events.push({ at, stage: m.stage });
                    if (m.stage === "proving") tProving = at;
                } else if (m && m.type === "done") {
                    events.push({ at, stage: "done" });
                    resolve({ at, proofBytes: m.proofBytes.length });
                } else if (m && m.type === "error") {
                    reject(new Error(m.detail));
                }
            });
            w.addEventListener("error", (ev) => reject(new Error(ev.message)));
            w.postMessage({ type: "prove", witness, circuitUrl });
        });
        w.terminate();
        const memory = (performance).memory ? {
            jsHeapSizeLimitMb: +(performance.memory.jsHeapSizeLimit / 1e6).toFixed(0),
            usedJSHeapSizeMb: +(performance.memory.usedJSHeapSize / 1e6).toFixed(1),
        } : null;
        return {
            totalMs: done.at - t0,
            circuitFetchMs: tProving ? tProving - t0 : null,
            proveMs: tProving ? done.at - tProving : done.at - t0,
            proofBytes: done.proofBytes,
            memory,
            events,
        };
    }, { witness: witnessInputs, workerUrl: WORKER_URL, circuitUrl: INTERCEPT_CIRCUIT ? "/crisp_qes_circuit.json" : V2_CIRCUIT_URL });

    console.log(`[run ${i + 1}/${RUNS}] total=${result.totalMs.toFixed(0)}ms prove=${result.proveMs.toFixed(0)}ms proof=${result.proofBytes}B`);
    records.push({ run: i + 1, ...result });
}

const variant = CPU_THROTTLE > 1 ? `${BROWSER}-cpuThrottle${CPU_THROTTLE}` : BROWSER;
const summary = {
    commit: COMMIT,
    host: env,
    target: "browser",
    circuit: "v2",
    browser: BROWSER,
    cpuThrottle: CPU_THROTTLE,
    variant,
    n: records.length,
    runs: records,
    proveMs: stats(records.map((r) => r.proveMs)),
    totalMs: stats(records.map((r) => r.totalMs)),
    proofBytes: records[0]?.proofBytes,
    timestamp: new Date().toISOString(),
};

const ts = summary.timestamp.replace(/[:.]/g, "-");
const out = `/data/Develop/crisp-qes/bench/v2-web-${variant}-${ts}.json`;
writeFileSync(out, JSON.stringify(summary, null, 2));
console.log(`\n[done] -> ${out}`);
console.log(`[summary] prove mean=${summary.proveMs.mean}ms median=${summary.proveMs.median}ms`);

await browser.close();
process.exit(0);
