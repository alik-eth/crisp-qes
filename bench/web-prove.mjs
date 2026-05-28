// Browser/WASM prover benchmark via Playwright.
//
// Bypasses the UI gates by spawning the live web app's own prove worker
// directly. We:
//   1. Build the witness in Node (same SDK as native bench).
//   2. Navigate to https://crisp-qes-web.fly.dev/ so the page inherits
//      the production COOP/COEP headers, MIME types, asset URLs, and the
//      same bundled @aztec/bb.js + @noir-lang/noir_js.
//   3. In the page context: spawn `new Worker("/assets/prove.worker-*.js",
//      { type: "module" })`, post a {type:"prove", witness, circuitUrl}
//      message, and time the round-trip until the worker posts
//      {type:"done"}.
//
// Output: bench/web-<browser>[-<device>]-<ts>.json with per-run prove
// timings and (Chromium) JS heap usage.
//
// Usage:
//   node bench/web-prove.mjs --runs=3 --browser=chromium
//   node bench/web-prove.mjs --runs=2 --browser=chromium --device="Pixel 7"
//   node bench/web-prove.mjs --runs=2 --browser=firefox

import { readFileSync, writeFileSync } from "node:fs";
import { chromium, firefox, devices } from "playwright";
import {
    parseP7s,
    findIntermediate,
    buildWitness,
} from "/data/Develop/crisp-qes/packages/sdk/dist/index.js";

function arg(name, fallback) {
    const m = process.argv.find((a) => a.startsWith(`--${name}=`));
    return m ? m.slice(name.length + 3) : fallback;
}

const RUNS = parseInt(arg("runs", "3"), 10);
const BROWSER = arg("browser", "chromium");
const DEVICE = arg("device", "");
const URL_BASE = arg("url", "https://crisp-qes-web.fly.dev");
const FIXTURE = arg("fixture", "/data/Develop/crisp-qes/fixtures/diia/petition-1-binding.bin.p7s");
const BUNDLE = arg("bundle", "/data/Develop/crisp-qes/packages/lotl-flattener/fixtures/diia_ecdsa.p7b");
const MANIFEST = arg("manifest", "/tmp/h/trust-manifest.json");
const COMMIT = arg("commit", "72add5b");

// -- 1. Build witness inputs in Node (one-time, reused across runs).
const parsed = parseP7s(new Uint8Array(readFileSync(FIXTURE)));
const bundleBytes = new Uint8Array(readFileSync(BUNDLE));
const manifestJson = JSON.parse(readFileSync(MANIFEST, "utf-8"));
const found = await findIntermediate(parsed, manifestJson, { bundleP7b: bundleBytes });
const { inputs } = await buildWitness({
    parsed,
    petitionId: 1n,
    petitionTextHash: Uint8Array.from(Buffer.from("6f65ef78e220476ca74bb7392dc4006099c54ce3e99f99c73b25d1f0ad8ae78f", "hex")),
    trustRoot: BigInt("0x0dc4f2d069e7daddf6891d00dd2bb77880ad5dc65b3d39bd1d2781afb85e6f53"),
    merklePath: found.merklePath,
    merklePathIndices: found.merklePathIndices,
    intermediate: {
        spkiDer: found.intermediateSpkiDer,
        pubkey: found.intermediatePubkey,
        pubkeyOffset: found.intermediatePubkeyOffset,
    },
});
console.log("[setup] witness inputs built");

// -- 2. Locate the live worker bundle URL (hash-based).
const indexHtml = await (await fetch(URL_BASE + "/")).text();
const indexJsMatch = indexHtml.match(/\/assets\/index-[A-Za-z0-9_-]+\.js/);
if (!indexJsMatch) throw new Error("could not find index-*.js asset URL");
const indexJs = await (await fetch(URL_BASE + indexJsMatch[0])).text();
const workerMatch = indexJs.match(/prove\.worker-[A-Za-z0-9_-]+\.js/);
if (!workerMatch) throw new Error("could not find prove.worker-*.js URL");
const WORKER_URL = "/assets/" + workerMatch[0];
console.log(`[setup] worker URL: ${WORKER_URL}`);

// -- 3. Launch browser.
const launcher = BROWSER === "firefox" ? firefox : chromium;
const browser = await launcher.launch({ headless: true });
const contextOpts = { viewport: { width: 1400, height: 900 } };
if (DEVICE) {
    if (!devices[DEVICE]) {
        throw new Error(`unknown device: ${DEVICE}. Known: ${Object.keys(devices).slice(0, 8).join(", ")}, ...`);
    }
    Object.assign(contextOpts, devices[DEVICE]);
}
const ctx = await browser.newContext(contextOpts);
const page = await ctx.newPage();

// CDP for CPU throttling (mobile emulation) and process-level memory.
const CPU_THROTTLE = parseFloat(arg("cpuThrottle", "1"));
let cdp = null;
if (BROWSER === "chromium") {
    cdp = await ctx.newCDPSession(page);
    if (CPU_THROTTLE > 1) {
        await cdp.send("Emulation.setCPUThrottlingRate", { rate: CPU_THROTTLE });
        console.log(`[setup] CPU throttled ${CPU_THROTTLE}x`);
    }
    await cdp.send("Performance.enable");
}

async function browserProcMemMb() {
    if (!cdp) return null;
    try {
        const { metrics } = await cdp.send("Performance.getMetrics");
        const map = Object.fromEntries(metrics.map((m) => [m.name, m.value]));
        return {
            jsHeapUsedMb: map.JSHeapUsedSize ? +(map.JSHeapUsedSize / 1e6).toFixed(1) : null,
            jsHeapTotalMb: map.JSHeapTotalSize ? +(map.JSHeapTotalSize / 1e6).toFixed(1) : null,
            processMemMb: map.ProcessTime ? null : null, // not available; see ProcessMemoryInfo on supported builds
        };
    } catch { return null; }
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
    // Each run uses a fresh page so the bb.js wasm gets initialised cold,
    // matching the real user experience (first-time vs warm cache).
    if (i > 0) {
        await page.goto(URL_BASE + "/", { waitUntil: "domcontentloaded" });
    }

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
            totalJSHeapSizeMb: +(performance.memory.totalJSHeapSize / 1e6).toFixed(1),
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
    }, { witness: inputs, workerUrl: WORKER_URL, circuitUrl: "/crisp_qes_circuit.json" });

    // Worker memory peaks during prove; sample process-wide via CDP just
    // after `done` so we still catch the high-water mark before GC.
    const procMem = await browserProcMemMb();
    const memStr = result.memory ? `usedJSHeap=${result.memory.usedJSHeapSizeMb}MB cdpHeap=${procMem?.jsHeapUsedMb}MB` : "memory=n/a";
    console.log(`[run ${i + 1}/${RUNS}] total=${result.totalMs.toFixed(0)}ms prove=${result.proveMs.toFixed(0)}ms circuit=${result.circuitFetchMs?.toFixed(0) ?? "n/a"}ms proof=${result.proofBytes}B ${memStr}`);
    records.push({ run: i + 1, ...result, procMem });
}

const variant = DEVICE ? `${BROWSER}-${DEVICE.replace(/\s+/g, "")}` : BROWSER;
const summary = {
    commit: COMMIT,
    host: env,
    target: "browser",
    browser: BROWSER,
    device: DEVICE || null,
    cpuThrottle: CPU_THROTTLE,
    variant,
    n: records.length,
    runs: records,
    proveMs: stats(records.map((r) => r.proveMs)),
    totalMs: stats(records.map((r) => r.totalMs)),
    peakUsedJSHeapMb: records.reduce((m, r) => Math.max(m, r.memory?.usedJSHeapSizeMb ?? 0), 0),
    proofBytes: records[0]?.proofBytes,
    timestamp: new Date().toISOString(),
};

const ts = summary.timestamp.replace(/[:.]/g, "-");
const out = `/data/Develop/crisp-qes/bench/web-${variant}-${ts}.json`;
writeFileSync(out, JSON.stringify(summary, null, 2));
console.log(`\n[done] -> ${out}`);
console.log(`[summary] prove mean=${summary.proveMs.mean}ms median=${summary.proveMs.median}ms stddev=${summary.proveMs.stddev}ms peakJSHeap=${summary.peakUsedJSHeapMb}MB`);

await browser.close();
process.exit(0);
