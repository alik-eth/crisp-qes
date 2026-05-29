// v2 prover memory-floor sweep.
//
// Question: how much WASM linear memory does the v2 sign/revoke proof
// actually need? The browser prover runs bb.js's threaded WASM backend,
// which reserves `memory.maximum` up front; iOS Safari refuses a >~1 GiB
// reservation. We cap it on iOS — this finds the smallest cap that still
// lets `generateProof` succeed, so we know whether 512 MiB is enough.
//
// Method: hold threads fixed, step memory.maximum (in WASM pages, 64 KiB
// each) from high to low. node's bb.js uses the same WASM prover; if the
// cap is below the working set, grow() fails and generateProof throws.
// The smallest cap that still proves = the floor. We also sample peak
// RSS + arrayBuffers for color.
//
// Usage:
//   node bench/v2-mem-floor.mjs --threads=2
//   node bench/v2-mem-floor.mjs --threads=2 --pages=4096,6144,8192,10240,12288,16384

import { readFileSync, writeFileSync } from "node:fs";
import { cpus, totalmem } from "node:os";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, BarretenbergSync, UltraHonkBackend } from "@aztec/bb.js";

function arg(name, fallback) {
    const m = process.argv.find((a) => a.startsWith(`--${name}=`));
    return m ? m.slice(name.length + 3) : fallback;
}

const THREADS = parseInt(arg("threads", "2"), 10);
const PAGES = arg("pages", "16384,12288,10240,8192,6144,5120,4096,3072")
    .split(",")
    .map((s) => parseInt(s, 10));
const CIRCUIT_PATH = arg(
    "circuit",
    "/data/Develop/crisp-qes/packages/web/public/crisp_qes_v2_circuit.json",
);
const PAGE_BYTES = 65536;

console.log(`[setup] threads=${THREADS} node=${process.version} cpus=${cpus().length} mem=${(totalmem() / 1e9).toFixed(1)}GB`);
console.log(`[setup] sweep pages=${PAGES.join(",")} (${PAGES.map((p) => (p * PAGE_BYTES) / 1048576 + "MiB").join(", ")})`);

const circuit = JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));

// --- synthetic witness (matches main.nr end_to_end_sanity_at_depth20) ---
const TREE_DEPTH = 20;
const DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31n;
const toFieldHex = (v) => "0x" + v.toString(16).padStart(64, "0");
const bigintToBE32 = (v) => {
    const out = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    return out;
};
const be32ToBigint = (b) => { let v = 0n; for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]); return v; };

const sync = await BarretenbergSync.initSingleton();
const pedersen = (fields) => be32ToBigint(sync.pedersenHash({ inputs: fields.map(bigintToBE32), hashIndex: 0 }).hash);

const SECRET = 0x42n, PETITION_ID = 999n;
const PATH = Array(TREE_DEPTH).fill(0n), INDICES = Array(TREE_DEPTH).fill(0);
let cur = SECRET;
for (let i = 0; i < TREE_DEPTH; i++) cur = pedersen([cur, PATH[i]]);
const witnessInputs = {
    enrollment_secret: toFieldHex(SECRET),
    merkle_path: PATH.map(toFieldHex),
    merkle_path_indices: INDICES.map((i) => i.toString(10)),
    petition_id: toFieldHex(PETITION_ID),
    enrollment_root: toFieldHex(cur),
    nullifier: toFieldHex(pedersen([SECRET, PETITION_ID, DOMAIN_PETITION_V2])),
};

const noir = new Noir(circuit);
const { witness } = await noir.execute(witnessInputs);
console.log(`[setup] witness ready, sweeping ${PAGES.length} caps\n`);

const results = [];
for (const pages of PAGES) {
    const mib = (pages * PAGE_BYTES) / 1048576;
    let peakRss = 0, peakAb = 0;
    const sampler = setInterval(() => {
        const m = process.memoryUsage();
        if (m.rss > peakRss) peakRss = m.rss;
        if (m.arrayBuffers > peakAb) peakAb = m.arrayBuffers;
    }, 25);
    let ok = false, ms = 0, err = "";
    try {
        const api = await Barretenberg.new({ threads: THREADS, memory: { maximum: pages } });
        const backend = new UltraHonkBackend(circuit.bytecode, api);
        const t0 = process.hrtime.bigint();
        const { proof } = await backend.generateProof(witness, { verifierTarget: "evm" });
        ms = Number(process.hrtime.bigint() - t0) / 1e6;
        ok = proof.length > 0;
        await api.destroy();
    } catch (e) {
        err = e instanceof Error ? e.message : String(e);
    }
    clearInterval(sampler);
    const row = { pages, mib, ok, proveMs: +ms.toFixed(0), peakRssMb: +(peakRss / 1e6).toFixed(0), peakArrayBufMb: +(peakAb / 1e6).toFixed(0), err: err.slice(0, 120) };
    results.push(row);
    console.log(`[cap ${mib}MiB / ${pages}p] ${ok ? "OK  " : "FAIL"} prove=${row.proveMs}ms peakRSS=${row.peakRssMb}MB peakArrayBuf=${row.peakArrayBufMb}MB ${err ? "err=" + row.err : ""}`);
}

const okCaps = results.filter((r) => r.ok).map((r) => r.mib);
const floor = okCaps.length ? Math.min(...okCaps) : null;
console.log(`\n[floor] smallest cap that proved: ${floor === null ? "NONE in sweep" : floor + " MiB"}`);
console.log(`[note] iOS default cap = 1024 MiB; current code caps iOS to 512 MiB`);

const summary = { threads: THREADS, circuit: "v2 (sign/revoke share it)", results, floorMib: floor, timestamp: new Date().toISOString() };
const ts = summary.timestamp.replace(/[:.]/g, "-");
const out = `/data/Develop/crisp-qes/bench/v2-mem-floor-t${THREADS}-${ts}.json`;
writeFileSync(out, JSON.stringify(summary, null, 2));
console.log(`[done] -> ${out}`);
process.exit(0);
