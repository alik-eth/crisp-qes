// SKELETON — DO NOT RUN UNTIL #30 (v2 circuit) COMMITS.
//
// v2 native (Node + bb.js wasm) prover benchmark.
//
// Differs from MVP (`native-prove.mjs`) in:
//   - No `parseP7s` / `findIntermediate` / `buildWitness` pipeline. The v2
//     witness is 3 publics + 2 privates (TREE_DEPTH=20 path + index bits).
//     We construct it synthetically here from a hand-pinned secret + an
//     all-zero-sibling Merkle path (matches the in-tree sanity test
//     `end_to_end_sanity_at_depth20`).
//   - Different circuit JSON path.
//   - Public-input order: [petition_id, enrollment_root, nullifier].
//
// Once the v2 SDK lands (TBD), swap the synthetic witness for the
// `buildV2Witness({enrollmentSecret, petitionId, ...})` helper so we
// measure the real production path.
//
// Usage (once unblocked):
//   node bench/v2-native-prove.mjs --threads=auto --runs=5 --label=multi
//   node bench/v2-native-prove.mjs --threads=1 --runs=5 --label=single

import { readFileSync, writeFileSync } from "node:fs";
import { cpus, totalmem } from "node:os";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, BarretenbergSync, UltraHonkBackend } from "@aztec/bb.js";

function arg(name, fallback) {
    const m = process.argv.find((a) => a.startsWith(`--${name}=`));
    return m ? m.slice(name.length + 3) : fallback;
}

const THREADS_RAW = arg("threads", "auto");
const RUNS = parseInt(arg("runs", "5"), 10);
const LABEL = arg("label", THREADS_RAW === "auto" ? "multi" : `t${THREADS_RAW}`);
const COMMIT = arg("commit", "");
const CIRCUIT_PATH = arg(
    "circuit",
    "/data/Develop/crisp-qes/packages/circuit/target/crisp_qes_v2_circuit.json",
);

// TREE_DEPTH = 20 — pinned in packages/circuit/src/main.nr.
// DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31 (ASCII "v2-pen-no1").
const TREE_DEPTH = 20;
const DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31n;

console.log(`[setup] threads=${THREADS_RAW} runs=${RUNS} label=${LABEL}`);
console.log(`[setup] node=${process.version} cpus=${cpus().length} mem=${(totalmem() / 1e9).toFixed(1)}GB`);

const circuit = JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));
console.log(`[setup] circuit=${CIRCUIT_PATH} (${(JSON.parse(readFileSync(CIRCUIT_PATH)).bytecode?.length ?? 0)} ACIR-base64-chars)`);

// ----------------------------------------------------------------------------
// Synthetic witness (matches main.nr `end_to_end_sanity_at_depth20`):
//   - enrollment_secret = 0x42
//   - merkle_path       = [0; TREE_DEPTH]   (all-zero siblings)
//   - merkle_path_indices = [0; TREE_DEPTH] (current is always left child)
//   - petition_id       = 999
//   - enrollment_root   = compute_root_pedersen(s, all_zero_path, indices)
//   - nullifier         = pedersen_hash([s, petition_id, DOMAIN_PETITION_V2])
//
// To compute the root + nullifier off-chain we use BarretenbergSync's
// pedersenHash, which matches Noir's `std::hash::pedersen_hash` with
// hashIndex=0.
// ----------------------------------------------------------------------------

function toFieldHex(v) {
    return "0x" + v.toString(16).padStart(64, "0");
}

function bigintToBE32(v) {
    const out = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) {
        out[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return out;
}

function be32ToBigint(b) {
    let v = 0n;
    for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]);
    return v;
}

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
console.log(`[setup] synthetic witness ready (root=${witnessInputs.enrollment_root.slice(0, 12)}…, null=${witnessInputs.nullifier.slice(0, 12)}…)`);

const records = [];
let peakRss = 0;
const rssTimer = setInterval(() => {
    const r = process.memoryUsage().rss;
    if (r > peakRss) peakRss = r;
}, 100);

for (let i = 0; i < RUNS; i++) {
    const noir = new Noir(circuit);
    const t0 = process.hrtime.bigint();
    const { witness: compressedWitness } = await noir.execute(witnessInputs);
    const t1 = process.hrtime.bigint();

    const beOpts = THREADS_RAW === "auto" ? {} : { threads: parseInt(THREADS_RAW, 10) };
    const beAsync = await Barretenberg.new(beOpts);
    const backend = new UltraHonkBackend(circuit.bytecode, beAsync);
    const t2 = process.hrtime.bigint();
    const { proof } = await backend.generateProof(compressedWitness, { verifierTarget: "evm" });
    const t3 = process.hrtime.bigint();
    await beAsync.destroy();

    const witnessMs = Number(t1 - t0) / 1e6;
    const proveMs = Number(t3 - t2) / 1e6;
    const rss = process.memoryUsage().rss;
    console.log(`[run ${i + 1}/${RUNS}] witness=${witnessMs.toFixed(0)}ms prove=${proveMs.toFixed(0)}ms proof=${proof.length}B rss=${(rss / 1e6).toFixed(0)}MB`);
    records.push({ run: i + 1, witnessMs, proveMs, proofBytes: proof.length, rssMb: rss / 1e6 });
}
clearInterval(rssTimer);

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

const summary = {
    commit: COMMIT,
    host: { node: process.version, platform: process.platform, cpus: cpus().length, memGb: +(totalmem() / 1e9).toFixed(1) },
    target: "node",
    circuit: "v2",
    variant: LABEL,
    threads: THREADS_RAW,
    n: records.length,
    runs: records,
    peakRssMb: +(peakRss / 1e6).toFixed(1),
    witnessMs: stats(records.map((r) => r.witnessMs)),
    proveMs: stats(records.map((r) => r.proveMs)),
    proofBytes: records[0]?.proofBytes,
    timestamp: new Date().toISOString(),
};

const ts = summary.timestamp.replace(/[:.]/g, "-");
const out = `/data/Develop/crisp-qes/bench/v2-native-${LABEL}-${ts}.json`;
writeFileSync(out, JSON.stringify(summary, null, 2));
console.log(`\n[done] -> ${out}`);
console.log(`[summary] prove mean=${summary.proveMs.mean}ms median=${summary.proveMs.median}ms stddev=${summary.proveMs.stddev}ms peakRss=${summary.peakRssMb}MB`);
process.exit(0);
