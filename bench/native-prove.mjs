// Native (Node + bb.js wasm) prover benchmark.
//
// Usage:
//   node bench/native-prove.mjs --threads=1 --runs=5 --label=single
//   node bench/native-prove.mjs --threads=auto --runs=5 --label=multi
//
// Measures, per run:
//   - witnessMs:   Noir.execute() to produce gzip witness
//   - proveMs:     UltraHonkBackend.generateProof()
//   - proofBytes:  raw EVM-flavoured proof length
//   - peakRssMb:   process.memoryUsage().rss sampled @100ms intervals
//
// Writes JSON to bench/native-<label>-<ts>.json. Re-uses /tmp/h artefacts
// produced by the existing e2e flow.

import { readFileSync, writeFileSync } from "node:fs";
import { cpus, totalmem } from "node:os";
import {
    parseP7s,
    findIntermediate,
    buildWitness,
} from "/data/Develop/crisp-qes/packages/sdk/dist/index.js";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";

function arg(name, fallback) {
    const m = process.argv.find((a) => a.startsWith(`--${name}=`));
    return m ? m.slice(name.length + 3) : fallback;
}

const THREADS_RAW = arg("threads", "auto");
const RUNS = parseInt(arg("runs", "5"), 10);
const LABEL = arg("label", THREADS_RAW === "auto" ? "multi" : `t${THREADS_RAW}`);

const COMMIT = arg("commit", "72add5b");
const FIXTURE = "/data/Develop/crisp-qes/fixtures/diia/petition-1-binding.bin.p7s";
const BUNDLE = "/data/Develop/crisp-qes/packages/lotl-flattener/fixtures/diia_ecdsa.p7b";
const MANIFEST = "/tmp/h/trust-manifest.json";
const CIRCUIT_PATH = "/data/Develop/crisp-qes/packages/circuit/target/crisp_qes_circuit.json";

console.log(`[setup] threads=${THREADS_RAW} runs=${RUNS} label=${LABEL}`);
console.log(`[setup] node=${process.version} cpus=${cpus().length} mem=${(totalmem() / 1e9).toFixed(1)}GB`);

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

const circuit = JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));

const records = [];
let peakRss = 0;
const rssTimer = setInterval(() => {
    const r = process.memoryUsage().rss;
    if (r > peakRss) peakRss = r;
}, 100);

for (let i = 0; i < RUNS; i++) {
    const noir = new Noir(circuit);
    const t0 = process.hrtime.bigint();
    const { witness: compressedWitness } = await noir.execute(inputs);
    const t1 = process.hrtime.bigint();

    const beOpts = THREADS_RAW === "auto" ? {} : { threads: parseInt(THREADS_RAW, 10) };
    const api = await Barretenberg.new(beOpts);
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    const t2 = process.hrtime.bigint();
    const { proof } = await backend.generateProof(compressedWitness, { verifierTarget: "evm" });
    const t3 = process.hrtime.bigint();
    await api.destroy();

    const witnessMs = Number(t1 - t0) / 1e6;
    const proveMs = Number(t3 - t2) / 1e6;
    const proofLen = proof.length;
    const rss = process.memoryUsage().rss;

    console.log(`[run ${i + 1}/${RUNS}] witness=${witnessMs.toFixed(0)}ms prove=${proveMs.toFixed(0)}ms proof=${proofLen}B rss=${(rss / 1e6).toFixed(0)}MB`);
    records.push({ run: i + 1, witnessMs, proveMs, proofBytes: proofLen, rssMb: rss / 1e6 });
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
const out = `/data/Develop/crisp-qes/bench/native-${LABEL}-${ts}.json`;
writeFileSync(out, JSON.stringify(summary, null, 2));
console.log(`\n[done] -> ${out}`);
console.log(`[summary] prove mean=${summary.proveMs.mean}ms median=${summary.proveMs.median}ms stddev=${summary.proveMs.stddev}ms peakRss=${summary.peakRssMb}MB`);
process.exit(0);
