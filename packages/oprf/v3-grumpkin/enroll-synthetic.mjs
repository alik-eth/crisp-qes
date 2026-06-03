// ENROLLMENT-PHASE orchestrator for the local CRISP-QES E2E (bb.js 4.x).
//
// Runs the REAL 2-of-3 threshold enrollment over a SYNTHETIC cert and emits an
// enrollment-artifact JSON the vote phase consumes. Everything here is bb.js 4.x
// (PATH `bb`); this does NOT touch the vote SDK (separate 3.x process).
//
// FLOW (one node process):
//   1. ensure the synth-CA-pinned enroll_commit_v2 circuit is built.
//   2. gen the enroll witness over the SYNTH cert, prove it -> M, C_r, proof.
//   3. POST /v3/blind-eval (REAL 3-node threshold app via app.inject) -> partials
//      (B_i + per-share DLEQ), epoch, publishedKpubSet.
//   4. build the THRESHOLD oprf_nullifier witness from the REAL response, prove
//      it -> nullifier (public word 12) == the enrollment leaf/commitment s.
//   5. POST /v3/register -> leafIndex, merklePath, roots, attesterSig.
//   6. VALIDATE: rootFromPath(s, path, indices) == newRoot; s == nullifier;
//      publishedKpubSet has 3 entries.
//   7. write the artifact JSON (env ENROLLMENT_OUT, default ./enrollment-artifact.json).
//
// TRANSPORT is thin + swappable: the core logic takes an `inject(req)->res`
// adapter; main() wires it to buildApp + app.inject (in-process, no HTTP, no
// chain). A later task points the same adapter at an HTTP base URL + real chain.
//
// SYNTHETIC CA / dev keys only. Run with cwd in packages/oprf/v3-grumpkin:
//   node enroll-synthetic.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildApp } from "./service/server.mjs";
import { createGate } from "./service/proof-gate.mjs";
import { pointFromHex } from "./service/oprf-node.mjs";
import { rootFromPath } from "./service/merkle.mjs";
import { Fn, N, scalarLimbs } from "./lib.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = __dirname; // packages/oprf/v3-grumpkin
const PROD_DIR = join(ROOT, "circuits", "enroll_commit_v2");
const SYNTH_DIR = join(ROOT, "circuits", "enroll_commit_v2_synthca");
const SYNTH_TARGET = join(SYNTH_DIR, "target");
const SYNTH_JSON = join(SYNTH_TARGET, "enroll_commit_v2_synthca.json");
const NULLIFIER_DIR = join(ROOT, "circuits", "oprf_nullifier");
const NULLIFIER_TARGET = join(NULLIFIER_DIR, "target");
const NULLIFIER_JSON = join(NULLIFIER_TARGET, "oprf_nullifier.json");

const BB = process.env.BB_BIN || "bb";
const ENROLLMENT_OUT = process.env.ENROLLMENT_OUT || join(ROOT, "enrollment-artifact.json");

// Public-input word indices (mirror service/proof-gate.mjs).
const ENROLL_M_X_WORD = 8;
const ENROLL_C_R_WORD = 10;
const ENROLL_WORD_COUNT = 13;
const THR_NULLIFIER_WORD = 12;
const THR_WORD_COUNT = 13;

// — small helpers ────────────────────────────────────────────────────────────

const hex32 = (v) => "0x" + v.toString(16).padStart(64, "0");

function readPublicInputWords(path) {
    const buf = readFileSync(path);
    const words = [];
    for (let i = 0; i < buf.length; i += 32) {
        words.push("0x" + buf.subarray(i, i + 32).toString("hex"));
    }
    return words;
}

// M wire format = 0x{x:32B}{y:32B} from the enroll public words [8],[9].
const mWireFromWords = (w) => "0x" + w[ENROLL_M_X_WORD].slice(2) + w[ENROLL_M_X_WORD + 1].slice(2);

// — step 1+2: build synth circuit + produce the enroll proof over the synth cert ─

function ensureEnrollProof() {
    const proofPath = join(SYNTH_TARGET, "proof");
    const piPath = join(SYNTH_TARGET, "public_inputs");
    if (process.env.ENROLL_FRESH !== "1" && existsSync(proofPath) && existsSync(piPath)) {
        return { proofPath, piPath };
    }
    if (!existsSync(SYNTH_JSON)) {
        console.log("  [enroll] building synth-CA circuit");
        execFileSync("node", ["build-synthca-circuit.mjs"], { cwd: ROOT, stdio: "inherit" });
    }
    console.log("  [enroll] gen witness + nargo execute + bb prove (synth cert)");
    execFileSync("node", ["gen-enroll-commit-v2-witness.mjs"], { cwd: ROOT, stdio: "inherit" });
    // The generator writes into the prod circuit dir; the synth circuit shares
    // identical inputs (same synth cert), so copy Prover.toml over.
    copyFileSync(join(PROD_DIR, "Prover.toml"), join(SYNTH_DIR, "Prover.toml"));
    execFileSync("nargo", ["execute"], { cwd: SYNTH_DIR, stdio: "inherit" });
    const bbOpts = { cwd: SYNTH_DIR, stdio: "inherit" };
    execFileSync(BB, ["write_vk", "-b", "target/enroll_commit_v2_synthca.json", "-o", "target"], bbOpts);
    execFileSync(BB, [
        "prove",
        "-b", "target/enroll_commit_v2_synthca.json",
        "-w", "target/enroll_commit_v2_synthca.gz",
        "-o", "target",
    ], bbOpts);
    return { proofPath, piPath };
}

// — step 4: build the threshold nullifier witness from the REAL service response ─
//
// The 13-word public layout (ABI order) + the 28 private/limb fields the circuit
// consumes. The circuit itself does the Lagrange combine + nullifier=pedersen(N),
// so we only supply M / Kpub-set / idx / epoch / c_r and the responders' raw
// B_i + DLEQ limbs + r/rinv limbs; the nullifier is READ from the proof output.
function writeNullifierToml({ Maff, kpubSet, idx1, idx2, epoch, cR, Ba, Bb, Da, Db, r, rinv }) {
    const DaL = { c: scalarLimbs(Da.c), z: scalarLimbs(Da.z) };
    const DbL = { c: scalarLimbs(Db.c), z: scalarLimbs(Db.z) };
    const rL = scalarLimbs(r);
    const riL = scalarLimbs(rinv);
    const d = (v) => v.toString();
    const toml = `# auto-generated by enroll-synthetic.mjs (threshold register, REAL service partials)
# 13-word public layout: mx[0] my[1] kp1x[2] kp1y[3] kp2x[4] kp2y[5] kp3x[6]
#   kp3y[7] idx1[8] idx2[9] epoch[10] c_r[11], return nullifier[12].
mx = "${d(Maff.x)}"
my = "${d(Maff.y)}"
kp1x = "${d(kpubSet[0].x)}"
kp1y = "${d(kpubSet[0].y)}"
kp2x = "${d(kpubSet[1].x)}"
kp2y = "${d(kpubSet[1].y)}"
kp3x = "${d(kpubSet[2].x)}"
kp3y = "${d(kpubSet[2].y)}"
idx1 = "${d(idx1)}"
idx2 = "${d(idx2)}"
epoch = "${d(epoch)}"
c_r = "${d(cR)}"
bax = "${d(Ba.x)}"
bay = "${d(Ba.y)}"
bbx = "${d(Bb.x)}"
bby = "${d(Bb.y)}"
ca_lo = "${d(DaL.c.lo)}"
ca_hi = "${d(DaL.c.hi)}"
za_lo = "${d(DaL.z.lo)}"
za_hi = "${d(DaL.z.hi)}"
cb_lo = "${d(DbL.c.lo)}"
cb_hi = "${d(DbL.c.hi)}"
zb_lo = "${d(DbL.z.lo)}"
zb_hi = "${d(DbL.z.hi)}"
r_lo = "${d(rL.lo)}"
r_hi = "${d(rL.hi)}"
rinv_lo = "${d(riL.lo)}"
rinv_hi = "${d(riL.hi)}"
`;
    writeFileSync(join(NULLIFIER_DIR, "Prover.toml"), toml);
}

function proveNullifier() {
    execFileSync("nargo", ["execute"], { cwd: NULLIFIER_DIR, stdio: "inherit" });
    const bbOpts = { cwd: NULLIFIER_DIR, stdio: "inherit" };
    execFileSync(BB, ["write_vk", "-b", "target/oprf_nullifier.json", "-o", "target"], bbOpts);
    execFileSync(BB, [
        "prove",
        "-b", "target/oprf_nullifier.json",
        "-w", "target/oprf_nullifier.gz",
        "-o", "target",
    ], bbOpts);
    return {
        proofPath: join(NULLIFIER_TARGET, "proof"),
        piPath: join(NULLIFIER_TARGET, "public_inputs"),
    };
}

// — the transport-agnostic enrollment orchestration ──────────────────────────
//
// `inject(req)->Promise<res>` is the thin swappable transport. `res` must expose
// { statusCode:number, json():object } (Fastify app.inject's shape). A later HTTP
// adapter just needs to return the same shape. No chain access happens here; the
// service's attester signs in-process and merkle is in-memory (demo).
export async function runEnrollment({ inject }) {
    // — step 2: enroll proof over the synth cert ──────────────────────────────
    console.log("[1/5] enroll proof (synthetic cert)");
    const { proofPath, piPath } = ensureEnrollProof();
    const enrollProofHex = "0x" + readFileSync(proofPath).toString("hex");
    const enrollPublicInputs = readPublicInputWords(piPath);
    if (enrollPublicInputs.length !== ENROLL_WORD_COUNT) {
        throw new Error(`enroll public_inputs: expected ${ENROLL_WORD_COUNT} words, got ${enrollPublicInputs.length}`);
    }
    const Mhex = mWireFromWords(enrollPublicInputs);
    const Mpoint = pointFromHex(Mhex);
    const Maff = Mpoint.toAffine();
    const cR = BigInt(enrollPublicInputs[ENROLL_C_R_WORD]);
    // The blind r is the same deterministic value the witness generator uses;
    // rinv = r^-1 mod N. Both proofs share r (bound on-chain by C_r, F2).
    const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;
    const r = det("crisp-qes-test-r");
    const rinv = Fn.inv(Fn.create(r));

    // — step 3: REAL threshold blind-eval ─────────────────────────────────────
    console.log("[2/5] POST /v3/blind-eval (3-node threshold)");
    const beRes = await inject({
        method: "POST",
        url: "/v3/blind-eval",
        payload: { M: Mhex, proof: enrollProofHex, publicInputs: enrollPublicInputs },
    });
    if (beRes.statusCode !== 200) {
        throw new Error(`blind-eval failed: status=${beRes.statusCode} body=${JSON.stringify(beRes.json?.() ?? beRes.body)?.slice?.(0, 300)}`);
    }
    const be = beRes.json();
    // WIRE: { partials:[{ i, B_i, dleq:{c,z}, Kpub_i }], epoch, publishedKpubSet:[{i,Kpub_i}] }
    //   B_i / Kpub_i: 0x{x:32B}{y:32B} hex (pointFromHex / pointToHex).
    //   dleq.c / dleq.z: DECIMAL strings (group-order scalars < N).
    //   epoch: DECIMAL string (the threshold session tag).
    if (!Array.isArray(be.publishedKpubSet) || be.publishedKpubSet.length !== 3) {
        throw new Error(`expected 3 publishedKpubSet entries, got ${be.publishedKpubSet?.length}`);
    }
    const epoch = BigInt(be.epoch);
    // Published Kpub set parsed to affine x,y in index order 1,2,3.
    const kpubSet = be.publishedKpubSet
        .slice()
        .sort((a, b) => Number(a.i) - Number(b.i))
        .map((p) => pointFromHex(p.Kpub_i).toAffine());

    // Pick responders idx1=1, idx2=2; take their partials' B_i + DLEQ.
    const byIdx = new Map(be.partials.map((p) => [Number(p.i), p]));
    const idx1 = 1n, idx2 = 2n;
    const pa = byIdx.get(1), pb = byIdx.get(2);
    if (!pa || !pb) throw new Error(`expected partials for responders 1 and 2, got [${[...byIdx.keys()].join(",")}]`);
    const Ba = pointFromHex(pa.B_i).toAffine();
    const Bb = pointFromHex(pb.B_i).toAffine();
    const Da = { c: BigInt(pa.dleq.c), z: BigInt(pa.dleq.z) };
    const Db = { c: BigInt(pb.dleq.c), z: BigInt(pb.dleq.z) };

    // — step 4: threshold nullifier witness + proof ───────────────────────────
    console.log("[3/5] threshold oprf_nullifier proof");
    if (!existsSync(NULLIFIER_JSON)) {
        execFileSync("nargo", ["compile"], { cwd: NULLIFIER_DIR, stdio: "inherit" });
    }
    writeNullifierToml({ Maff, kpubSet, idx1, idx2, epoch, cR, Ba, Bb, Da, Db, r, rinv });
    const { proofPath: nProofPath, piPath: nPiPath } = proveNullifier();
    const nullifierProofHex = "0x" + readFileSync(nProofPath).toString("hex");
    const nullifierPublicInputs = readPublicInputWords(nPiPath);
    if (nullifierPublicInputs.length !== THR_WORD_COUNT) {
        throw new Error(`nullifier public_inputs: expected ${THR_WORD_COUNT} words, got ${nullifierPublicInputs.length}`);
    }
    // The nullifier = public word 12; the enrollment leaf/commitment s == this.
    const s = BigInt(nullifierPublicInputs[THR_NULLIFIER_WORD]);
    const commitment = hex32(s);

    // — step 5: REAL /v3/register ─────────────────────────────────────────────
    console.log("[4/5] POST /v3/register");
    const regRes = await inject({
        method: "POST",
        url: "/v3/register",
        payload: {
            commitment,
            enrollProof: enrollProofHex,
            enrollPublicInputs,
            nullifierProof: nullifierProofHex,
            nullifierPublicInputs,
        },
    });
    if (regRes.statusCode !== 200) {
        throw new Error(`register failed: status=${regRes.statusCode} body=${JSON.stringify(regRes.json?.() ?? regRes.body)?.slice?.(0, 400)}`);
    }
    const reg = regRes.json();
    // WIRE: { leafIndex, merklePath:[0x..], merklePathIndices:[int], oldRoot, newRoot,
    //         newCommitments:[0x..], attesterSig, attesterAddr, ... }
    return {
        s,
        commitment,
        leafIndex: reg.leafIndex,
        merklePath: reg.merklePath,
        merklePathIndices: reg.merklePathIndices,
        oldRoot: reg.oldRoot,
        newRoot: reg.newRoot,
        newCommitments: reg.newCommitments,
        attesterSig: reg.attesterSig,
        attesterAddr: reg.attesterAddr,
        publishedKpubSet: be.publishedKpubSet,
    };
}

// — step 6: validation ───────────────────────────────────────────────────────
async function validate(result) {
    console.log("[5/5] validation");
    let failures = 0;
    const check = (name, cond, extra) => {
        if (!cond) failures++;
        console.log(`  [${cond ? "PASS" : "FAIL"}] ${name}${extra ? "  — " + extra : ""}`);
    };

    // (a) the returned merklePath reproduces newRoot for leaf s.
    const path = result.merklePath.map((h) => BigInt(h));
    const recomputed = await rootFromPath(result.s, path, result.merklePathIndices);
    check(
        "rootFromPath(s, merklePath, indices) == newRoot",
        hex32(recomputed) === result.newRoot.toLowerCase(),
        `recomputed=${hex32(recomputed)} newRoot=${result.newRoot}`,
    );
    // (b) s == nullifier word (it is, by construction; assert the leaf carried it).
    check(
        "commitment leaf == nullifier word",
        result.commitment.toLowerCase() === hex32(result.s).toLowerCase() &&
            (result.newCommitments?.[0]?.toLowerCase?.() === result.commitment.toLowerCase()),
        `commitment=${result.commitment}`,
    );
    // (c) publishedKpubSet has 3 entries.
    check("publishedKpubSet has 3 entries", result.publishedKpubSet?.length === 3,
        `len=${result.publishedKpubSet?.length}`);

    return failures;
}

// — step 7: artifact emission ────────────────────────────────────────────────
function writeArtifact(result) {
    const artifact = {
        s: hex32(result.s),
        leafIndex: result.leafIndex,
        merklePath: result.merklePath,
        merklePathIndices: result.merklePathIndices,
        enrollmentRoot: result.newRoot,
        oldRoot: result.oldRoot,
        newCommitments: [hex32(result.s)],
        attesterSig: result.attesterSig,
    };
    writeFileSync(ENROLLMENT_OUT, JSON.stringify(artifact, null, 2) + "\n");
    return artifact;
}

// HTTP transport: same { statusCode, json() } shape as Fastify app.inject, but
// over fetch to a separately-booted OPRF service (set OPRF_URL). Used by the
// harness; the service there owns the synth-CA gate via ENROLL_GATE_CIRCUIT.
function httpInject(baseUrl) {
    const base = baseUrl.replace(/\/+$/, "");
    return async ({ method, url, payload }) => {
        const res = await fetch(base + url, {
            method,
            headers: { "content-type": "application/json" },
            body: payload != null ? JSON.stringify(payload) : undefined,
        });
        const text = await res.text();
        return { statusCode: res.status, json: () => JSON.parse(text), body: text };
    };
}

// — main: HTTP (OPRF_URL) against a booted service, else in-process buildApp ───
async function main() {
    const OPRF_URL = process.env.OPRF_URL;
    console.log(
        `CRISP-QES enrollment orchestrator (synthetic cert, ${OPRF_URL ? "HTTP " + OPRF_URL : "in-process"})\n`,
    );

    // The prover always needs the synth-CA circuit locally (nargo execute + bb prove).
    if (!existsSync(SYNTH_JSON)) {
        console.log("  (building synth-CA circuit)");
        execFileSync("node", ["build-synthca-circuit.mjs"], { cwd: ROOT, stdio: "inherit" });
    }

    let app = null;
    let inject;
    if (OPRF_URL) {
        inject = httpInject(OPRF_URL);
    } else {
        // In-process: gate pinned to the synth-CA circuit; real 3-node threshold
        // app (dev seeds OK), merkle in-memory (leaves:[] => syncCfg=null).
        const gate = await createGate(SYNTH_JSON);
        app = await buildApp({ gate, leaves: [], logger: false });
        inject = (req) => app.inject(req);
    }

    let failures = 1;
    try {
        const result = await runEnrollment({ inject });
        failures = await validate(result);
        if (failures === 0) {
            const artifact = writeArtifact(result);
            const trunc = (h) => (typeof h === "string" && h.length > 18 ? h.slice(0, 10) + "…" + h.slice(-6) : h);
            console.log(`\nartifact -> ${ENROLLMENT_OUT}`);
            console.log(
                `  s=${trunc(artifact.s)} leafIndex=${artifact.leafIndex} ` +
                `root=${trunc(artifact.enrollmentRoot)} path=${artifact.merklePath.length} sibs ` +
                `sig=${trunc(artifact.attesterSig)}`,
            );
        }
    } finally {
        if (app) await app.close();
    }

    console.log(`\n${failures === 0 ? "ALL PASS — enrollment artifact written" : failures + " VALIDATION FAILURE(S)"}`);
    process.exit(failures === 0 ? 0 : 1);
}

const isMain =
    import.meta.url === `file://${process.argv[1]}` ||
    process.argv[1]?.endsWith("enroll-synthetic.mjs");
if (isMain) main().catch((e) => { console.error(e); process.exit(1); });
