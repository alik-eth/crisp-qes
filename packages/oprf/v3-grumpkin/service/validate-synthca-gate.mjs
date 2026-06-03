// TEST-ONLY: validate the synthetic-CA enroll gate end-to-end.
//
// Proves that a SYNTHETIC cert (gen-enroll-commit-v2-witness.mjs) produces an
// enroll_commit_v2 proof that the /v3/blind-eval gate ACCEPTS when the gate is
// pointed at the synth-CA-pinned circuit (ENROLL_GATE_CIRCUIT). This closes the
// "production pins real Diia CA" blocker for the local full-stack E2E.
//
// Flow (all bb.js 4.x):
//   1. build-synthca-circuit.mjs              -> synthca circuit JSON
//   2. gen-enroll-commit-v2-witness.mjs       -> Prover.toml (synth cert)
//   3. copy Prover.toml into the synthca dir; nargo execute -> witness
//   4. bb write_vk + bb prove (PATH bb = 4.x) -> target/{proof,public_inputs}
//   5. buildApp({ gate: createGate(synthcaJson) }) and inject /v3/blind-eval:
//        accept-valid, reject-invalid, reject-mismatched-M.
//
// Run from packages/oprf/v3-grumpkin:  node service/validate-synthca-gate.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildApp } from "./server.mjs";
import { OprfNode } from "./oprf-node.mjs";
import { createGate, PUBLIC_INPUT_WORD_COUNT, M_X_WORD_INDEX } from "./proof-gate.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const PROD_DIR = join(ROOT, "circuits", "enroll_commit_v2");
const SYNTH_DIR = join(ROOT, "circuits", "enroll_commit_v2_synthca");
const SYNTH_TARGET = join(SYNTH_DIR, "target");
const SYNTH_JSON = join(SYNTH_TARGET, "enroll_commit_v2_synthca.json");
const BB = process.env.BB_BIN || "bb";

let failures = 0;
const check = (name, cond, extra) => {
    if (!cond) failures++;
    console.log(`  [${cond ? "PASS" : "FAIL"}] ${name}${extra ? "  — " + extra : ""}`);
};

const readPublicInputWords = (path) => {
    const buf = readFileSync(path);
    const words = [];
    for (let i = 0; i < buf.length; i += 32) words.push("0x" + buf.subarray(i, i + 32).toString("hex"));
    return words;
};
const mWireFromWords = (w) => "0x" + w[M_X_WORD_INDEX].slice(2) + w[M_X_WORD_INDEX + 1].slice(2);

function ensureProof() {
    const proofPath = join(SYNTH_TARGET, "proof");
    const piPath = join(SYNTH_TARGET, "public_inputs");
    if (process.env.SYNTHCA_FRESH !== "1" && existsSync(proofPath) && existsSync(piPath)) {
        return { proofPath, piPath };
    }
    if (!existsSync(SYNTH_JSON)) {
        console.log("  (building synth-CA circuit)");
        execFileSync("node", ["build-synthca-circuit.mjs"], { cwd: ROOT, stdio: "inherit" });
    }
    console.log("  (generating synthetic client proof: witness + nargo execute + bb prove)");
    execFileSync("node", ["gen-enroll-commit-v2-witness.mjs"], { cwd: ROOT, stdio: "inherit" });
    // The witness generator writes Prover.toml into the prod circuit dir; the
    // synth circuit shares identical inputs (same synth cert), so copy it over.
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

async function main() {
    console.log("synthetic-CA enroll gate validation (TEST-ONLY)\n");
    const { proofPath, piPath } = ensureProof();

    const proofBytes = readFileSync(proofPath);
    const proofHex = "0x" + proofBytes.toString("hex");
    const publicInputs = readPublicInputWords(piPath);
    check(`public_inputs has ${PUBLIC_INPUT_WORD_COUNT} words`, publicInputs.length === PUBLIC_INPUT_WORD_COUNT, `got ${publicInputs.length}`);
    const Mhex = mWireFromWords(publicInputs);

    // Gate pinned to the synth-CA circuit (what the harness sets via ENROLL_GATE_CIRCUIT).
    const gate = await createGate(SYNTH_JSON);
    const node = new OprfNode(123456789n);
    const app = await buildApp({ node, gate, logger: false });

    const okRes = await app.inject({ method: "POST", url: "/v3/blind-eval", payload: { M: Mhex, proof: proofHex, publicInputs } });
    check("accept-valid: synth proof + matching M => 200", okRes.statusCode === 200, `status=${okRes.statusCode}`);
    if (okRes.statusCode === 200) {
        const b = okRes.json();
        // Threshold blind-eval returns per-share partials, each with B_i + DLEQ.
        const evaluated = Array.isArray(b.partials) && b.partials.length >= 1 &&
            b.partials.every((p) => typeof p.B_i === "string" && p.dleq && typeof p.dleq.c === "string");
        check("accept-valid: evaluated (threshold partials + DLEQ present)", evaluated, `partials=${b.partials?.length}`);
    } else {
        console.log("   body:", okRes.body?.slice(0, 200));
    }

    const tampered = Buffer.from(proofBytes);
    tampered[Math.floor(tampered.length / 2)] ^= 0xff;
    const badRes = await app.inject({ method: "POST", url: "/v3/blind-eval", payload: { M: Mhex, proof: "0x" + tampered.toString("hex"), publicInputs } });
    check("reject-invalid: tampered proof => 4xx", badRes.statusCode >= 400 && badRes.statusCode < 500, `status=${badRes.statusCode}`);

    await app.close();
    console.log(`\n${failures === 0 ? "ALL PASS" : failures + " FAILURE(S)"} — synth-CA gate ${failures === 0 ? "accepts synthetic certs" : "NOT working"}`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
