// Proof-gating test for the v3 Grumpkin VOPRF service (build, unaudited).
//
// Proves the admission gate on POST /v3/blind-eval actually gates on a REAL
// enroll_commit_v2 ZK proof bound to the request's M:
//
//   (a) accept-valid       : a valid proof whose public-output M matches the
//                            request M is accepted and evaluated (200 + Y).
//   (b) reject-invalid     : a tampered/invalid proof is rejected (4xx), no eval.
//   (c) reject-mismatched-M : a VALID proof but a request M that does not equal
//                            the proof's committed M is rejected (4xx).
//
// The real client proof is produced by the existing gen-enroll-commit-v2-witness
// + nargo execute + bb prove flow (run here so the test is self-contained), then
// loaded from circuits/enroll_commit_v2/target/{proof,public_inputs}. The vk is
// derived once by buildApp via `bb write_vk`, exactly as in production.
//
// Run with cwd in v3-grumpkin:  node service/gating-test.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildApp } from "./server.mjs";
import { OprfNode } from "./oprf-node.mjs";
import {
    PUBLIC_INPUT_WORD_COUNT,
    M_X_WORD_INDEX,
} from "./proof-gate.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const CIRCUIT_DIR = join(ROOT, "circuits", "enroll_commit_v2");
const TARGET = join(CIRCUIT_DIR, "target");
const BB = process.env.BB_BIN || "bb";

let failures = 0;
function check(name, cond, extra) {
    const tag = cond ? "PASS" : "FAIL";
    if (!cond) failures++;
    console.log(`  [${tag}] ${name}${extra ? "  — " + extra : ""}`);
}

// Read a flat 32B-BE public_inputs file into an array of 0x-hex field words.
function readPublicInputWords(path) {
    const buf = readFileSync(path);
    const words = [];
    for (let i = 0; i < buf.length; i += 32) {
        words.push("0x" + buf.subarray(i, i + 32).toString("hex"));
    }
    return words;
}

// Build the M wire hex (0x{x:32B}{y:32B}) from the proof's public-input words.
function mWireFromWords(words) {
    const x = words[M_X_WORD_INDEX].slice(2);
    const y = words[M_X_WORD_INDEX + 1].slice(2);
    return "0x" + x + y;
}

function ensureProofArtifacts() {
    const proofPath = join(TARGET, "proof");
    const piPath = join(TARGET, "public_inputs");
    const fresh = process.env.GATING_TEST_FRESH === "1";
    if (!fresh && existsSync(proofPath) && existsSync(piPath)) {
        return { proofPath, piPath };
    }
    console.log("  (generating real client proof: witness + nargo execute + bb write_vk + bb prove)");
    // 1. witness TOML (cwd must be v3-grumpkin for its relative writes).
    execFileSync("node", ["gen-enroll-commit-v2-witness.mjs"], { cwd: ROOT, stdio: "inherit" });
    // 2. solve witness (cwd in the circuit dir; writes target/*.gz).
    execFileSync("nargo", ["execute"], { cwd: CIRCUIT_DIR, stdio: "inherit" });
    // bb resolves ./target/vk relative to its cwd, so run the bb steps WITH cwd
    // in the circuit dir and use circuit-relative paths (matches the manual flow).
    const bbOpts = { cwd: CIRCUIT_DIR, stdio: "inherit" };
    // 3. write_vk (bb prove needs ./target/vk present for this scheme).
    execFileSync(BB, ["write_vk", "-b", "target/enroll_commit_v2.json", "-o", "target"], bbOpts);
    // 4. prove (writes target/{proof,public_inputs}).
    execFileSync(BB, [
        "prove",
        "-b", "target/enroll_commit_v2.json",
        "-w", "target/enroll_commit_v2.gz",
        "-o", "target",
    ], bbOpts);
    return { proofPath, piPath };
}

async function main() {
    console.log("v3 Grumpkin VOPRF proof-gating test (build, unaudited)\n");

    const { proofPath, piPath } = ensureProofArtifacts();

    const proofBytes = readFileSync(proofPath);
    const proofHex = "0x" + proofBytes.toString("hex");
    const publicInputs = readPublicInputWords(piPath);
    check(
        `public_inputs has ${PUBLIC_INPUT_WORD_COUNT} field words`,
        publicInputs.length === PUBLIC_INPUT_WORD_COUNT,
        `got ${publicInputs.length}`,
    );

    const Mhex = mWireFromWords(publicInputs);

    // Node key is irrelevant to gating (proof commits to M, not to the node);
    // use a fixed dev key so the eval path is deterministic.
    const node = new OprfNode(123456789n);
    const app = await buildApp({ node, logger: false });

    // — (a) accept-valid ─────────────────────────────────────────────────
    const okRes = await app.inject({
        method: "POST",
        url: "/v3/blind-eval",
        payload: { M: Mhex, proof: proofHex, publicInputs },
    });
    check(
        "accept-valid: valid proof + matching M => 200",
        okRes.statusCode === 200,
        `status=${okRes.statusCode}`,
    );
    if (okRes.statusCode === 200) {
        const body = okRes.json();
        check(
            "accept-valid: response carries Y + DLEQ (evaluated)",
            typeof body.Y === "string" && body.dleq && typeof body.dleq.c === "string",
        );
        check(
            "accept-valid: proofAccepted reports verified",
            typeof body.proofAccepted === "string" && body.proofAccepted.includes("verified"),
            body.proofAccepted,
        );
    }

    // — (b) reject-invalid ───────────────────────────────────────────────
    // Tamper with the proof bytes (flip a byte in the middle) — same length,
    // same public inputs / M, but bb verify must fail.
    const tampered = Buffer.from(proofBytes);
    const mid = Math.floor(tampered.length / 2);
    tampered[mid] ^= 0xff;
    const tamperedHex = "0x" + tampered.toString("hex");
    const badRes = await app.inject({
        method: "POST",
        url: "/v3/blind-eval",
        payload: { M: Mhex, proof: tamperedHex, publicInputs },
    });
    check(
        "reject-invalid: tampered proof => 4xx",
        badRes.statusCode >= 400 && badRes.statusCode < 500,
        `status=${badRes.statusCode} body=${JSON.stringify(badRes.json())}`,
    );

    // — (c) reject-mismatched-M ──────────────────────────────────────────
    // VALID proof + valid public inputs, but the request M points elsewhere on
    // the curve. The M-binding check must reject before/independent of crypto.
    // Use the node's own Kpub (a guaranteed valid on-curve point != M).
    const otherM = node.publicKeyHex();
    check("mismatched-M setup: chosen M differs from proof M", otherM !== Mhex);
    const mismatchRes = await app.inject({
        method: "POST",
        url: "/v3/blind-eval",
        payload: { M: otherM, proof: proofHex, publicInputs },
    });
    check(
        "reject-mismatched-M: valid proof but wrong M => 4xx",
        mismatchRes.statusCode >= 400 && mismatchRes.statusCode < 500,
        `status=${mismatchRes.statusCode} body=${JSON.stringify(mismatchRes.json())}`,
    );
    if (mismatchRes.statusCode >= 400 && mismatchRes.statusCode < 500) {
        check(
            "reject-mismatched-M: error code is ProofMismatchedM",
            mismatchRes.json().error === "ProofMismatchedM",
            mismatchRes.json().error,
        );
    }

    await app.close();

    console.log("");
    if (failures === 0) {
        console.log("ALL GATING CHECKS PASS");
        process.exit(0);
    } else {
        console.log(`${failures} GATING CHECK(S) FAILED`);
        process.exit(1);
    }
}

main().catch((e) => {
    console.error("gating-test crashed:", e);
    process.exit(1);
});
