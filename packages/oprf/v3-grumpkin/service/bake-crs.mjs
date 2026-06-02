// Build-time CRS pre-bake + in-image smoke test for the v3 Grumpkin VOPRF gate.
//
// Runs ONE real in-process UltraHonk verify (via @aztec/bb.js, no `bb` CLI)
// against the committed THRESHOLD oprf_nullifier circuit + its test proof. This
// forces the verifier to download exactly the structured-reference-string slice
// it needs (~8MB bn254_g1.dat) into CRS_PATH so the running container never
// reaches out to crs.aztec.network at request time. It also doubles as a smoke
// test that the in-process gate works inside the image. Exits non-zero on failure.
//
// NOTE: smoke-tests against oprf_nullifier (not enroll_commit_v2) because the
// enroll circuit requires a production-pinned Diia CA witness that cannot be
// generated without a real cert, whereas the nullifier proof is locally
// reproducible. The VERIFIER CRS is fixed-size (circuit-independent), so this
// warms the same SRS slice the runtime enroll-gate verify needs; the enroll-gate
// VK still derives from enroll_commit_v2.json at runtime in proof-gate.mjs.
//
// Self-contained: derives the vk from the circuit bytecode (no vk file needed).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
    Barretenberg,
    UltraHonkBackend,
    UltraHonkVerifierBackend,
} from "@aztec/bb.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TARGET = join(__dirname, "..", "circuits", "oprf_nullifier", "target");

const bytecode = JSON.parse(
    readFileSync(join(TARGET, "oprf_nullifier.json"), "utf8"),
).bytecode;
const proof = new Uint8Array(readFileSync(join(TARGET, "proof")));
const piBytes = new Uint8Array(readFileSync(join(TARGET, "public_inputs")));
const publicInputs = [];
for (let i = 0; i < piBytes.length; i += 32) {
    publicInputs.push("0x" + Buffer.from(piBytes.subarray(i, i + 32)).toString("hex"));
}

const threads = Number(process.env.BB_THREADS || 1);
const backend = process.env.BB_BACKEND || "Wasm";
const api = await Barretenberg.new({ threads, ...(backend ? { backend } : {}) });
const vk = await new UltraHonkBackend(bytecode, api).getVerificationKey();
const verifier = new UltraHonkVerifierBackend(api);

const valid = await verifier.verifyProof({ proof, publicInputs, verificationKey: vk });

// Negative control: a tampered proof must NOT verify.
const tampered = new Uint8Array(proof);
tampered[tampered.length >> 1] ^= 0xff;
const tamperedOk = await verifier.verifyProof({ proof: tampered, publicInputs, verificationKey: vk });

console.log(`bake-crs: valid=${valid} tampered=${tamperedOk} (CRS_PATH=${process.env.CRS_PATH || "~/.bb-crs"})`);

if (!valid || tamperedOk) {
    console.error("bake-crs: in-process verify smoke test FAILED");
    process.exit(1);
}
console.log("bake-crs: CRS warmed + in-process gate verified OK");
process.exit(0);
