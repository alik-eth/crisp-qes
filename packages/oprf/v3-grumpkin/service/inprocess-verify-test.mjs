// Spike: can @aztec/bb.js verify an UltraHonk proof IN-PROCESS (no `bb` CLI)?
//
// Loads the committed enroll_commit_v2 artifacts (proof, public_inputs, vk,
// bytecode JSON) and attempts in-process verification with bb.js. Prints which
// variant works so proof-gate.mjs can be refactored to drop the bb dependency.
//
// Run with cwd in v3-grumpkin:  node service/inprocess-verify-test.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
    Barretenberg,
    UltraHonkBackend,
    UltraHonkVerifierBackend,
} from "@aztec/bb.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TARGET = join(__dirname, "..", "circuits", "enroll_commit_v2", "target");

const bytecode = JSON.parse(
    readFileSync(join(TARGET, "enroll_commit_v2.json"), "utf8"),
).bytecode;
const proofBytes = new Uint8Array(readFileSync(join(TARGET, "proof")));
const piBytes = new Uint8Array(readFileSync(join(TARGET, "public_inputs")));
const vkBytes = new Uint8Array(readFileSync(join(TARGET, "vk")));

// public_inputs file = flat 32B-BE words → string[] of 0x-hex.
const publicInputs = [];
for (let i = 0; i < piBytes.length; i += 32) {
    publicInputs.push(
        "0x" + Buffer.from(piBytes.subarray(i, i + 32)).toString("hex"),
    );
}

console.log(`proof bytes=${proofBytes.length} pi words=${publicInputs.length} vk bytes=${vkBytes.length}`);

const results = {};

async function tryVariant(name, fn) {
    try {
        const ok = await fn();
        results[name] = ok;
        console.log(`  [${ok ? "VERIFIED" : "rejected"}] ${name}`);
    } catch (e) {
        results[name] = `ERR: ${e.message}`;
        console.log(`  [ERROR] ${name} — ${e.message}`);
    }
}

// — Variant 1: UltraHonkBackend(bytecode).verifyProof({proof, publicInputs}) ──
// Backend derives the VK from bytecode internally.
await tryVariant("UltraHonkBackend.verifyProof (vk from bytecode)", async () => {
    const backend = new UltraHonkBackend(bytecode, await Barretenberg.new({ threads: 1 }));
    try {
        return await backend.verifyProof({ proof: proofBytes, publicInputs });
    } finally {
        // backend holds the api; no explicit destroy method — let process exit.
    }
});

// — Variant 2: UltraHonkVerifierBackend.verifyProof with explicit vk ──────────
await tryVariant("UltraHonkVerifierBackend.verifyProof (explicit vk)", async () => {
    const api = await Barretenberg.new({ threads: 1 });
    const verifier = new UltraHonkVerifierBackend(api);
    return await verifier.verifyProof({
        proof: proofBytes,
        publicInputs,
        verificationKey: vkBytes,
    });
});

// — Negative control: tamper a proof byte; must NOT verify ────────────────────
await tryVariant("UltraHonkBackend.verifyProof (TAMPERED — must reject)", async () => {
    const t = new Uint8Array(proofBytes);
    t[Math.floor(t.length / 2)] ^= 0xff;
    const backend = new UltraHonkBackend(bytecode, await Barretenberg.new({ threads: 1 }));
    return await backend.verifyProof({ proof: t, publicInputs });
});

console.log("\nSUMMARY:", JSON.stringify(results, null, 2));

const v1 = results["UltraHonkBackend.verifyProof (vk from bytecode)"] === true;
const v2 = results["UltraHonkVerifierBackend.verifyProof (explicit vk)"] === true;
const neg = results["UltraHonkBackend.verifyProof (TAMPERED — must reject)"] === false;

if ((v1 || v2) && neg) {
    console.log("\nIN-PROCESS VERIFY WORKS (and rejects tampered).");
    process.exit(0);
} else {
    console.log("\nIN-PROCESS VERIFY did NOT cleanly work.");
    process.exit(1);
}
