// Repro for the /v3/blind-eval "Conversion err" (grumpkin::fr >= 2^128).
//
// Hypothesis: the browser worker proves with { verifierTarget: "evm" } (Keccak
// Fiat-Shamir oracle) but the service derives its VK and verifies with the
// DEFAULT flavor (no options). VK + proof are flavor-specific, so the default
// verifier reads the evm-flavored transcript at the wrong offsets and a
// grumpkin scalar limb deserializes to a full field element -> assertion.
//
// Uses the smallest committed circuit (oprf_nullifier, 8.2k) + its committed
// witness so the repro is fast. Run with cwd in v3-grumpkin:
//   node service/flavor-mismatch-repro.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend } from "@aztec/bb.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TARGET = join(__dirname, "..", "circuits", "oprf_nullifier", "target");
const bytecode = JSON.parse(readFileSync(join(TARGET, "oprf_nullifier.json"), "utf8")).bytecode;
const witness = new Uint8Array(readFileSync(join(TARGET, "oprf_nullifier.gz"))); // gzipped witness

const api = await Barretenberg.new({ threads: 1 });
const backend = new UltraHonkBackend(bytecode, api);

// Service side: VK + verifier both default flavor (matches proof-gate.mjs).
const vkDefault = await backend.getVerificationKey();
const verifier = new UltraHonkVerifierBackend(api);

async function verifyAsService(proofData) {
    try {
        const ok = await verifier.verifyProof({ ...proofData, verificationKey: vkDefault });
        return { ok };
    } catch (e) {
        return { ok: false, err: (e.message || String(e)).split("\n").slice(0, 4).join(" | ") };
    }
}

console.log("== Browser path: generateProof({ verifierTarget: 'evm' }) ==");
const evm = await backend.generateProof(witness, { verifierTarget: "evm" });
const evmRes = await verifyAsService(evm);
console.log("  service-verify(evm proof):", JSON.stringify(evmRes));

console.log("== Fixed path: generateProof() default flavor ==");
const def = await backend.generateProof(witness);
const defRes = await verifyAsService(def);
console.log("  service-verify(default proof):", JSON.stringify(defRes));

await api.destroy();

const reproduced = evmRes.ok === false && defRes.ok === true;
console.log("");
console.log(reproduced
    ? "REPRODUCED: evm-flavored proof is REJECTED by default verifier; default-flavored proof VERIFIES."
    : "NOT reproduced (evmRes/defRes unexpected) — hypothesis wrong, investigate further.");
process.exit(reproduced ? 0 : 1);
