// Regenerate committed enroll_commit_v2 fixtures (proof, public_inputs, vk,
// vk_hash) with @aztec/bb.js DEFAULT flavor — byte-for-byte the flavor the
// service's ProofGate verifies with. Run with cwd in v3-grumpkin AFTER
// `nargo execute` has produced target/enroll_commit_v2.gz.
//   node service/gen-fixtures.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";

const T = join(dirname(fileURLToPath(import.meta.url)), "..", "circuits", "enroll_commit_v2", "target");
const bytecode = JSON.parse(readFileSync(join(T, "enroll_commit_v2.json"), "utf8")).bytecode;
const witness = new Uint8Array(readFileSync(join(T, "enroll_commit_v2.gz")));

const api = await Barretenberg.new({ threads: 1 });
const backend = new UltraHonkBackend(bytecode, api);
const { proof, publicInputs } = await backend.generateProof(witness); // DEFAULT flavor
const vk = await backend.getVerificationKey();
await api.destroy();

writeFileSync(join(T, "proof"), Buffer.from(proof));
const pi = Buffer.concat(publicInputs.map((w) => Buffer.from(w.replace(/^0x/, ""), "hex")));
writeFileSync(join(T, "public_inputs"), pi);
writeFileSync(join(T, "vk"), Buffer.from(vk));
writeFileSync(join(T, "vk_hash"), createHash("sha256").update(Buffer.from(vk)).digest());
console.log(`wrote fixtures: proof=${proof.length}B pi=${publicInputs.length} words vk=${vk.length}B`);
console.log(`public digest words [14]=${publicInputs[14]} [15]=${publicInputs[15]}`);
