// Generate one v2 proof + publicInputs and write them to disk in a form
// the forge gas-report test can consume. The witness is the same
// synthetic shape used in v2-native-prove.mjs / v2-web-prove.mjs.
//
// Output:
//   bench/v2-proof.bin      raw EVM-flavoured Honk proof bytes
//   bench/v2-publics.json   { publicInputs: ["0x...", ...] }

import { readFileSync, writeFileSync } from "node:fs";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, BarretenbergSync, UltraHonkBackend } from "@aztec/bb.js";

const TREE_DEPTH = 20;
const DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31n;
const ENROLLMENT_SECRET = 0x42n;
const PETITION_ID = 1n;
const PATH = Array(TREE_DEPTH).fill(0n);
const INDICES = Array(TREE_DEPTH).fill(0);
const CIRCUIT_PATH = "/data/Develop/crisp-qes/packages/v2-circuit/target/crisp_qes_v2_circuit.json";

function toFieldHex(v) { return "0x" + v.toString(16).padStart(64, "0"); }
function bigintToBE32(v) {
    const out = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    return out;
}
function be32ToBigint(b) { let v = 0n; for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[i]); return v; }

const apiSync = await BarretenbergSync.initSingleton();
function pedersenHashFields(fields) {
    const inputs = fields.map(bigintToBE32);
    const { hash } = apiSync.pedersenHash({ inputs, hashIndex: 0 });
    return be32ToBigint(hash);
}
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

const circuit = JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));
const noir = new Noir(circuit);
const { witness: compressedWitness } = await noir.execute(witnessInputs);
const api = await Barretenberg.new({});
const backend = new UltraHonkBackend(circuit.bytecode, api);
const { proof, publicInputs } = await backend.generateProof(compressedWitness, { verifierTarget: "evm" });
await api.destroy();

writeFileSync("/data/Develop/crisp-qes/bench/v2-proof.bin", Buffer.from(proof));
writeFileSync("/data/Develop/crisp-qes/bench/v2-publics.json", JSON.stringify({
    publicInputs,
    proofHex: "0x" + Buffer.from(proof).toString("hex"),
}, null, 2));
console.log(`proof bytes: ${proof.length}`);
console.log(`publicInputs (${publicInputs.length}):`);
publicInputs.forEach((p, i) => console.log(`  [${i}] ${p}`));
process.exit(0);
