// End-to-end demo: enrol a citizen via the deployed OPRF service, anchor
// the new EnrollmentRegistry root on Base Sepolia, generate a real v2
// UltraHonk proof, and submit it through the deployed v2-relayer.
//
// Run as:
//   node packages/v2-relayer/scripts/e2e-sign.mjs <petitionId> <vote>
//
// Defaults: petitionId=1, vote=0 (the demo petition created by N5).
//
// This script intentionally lives outside the production wire — it's a
// one-shot integration probe whose output is the demo tx hash.

import { readFileSync } from "node:fs";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, BarretenbergSync, UltraHonkBackend } from "@aztec/bb.js";
import {
    RistrettoPoint,
    hash_to_ristretto255,
    ed25519,
} from "@noble/curves/ed25519";
// Compat shim: older noble (1.9.1 in bench) exposes RistrettoPoint
// directly instead of the `ristretto255.Point` namespace used by v2-oprf
// (1.9.7). Same point type underneath — just a different surface.
const ristretto255 = {
    Point: RistrettoPoint,
    Fn: { ORDER: ed25519.CURVE.n, create: (x) => ((x % ed25519.CURVE.n) + ed25519.CURVE.n) % ed25519.CURVE.n, inv: (x) => {
        // Fermat's little theorem inverse: x^(n-2) mod n.
        let r = 1n, b = ((x % ed25519.CURVE.n) + ed25519.CURVE.n) % ed25519.CURVE.n, e = ed25519.CURVE.n - 2n, m = ed25519.CURVE.n;
        while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
        return r;
    } },
};
const ristretto255_hasher = { hashToCurve: hash_to_ristretto255 };
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
    createPublicClient,
    createWalletClient,
    http,
    parseAbi,
    encodeFunctionData,
    keccak256,
} from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// — Config ─────────────────────────────────────────────────────────────────

const OPRF_URL = "https://crisp-qes-v2-oprf.fly.dev";
const RELAYER_URL = "https://crisp-qes-v2-relayer.fly.dev";
const ENROLLMENT_REGISTRY = "0x66573066C9e5f87cF63c9607BD1e75d9831850aA";
const PETITION_REGISTRY_V2 = "0xe7cC90F3E4d70e47D1d35DCDF820C3B1c27aE8Cd";
const RPC = "https://sepolia.base.org";
const CIRCUIT_PATH =
    "/data/Develop/crisp-qes/packages/v2-circuit/target/crisp_qes_v2_circuit.json";
const P7S_PATH = "/data/Develop/crisp-qes/fixtures/diia/petition-1-binding.bin.p7s";

const TREE_DEPTH = 20;
const DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31n;

const PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY;
if (!PRIVATE_KEY) {
    console.error("Set RELAYER_PRIVATE_KEY (the testnet admin key)");
    process.exit(1);
}
const petitionId = BigInt(process.argv[2] ?? "1");
const vote = Number(process.argv[3] ?? "0");

// — Helpers ────────────────────────────────────────────────────────────────

const toHex = (b) => `0x${bytesToHex(b)}`;
const fromHex = (h) => hexToBytes(h.startsWith("0x") ? h.slice(2) : h);

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

const FN = ristretto255.Point.Fn;

// VOPRF "ristretto255-SHA512" context.
const CONTEXT_STRING = new Uint8Array([
    ...new TextEncoder().encode("OPRFV1-"),
    0x01,
    ...new TextEncoder().encode("-ristretto255-SHA512"),
]);
const DST_HTC = new Uint8Array([
    ...new TextEncoder().encode("HashToGroup-"),
    ...CONTEXT_STRING,
]);
function hashToGroup(msg) {
    return ristretto255_hasher.hashToCurve(msg, { DST: DST_HTC });
}
function randomScalar() {
    return ristretto255.Fn.create(BigInt(`0x${bytesToHex(crypto.getRandomValues(new Uint8Array(64)))}`)) || 1n;
}
// noble 1.9.1 uses `toRawBytes()` on RistrettoPoint where 1.9.7 uses
// `toBytes()`. Tiny wrapper so the rest of the script stays clean.
const enc = (p) => (p.toBytes ? p.toBytes() : p.toRawBytes());
function blind(input) {
    const r = randomScalar();
    const X = hashToGroup(input);
    return { r, M: enc(ristretto255.Point.fromHex(enc(X)).multiply(r)) };
}
function unblind(r, Y) {
    return enc(ristretto255.Point.fromHex(Y).multiply(ristretto255.Fn.inv(r)));
}

// — Pedersen via bb.js (matches v2-oprf + circuit byte-for-byte) ───────────

const apiSync = await BarretenbergSync.initSingleton();
function pedersenHash(fields, hashIndex = 0) {
    const inputs = fields.map(bigintToBE32);
    const { hash } = apiSync.pedersenHash({ inputs, hashIndex });
    return be32ToBigint(hash);
}

// — Step 1: OPRF blind-eval against deployed service ───────────────────────

console.log(`[1/6] Reading Diia .p7s fixture (${P7S_PATH})`);
const p7sBytes = readFileSync(P7S_PATH);
const p7sB64 = Buffer.from(p7sBytes).toString("base64");

// RNOKPP is what the .p7s subject serial encodes; for the demo we use a
// fresh random bigint as the OPRF input so each run produces a distinct
// commitment (otherwise we'd 409 after the first enrollment).
const rnokppLike = `RNOKPP=${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
console.log(`        Using synthetic OPRF input: ${rnokppLike}`);

const inputBytes = new TextEncoder().encode(rnokppLike);
const { r, M } = blind(inputBytes);

console.log(`[2/6] POST ${OPRF_URL}/oprf/blind-eval`);
const blindEvalRes = await fetch(`${OPRF_URL}/oprf/blind-eval`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
        blindedInput: toHex(M),
        attestation: { p7s: p7sB64 },
    }),
});
if (!blindEvalRes.ok) {
    console.error(`blind-eval failed: ${blindEvalRes.status} ${await blindEvalRes.text()}`);
    process.exit(1);
}
const { Y, K } = await blindEvalRes.json();
console.log(`        Y = ${Y.slice(0, 18)}…`);

const N = unblind(r, fromHex(Y));

// — Step 3: Derive s = pedersen([N_hi, N_lo], 0) and register ──────────────

let N_hi = 0n;
for (let i = 0; i < 16; i++) N_hi = (N_hi << 8n) | BigInt(N[i]);
let N_lo = 0n;
for (let i = 16; i < 32; i++) N_lo = (N_lo << 8n) | BigInt(N[i]);
const s = pedersenHash([N_hi, N_lo], 0);
const commitment = toFieldHex(s);

console.log(`[3/6] POST ${OPRF_URL}/oprf/register (commitment = ${commitment.slice(0, 18)}…)`);
const registerRes = await fetch(`${OPRF_URL}/oprf/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
        commitment,
        blindedInputUsed: toHex(M),
        unblindedOutput: toHex(N),
    }),
});
if (!registerRes.ok) {
    console.error(`register failed: ${registerRes.status} ${await registerRes.text()}`);
    process.exit(1);
}
const reg = await registerRes.json();
console.log(`        leafIndex=${reg.leafIndex}  newRoot=${reg.newRoot.slice(0, 18)}…`);

// — Step 4: Anchor newRoot on chain via EnrollmentRegistry.updateRoot ──────

const account = privateKeyToAccount(PRIVATE_KEY);
const publicClient = createPublicClient({ chain: baseSepolia, transport: http(RPC) });
const walletClient = createWalletClient({ account, chain: baseSepolia, transport: http(RPC) });

// EnrollmentRegistry ABI surface we need.
const enrollmentAbi = parseAbi([
    "function updateRoot(bytes32 newRoot, uint256 leafIndex, bytes signature) external",
    "function enrollmentRoot() view returns (bytes32)",
    "function leafCount() view returns (uint256)",
    "function previewDigest(bytes32 newRoot, uint256 leafIndex) view returns (bytes32)",
]);

console.log(`[4/6] EnrollmentRegistry.updateRoot(newRoot, leafIndex=${reg.leafIndex}, sig)`);
const updateTx = await walletClient.writeContract({
    address: ENROLLMENT_REGISTRY,
    abi: enrollmentAbi,
    functionName: "updateRoot",
    args: [reg.newRoot, BigInt(reg.leafIndex), reg.attesterSig],
});
console.log(`        tx: ${updateTx}`);
const updateReceipt = await publicClient.waitForTransactionReceipt({ hash: updateTx });
console.log(`        status=${updateReceipt.status}  gasUsed=${updateReceipt.gasUsed}`);
if (updateReceipt.status !== "success") {
    console.error("updateRoot reverted; bailing");
    process.exit(1);
}

const liveRoot = await publicClient.readContract({
    address: ENROLLMENT_REGISTRY,
    abi: enrollmentAbi,
    functionName: "enrollmentRoot",
});
console.log(`        on-chain enrollmentRoot = ${liveRoot.slice(0, 18)}…`);
if (liveRoot.toLowerCase() !== reg.newRoot.toLowerCase()) {
    console.error("on-chain root != /oprf/register newRoot — wire mismatch");
    process.exit(1);
}

// — Step 5: Generate the v2 UltraHonk proof ────────────────────────────────

console.log(`[5/6] Generating v2 UltraHonk proof (petitionId=${petitionId}, vote=${vote})`);
const nullifier = pedersenHash([s, petitionId, DOMAIN_PETITION_V2], 0);

const merklePath = reg.merklePath.map((h) => BigInt(h));
const merkleIndices = reg.merklePathIndices;

const witnessInputs = {
    enrollment_secret: toFieldHex(s),
    merkle_path: merklePath.map(toFieldHex),
    merkle_path_indices: merkleIndices.map((i) => i.toString(10)),
    petition_id: toFieldHex(petitionId),
    enrollment_root: liveRoot,
    nullifier: toFieldHex(nullifier),
};

const circuit = JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));
const noir = new Noir(circuit);
const t0 = Date.now();
const { witness } = await noir.execute(witnessInputs);
const api = await Barretenberg.new({});
const backend = new UltraHonkBackend(circuit.bytecode, api);
const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: "evm" });
await api.destroy();
const proveMs = Date.now() - t0;
console.log(`        proof bytes: ${proof.length}, public inputs: ${publicInputs.length}, prove time: ${proveMs} ms`);

// — Step 6: Submit through the v2-relayer ──────────────────────────────────

const proofHex = toHex(proof);
console.log(`[6/6] POST ${RELAYER_URL}/v2/submit`);
const submitRes = await fetch(`${RELAYER_URL}/v2/submit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
        petitionId: petitionId.toString(),
        vote,
        nullifier: toFieldHex(nullifier),
        proof: proofHex,
        publicInputs,
    }),
});
const submitBody = await submitRes.text();
console.log(`        HTTP ${submitRes.status}: ${submitBody}`);
if (!submitRes.ok) process.exit(1);

const { txHash, blockExplorerUrl } = JSON.parse(submitBody);
console.log(`\n✅ Demo signature on chain:`);
console.log(`   txHash:       ${txHash}`);
console.log(`   explorer:     ${blockExplorerUrl}`);
console.log(`   prove time:   ${proveMs} ms`);
