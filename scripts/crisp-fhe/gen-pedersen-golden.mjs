#!/usr/bin/env node
// Generate the Pedersen golden vectors for packages/oprf/tests/pedersen-golden.test.ts
// using the CIRCUIT's bb.js (@aztec/bb.js 3.0.0-nightly.20260102, bundled in the
// vendored fork), NOT the off-chain 4.x bb.js. The test then asserts the off-chain
// 4.x helpers reproduce these values — pinning the two bb.js majors together.
//
// Run:  node scripts/crisp-fhe/gen-pedersen-golden.mjs
//
// If you change the fixed inputs in the test, regenerate with this script and
// paste the new GOLDEN block. Requires the fork's pnpm install to have run
// (scripts/crisp-fhe/bootstrap.sh) so the 3.x bb.js is present.

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..", "..");

// Resolve the circuit's 3.x bb.js deterministically via its pnpm content-addressed
// path. Fail loudly if it is absent (rather than silently falling back to 4.x).
const BB3 = resolve(
    ROOT,
    "vendor/crisp-qes-enclave/node_modules/.pnpm",
    "@aztec+bb.js@3.0.0-nightly.20260102",
    "node_modules/@aztec/bb.js/dest/node/index.js",
);
if (!existsSync(BB3)) {
    console.error(
        `FATAL: circuit bb.js not found at ${BB3}\n` +
            "Run scripts/crisp-fhe/bootstrap.sh (pnpm install in the fork) first.",
    );
    process.exit(1);
}

const bigintToBE32 = (v) => {
    const o = new Uint8Array(32);
    let x = v;
    for (let i = 31; i >= 0; i--) {
        o[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return o;
};
const be32ToBigInt = (b) => {
    let a = 0n;
    for (let i = 0; i < b.length; i++) a = (a << 8n) | BigInt(b[i]);
    return a;
};
const splitBE32 = (buf) => {
    let hi = 0n;
    let lo = 0n;
    for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(buf[i]);
    for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(buf[i]);
    return { hi, lo };
};
const hx = (v) => `0x${v.toString(16).padStart(64, "0")}`;

const DOMAIN_PETITION_V2 = 0x76322d70656e2d6e6f31n;

const { BarretenbergSync } = await import(BB3);
const api = await BarretenbergSync.initSingleton();
const ped = (inputs, hashIndex) =>
    be32ToBigInt(
        api.pedersenHash({ inputs: inputs.map(bigintToBE32), hashIndex }).hash,
    );

// Fixed inputs — MUST match packages/oprf/tests/pedersen-golden.test.ts.
const N = new Uint8Array(32);
for (let i = 0; i < 32; i++) N[i] = (i * 7 + 3) & 0xff;
const { hi, lo } = splitBE32(N);
const s = ped([hi, lo], 0);
const petitionId = 42n;
const nullifier = ped([s, petitionId, DOMAIN_PETITION_V2], 0);

const leaves = [0x1111n, 0x2222n, 0x3333n, 0n];
const l01 = ped([leaves[0], leaves[1]], 0);
const l23 = ped([leaves[2], leaves[3]], 0);
const merkleRoot = ped([l01, l23], 0);

console.log("bb.js (circuit):", "3.0.0-nightly.20260102");
console.log("const GOLDEN = {");
console.log(`    N_hi: "${hx(hi)}",`);
console.log(`    N_lo: "${hx(lo)}",`);
console.log(`    s: "${hx(s)}",`);
console.log(`    nullifier: "${hx(nullifier)}",`);
console.log(`    merkleNode_1111_2222: "${hx(ped([0x1111n, 0x2222n], 0))}",`);
console.log(`    merkleRoot: "${hx(merkleRoot)}",`);
console.log("} as const;");
