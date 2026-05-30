// On-chain-enrollment test for the v3 Grumpkin VOPRF service (build, unaudited).
//
// Proves POST /v3/register lands a citizen's commitment on the SAME deployed
// EnrollmentRegistry path v2 uses, end-to-end:
//
//   1. generate a REAL enroll_commit_v2 client proof (witness + nargo execute +
//      bb write_vk + bb prove) — the same artifacts the blind-eval gate gates on;
//   2. derive the enrollment commitment = pedersen([N.x, N.y]) where N is the
//      unblinded OPRF output (N = k*H2C(RNOKPP)), exactly as e2e-test.mjs does;
//   3. POST { commitment, proof, publicInputs } to /v3/register;
//   4. ASSERT:
//      (a) the returned merklePath + merklePathIndices recompute to newRoot,
//      (b) oldRoot == GENESIS (first append onto a fresh tree),
//      (c) the attesterSig recovers (via viem) to the configured attester addr,
//      (d) the attesterDigest equals the independently-recomputed inner digest,
//      (e) GET /v3/enrollment/:commitment/path returns the same leaf/root,
//      (f) a second register of the same commitment is rejected 409,
//      (g) a tampered proof is rejected 4xx (gate is real).
//
// The attester key is injected as a fixed dev key so the recovery assertion is
// deterministic; in production the human sets V3_ATTESTER_KEY to the secp256k1
// key whose address is 0x876E995c6f4f158ED5D746B5e10A00329df1E246 (the address
// EnrollmentRegistry.updateRoot trusts), and the SAME recovery holds.
//
// Run with cwd in v3-grumpkin:  node service/register-test.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { buildApp } from "./server.mjs";
import { OprfNode, pointFromHex } from "./oprf-node.mjs";
import { PUBLIC_INPUT_WORD_COUNT, M_X_WORD_INDEX } from "./proof-gate.mjs";
import { rootFromPath, GENESIS_ROOT, bigintToHex32 } from "./merkle.mjs";
import { innerDigest } from "./attester.mjs";
import { Fp, hashToCurve, oprfEval } from "../lib.mjs";
import { BarretenbergSync } from "@aztec/bb.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const CIRCUIT_DIR = join(ROOT, "circuits", "enroll_commit_v2");
const TARGET = join(CIRCUIT_DIR, "target");
const BB = process.env.BB_BIN || "bb";

// RNOKPP must match gen-enroll-commit-v2-witness.mjs so the commitment we derive
// here is the one whose M the generated proof commits to.
const RNOKPP = "1234567890";

// Fixed dev attester key for a deterministic recovery assertion. (Prod uses
// V3_ATTESTER_KEY = the key for 0x876E...E246; recovery works identically.)
const ATTESTER_KEY =
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CHAIN_ID = 11155111;
const ENROLLMENT_REGISTRY = "0x0214504C1Be6d664bbE3AE6687507aBE19A36d1a";

let failures = 0;
function check(name, cond, extra) {
    const tag = cond ? "PASS" : "FAIL";
    if (!cond) failures++;
    console.log(`  [${tag}] ${name}${extra ? "  — " + extra : ""}`);
}

function readPublicInputWords(path) {
    const buf = readFileSync(path);
    const words = [];
    for (let i = 0; i < buf.length; i += 32) {
        words.push("0x" + buf.subarray(i, i + 32).toString("hex"));
    }
    return words;
}

function ensureProofArtifacts() {
    const proofPath = join(TARGET, "proof");
    const piPath = join(TARGET, "public_inputs");
    const fresh = process.env.REGISTER_TEST_FRESH === "1";
    if (!fresh && existsSync(proofPath) && existsSync(piPath)) {
        return { proofPath, piPath };
    }
    console.log("  (generating real client proof: witness + nargo execute + bb write_vk + bb prove)");
    execFileSync("node", ["gen-enroll-commit-v2-witness.mjs"], { cwd: ROOT, stdio: "inherit" });
    execFileSync("nargo", ["execute"], { cwd: CIRCUIT_DIR, stdio: "inherit" });
    const bbOpts = { cwd: CIRCUIT_DIR, stdio: "inherit" };
    execFileSync(BB, ["write_vk", "-b", "target/enroll_commit_v2.json", "-o", "target"], bbOpts);
    execFileSync(BB, ["prove", "-b", "target/enroll_commit_v2.json", "-w", "target/enroll_commit_v2.gz", "-o", "target"], bbOpts);
    return { proofPath, piPath };
}

// Pedersen over (n.x, n.y) — same primitive lib.mjs + the nullifier circuit use.
let _bb = null;
const toBE32 = (v) => {
    const o = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
    return o;
};
async function pedersen(fields) {
    if (!_bb) _bb = await BarretenbergSync.initSingleton();
    const res = _bb.pedersenHash({ inputs: fields.map((f) => toBE32(Fp.create(f))), hashIndex: 0 });
    let acc = 0n;
    for (const b of res.hash) acc = (acc << 8n) | BigInt(b);
    return acc;
}

async function main() {
    console.log("v3 Grumpkin VOPRF on-chain-register test (build, unaudited)\n");

    const { proofPath, piPath } = ensureProofArtifacts();
    const proofBytes = readFileSync(proofPath);
    const proofHex = "0x" + proofBytes.toString("hex");
    const publicInputs = readPublicInputWords(piPath);
    check(
        `public_inputs has ${PUBLIC_INPUT_WORD_COUNT} field words`,
        publicInputs.length === PUBLIC_INPUT_WORD_COUNT,
        `got ${publicInputs.length}`,
    );

    // Fixed node key so N (and thus the commitment) is deterministic.
    const node = new OprfNode(123456789n);

    // — Derive the enrollment commitment exactly as the client would ─────────
    // N = unblinded OPRF output = k * H2C(RNOKPP)  (== rinv * (k * (r*H))).
    const Hpt = hashToCurve(new TextEncoder().encode(RNOKPP));
    const Npt = oprfEval(node.k, Hpt); // k*H
    const Naff = Npt.toAffine();
    const commitmentBig = await pedersen([Naff.x, Naff.y]);
    const commitment = bigintToHex32(commitmentBig);

    // Sanity: the proof's public-output M must equal r*H for the SAME RNOKPP —
    // i.e. M and our N share the H2C(RNOKPP) base. We verify M is on-curve and
    // that k*M unblinds (via rinv) to N inside the service; here we just confirm
    // the proof's M is a valid point so the binding in /v3/register is exercised.
    const Mx = publicInputs[M_X_WORD_INDEX], My = publicInputs[M_X_WORD_INDEX + 1];
    const Mpt = pointFromHex("0x" + Mx.slice(2) + My.slice(2));
    check("proof public-output M is a valid on-curve Grumpkin point", !!Mpt);

    // — Build the app with our fixed attester + a fresh (empty) tree ─────────
    const app = await buildApp({
        node,
        attesterKey: ATTESTER_KEY,
        chainId: CHAIN_ID,
        enrollmentRegistry: ENROLLMENT_REGISTRY,
        logger: false,
    });
    const expectedAttester = privateKeyToAccount(ATTESTER_KEY).address;

    // — POST /v3/register ────────────────────────────────────────────────
    const res = await app.inject({
        method: "POST",
        url: "/v3/register",
        payload: { commitment, proof: proofHex, publicInputs },
    });
    check("register: valid proof + commitment => 200", res.statusCode === 200,
        `status=${res.statusCode} body=${JSON.stringify(res.json()).slice(0, 200)}`);

    if (res.statusCode === 200) {
        const body = res.json();

        check("register: leafIndex == 0 (first enrollment)", body.leafIndex === 0,
            `leafIndex=${body.leafIndex}`);
        check("register: returns newCommitments == [commitment]",
            Array.isArray(body.newCommitments) && body.newCommitments[0] === commitment);

        // (b) oldRoot == GENESIS.
        check("register: oldRoot == canonical depth-20 genesis root",
            BigInt(body.oldRoot) === GENESIS_ROOT,
            `oldRoot=${body.oldRoot}`);

        // (a) merklePath recomputes to newRoot.
        const path = body.merklePath.map((h) => BigInt(h));
        const indices = body.merklePathIndices;
        check("register: merklePath has TREE_DEPTH (20) siblings", path.length === 20,
            `len=${path.length}`);
        const recomputed = await rootFromPath(commitmentBig, path, indices);
        check("register: merklePath verifies leaf -> newRoot",
            recomputed === BigInt(body.newRoot),
            `recomputed=${bigintToHex32(recomputed)} newRoot=${body.newRoot}`);

        // (d) attesterDigest == independently-recomputed inner digest.
        const expectedDigest = innerDigest({
            oldRoot: BigInt(body.oldRoot),
            newRoot: BigInt(body.newRoot),
            newCommitments: [commitmentBig],
            chainId: CHAIN_ID,
            enrollmentRegistry: ENROLLMENT_REGISTRY,
        });
        check("register: attesterDigest matches recomputed inner digest",
            body.attesterDigest.toLowerCase() === expectedDigest.toLowerCase(),
            `got=${body.attesterDigest} exp=${expectedDigest}`);

        // (c) attesterSig recovers to the configured attester address.
        check("register: response attesterAddr == configured attester",
            body.attesterAddr.toLowerCase() === expectedAttester.toLowerCase(),
            `${body.attesterAddr} vs ${expectedAttester}`);
        const recovered = await recoverMessageAddress({
            message: { raw: body.attesterDigest },
            signature: body.attesterSig,
        });
        check("register: attesterSig recovers (EIP-191) to the attester address",
            recovered.toLowerCase() === expectedAttester.toLowerCase(),
            `recovered=${recovered} expected=${expectedAttester}`);

        // (e) recovery path lookup mirrors the register result.
        const pathRes = await app.inject({
            method: "GET",
            url: `/v3/enrollment/${commitment}/path`,
        });
        check("path lookup: GET /v3/enrollment/:commitment/path => 200",
            pathRes.statusCode === 200, `status=${pathRes.statusCode}`);
        if (pathRes.statusCode === 200) {
            const pb = pathRes.json();
            const recomputed2 = await rootFromPath(
                commitmentBig, pb.merklePath.map((h) => BigInt(h)), pb.merklePathIndices,
            );
            check("path lookup: leafIndex + root match register",
                pb.leafIndex === body.leafIndex && pb.root === body.newRoot);
            check("path lookup: returned path verifies to root",
                recomputed2 === BigInt(pb.root));
        }

        // (f) duplicate register rejected.
        const dupRes = await app.inject({
            method: "POST",
            url: "/v3/register",
            payload: { commitment, proof: proofHex, publicInputs },
        });
        check("register: duplicate commitment => 409", dupRes.statusCode === 409,
            `status=${dupRes.statusCode}`);
    }

    // (g) tampered proof rejected (gate is real, not a stub).
    const tampered = Buffer.from(proofBytes);
    tampered[Math.floor(tampered.length / 2)] ^= 0xff;
    const badRes = await app.inject({
        method: "POST",
        url: "/v3/register",
        // use a different commitment so it isn't a 409 short-circuit
        payload: { commitment: bigintToHex32(commitmentBig + 1n), proof: "0x" + tampered.toString("hex"), publicInputs },
    });
    check("register: tampered proof => 4xx (gate enforced)",
        badRes.statusCode >= 400 && badRes.statusCode < 500,
        `status=${badRes.statusCode}`);

    await app.close();

    console.log("");
    if (failures === 0) {
        console.log("ALL REGISTER CHECKS PASS");
        process.exit(0);
    } else {
        console.log(`${failures} REGISTER CHECK(S) FAILED`);
        process.exit(1);
    }
}

main().catch((e) => {
    console.error("register-test crashed:", e);
    process.exit(1);
});
