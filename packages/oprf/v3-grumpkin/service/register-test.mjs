// On-chain-enrollment test for the v3 Grumpkin VOPRF service (build, unaudited).
//
// Proves POST /v3/register lands a citizen's commitment on the SAME deployed
// EnrollmentRegistry path v2 uses, end-to-end, AND that the Sybil-binding gap is
// closed: the submitted commitment is cryptographically bound to the cert via
// TWO proofs (enroll_commit_v2 + oprf_nullifier) and the service's cross-checks.
//
//   1. generate a REAL enroll_commit_v2 client proof (binds M <-> age>=18 cert);
//   2. generate a REAL oprf_nullifier client proof (verifies DLEQ Y=k*M for the
//      node's Kpub, unblinds N=rinv*Y, RETURNS commitment=pedersen(N)). Both use
//      the SAME RNOKPP + blinding r, and the nullifier uses THIS node's k, so
//      the proofs' M agree and the nullifier commitment == the derived leaf;
//   3. POST { commitment, enrollProof, enrollPublicInputs, nullifierProof,
//      nullifierPublicInputs } to /v3/register;
//   4. ASSERT:
//      (a) the returned merklePath + merklePathIndices recompute to newRoot,
//      (b) oldRoot == GENESIS (first append onto a fresh tree),
//      (c) the attesterSig recovers (via viem) to the key-derived attester addr,
//      (d) the attesterDigest equals the independently-recomputed inner digest,
//      (e) GET /v3/enrollment/:commitment/path returns the same leaf/root,
//      (f) a second register of the same commitment is rejected 409,
//      (g) a tampered enroll proof is rejected 4xx (gate is real),
//      (h) a FORGED commitment (!= pedersen(N)) is REJECTED 4xx (binding holds),
//      (i) a tampered nullifier proof is rejected 4xx.
//
// The attester key is injected as a fixed dev key; the recovery assertion is
// against the address DERIVED from that key (no hardcoded address). In
// production the human sets V3_ATTESTER_KEY to the ROTATED registry attester key
// and the SAME derive-and-recover holds.
//
// Run with cwd in v3-grumpkin:  node service/register-test.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { buildApp } from "./server.mjs";
import { OprfNode, pointFromHex } from "./oprf-node.mjs";
import {
    PUBLIC_INPUT_WORD_COUNT,
    M_X_WORD_INDEX,
    NULLIFIER_PUBLIC_INPUT_WORD_COUNT,
    NULLIFIER_COMMITMENT_WORD_INDEX,
} from "./proof-gate.mjs";
import { rootFromPath, GENESIS_ROOT, bigintToHex32 } from "./merkle.mjs";
import { innerDigest } from "./attester.mjs";
import {
    Fp, Fn, N, G, hashToCurve, oprfEval, dleqProve, scalarLimbs,
} from "../lib.mjs";
import { BarretenbergSync } from "@aztec/bb.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const ENROLL_DIR = join(ROOT, "circuits", "enroll_commit_v2");
const ENROLL_TARGET = join(ENROLL_DIR, "target");
const NULLIFIER_DIR = join(ROOT, "circuits", "oprf_nullifier");
const NULLIFIER_TARGET = join(NULLIFIER_DIR, "target");
const BB = process.env.BB_BIN || "bb";

// det() matches gen-enroll-commit-v2-witness.mjs + gen-nullifier-witness.mjs so
// the RNOKPP, blinding r and node key k are identical across both proofs.
const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;

// RNOKPP + r must match gen-enroll-commit-v2-witness.mjs so the enroll proof's
// public-output M equals the M the nullifier proof is built over.
const RNOKPP = "1234567890";
const R_SCALAR = det("crisp-qes-test-r");
// Node secret k. We drive the SERVICE node with this SAME k so the nullifier
// proof's Kpub == this node's Kpub (cross-check b) and Y == k*M.
const NODE_K = det("crisp-qes-node-secret-k");

// Fixed dev attester key. The recovery assertion targets the address DERIVED
// from this key (no hardcoded address). Prod uses the rotated V3_ATTESTER_KEY.
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

// Generate the enroll_commit_v2 proof (binds M <-> cert) via the committed flow.
function ensureEnrollProof() {
    const proofPath = join(ENROLL_TARGET, "proof");
    const piPath = join(ENROLL_TARGET, "public_inputs");
    const fresh = process.env.REGISTER_TEST_FRESH === "1";
    if (!fresh && existsSync(proofPath) && existsSync(piPath)) {
        return { proofPath, piPath };
    }
    console.log("  (generating enroll_commit_v2 proof: witness + nargo execute + bb write_vk + bb prove)");
    execFileSync("node", ["gen-enroll-commit-v2-witness.mjs"], { cwd: ROOT, stdio: "inherit" });
    execFileSync("nargo", ["execute"], { cwd: ENROLL_DIR, stdio: "inherit" });
    const bbOpts = { cwd: ENROLL_DIR, stdio: "inherit" };
    execFileSync(BB, ["write_vk", "-b", "target/enroll_commit_v2.json", "-o", "target"], bbOpts);
    execFileSync(BB, ["prove", "-b", "target/enroll_commit_v2.json", "-w", "target/enroll_commit_v2.gz", "-o", "target"], bbOpts);
    return { proofPath, piPath };
}

// Generate the oprf_nullifier proof over the SAME M (RNOKPP + r) and THIS test's
// node key k, so the cross-checks at /v3/register hold. We write the Prover.toml
// here (rather than gen-nullifier-witness.mjs) so k matches the service node.
async function ensureNullifierProof() {
    const proofPath = join(NULLIFIER_TARGET, "proof");
    const piPath = join(NULLIFIER_TARGET, "public_inputs");

    // Build the witness from the same primitives lib.mjs / the circuit use.
    const Hpt = hashToCurve(new TextEncoder().encode(RNOKPP));
    const M = Hpt.multiply(R_SCALAR);
    const Kpub = G.multiply(NODE_K);
    const Y = oprfEval(NODE_K, M);                 // Y = k*M
    const { c, z } = await dleqProve(NODE_K, Kpub, M, Y, det("crisp-qes-dleq-nonce-t"));
    const rinv = Fn.inv(Fn.create(R_SCALAR));

    const aff = (P) => P.toAffine();
    const Ga = aff(G), Ka = aff(Kpub), Ma = aff(M), Ya = aff(Y);
    const cL = scalarLimbs(c), zL = scalarLimbs(z);
    const riL = scalarLimbs(rinv), rL = scalarLimbs(R_SCALAR);

    const toml = `# auto-generated by service/register-test.mjs (node k matches the service node)
gx = "${Ga.x}"
gy = "${Ga.y}"
kpx = "${Ka.x}"
kpy = "${Ka.y}"
mx = "${Ma.x}"
my = "${Ma.y}"
yx = "${Ya.x}"
yy = "${Ya.y}"
c_lo = "${cL.lo}"
c_hi = "${cL.hi}"
z_lo = "${zL.lo}"
z_hi = "${zL.hi}"
rinv_lo = "${riL.lo}"
rinv_hi = "${riL.hi}"
r_lo = "${rL.lo}"
r_hi = "${rL.hi}"
c_expected = "${c}"
`;
    console.log("  (generating oprf_nullifier proof: witness + nargo execute + bb write_vk + bb prove)");
    writeFileSync(join(NULLIFIER_DIR, "Prover.toml"), toml);
    execFileSync("nargo", ["execute"], { cwd: NULLIFIER_DIR, stdio: "inherit" });
    const bbOpts = { cwd: NULLIFIER_DIR, stdio: "inherit" };
    execFileSync(BB, ["write_vk", "-b", "target/oprf_nullifier.json", "-o", "target"], bbOpts);
    execFileSync(BB, ["prove", "-b", "target/oprf_nullifier.json", "-w", "target/oprf_nullifier.gz", "-o", "target"], bbOpts);
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

    // — Generate BOTH real client proofs ─────────────────────────────────────
    const { proofPath: ep, piPath: epi } = ensureEnrollProof();
    const enrollProofBytes = readFileSync(ep);
    const enrollProofHex = "0x" + enrollProofBytes.toString("hex");
    const enrollPublicInputs = readPublicInputWords(epi);
    check(
        `enroll public_inputs has ${PUBLIC_INPUT_WORD_COUNT} field words`,
        enrollPublicInputs.length === PUBLIC_INPUT_WORD_COUNT,
        `got ${enrollPublicInputs.length}`,
    );

    const { proofPath: np, piPath: npi } = await ensureNullifierProof();
    const nullifierProofBytes = readFileSync(np);
    const nullifierProofHex = "0x" + nullifierProofBytes.toString("hex");
    const nullifierPublicInputs = readPublicInputWords(npi);
    check(
        `nullifier public_inputs has ${NULLIFIER_PUBLIC_INPUT_WORD_COUNT} field words`,
        nullifierPublicInputs.length === NULLIFIER_PUBLIC_INPUT_WORD_COUNT,
        `got ${nullifierPublicInputs.length}`,
    );

    // Service node driven with the SAME k the nullifier proof was built over.
    const node = new OprfNode(NODE_K);

    // — Derive the enrollment commitment exactly as the client would ─────────
    // N = unblinded OPRF output = rinv*(k*M) = k*H2C(RNOKPP). commitment=pedersen(N).
    const Hpt = hashToCurve(new TextEncoder().encode(RNOKPP));
    const Npt = oprfEval(node.k, Hpt); // k*H == rinv*(k*M)
    const Naff = Npt.toAffine();
    const commitmentBig = await pedersen([Naff.x, Naff.y]);
    const commitment = bigintToHex32(commitmentBig);

    // Sanity: enroll M is on-curve, and the nullifier proof's returned commitment
    // word equals the leaf we derived (so cross-check (c) will pass server-side).
    const Mx = enrollPublicInputs[M_X_WORD_INDEX], My = enrollPublicInputs[M_X_WORD_INDEX + 1];
    const Mpt = pointFromHex("0x" + Mx.slice(2) + My.slice(2));
    check("enroll proof public-output M is a valid on-curve Grumpkin point", !!Mpt);
    check("nullifier proof's returned commitment == derived leaf",
        BigInt(nullifierPublicInputs[NULLIFIER_COMMITMENT_WORD_INDEX]) === commitmentBig,
        `null=${nullifierPublicInputs[NULLIFIER_COMMITMENT_WORD_INDEX]} leaf=${commitment}`);
    check("nullifier proof M == enroll proof M",
        nullifierPublicInputs[4] === Mx && nullifierPublicInputs[5] === My);

    // — Build the app with our fixed attester + a fresh (empty) tree ─────────
    const app = await buildApp({
        node,
        attesterKey: ATTESTER_KEY,
        chainId: CHAIN_ID,
        enrollmentRegistry: ENROLLMENT_REGISTRY,
        logger: false,
    });
    // Attester address is DERIVED from the configured key (no hardcoded addr).
    const expectedAttester = privateKeyToAccount(ATTESTER_KEY).address;

    const validPayload = {
        commitment,
        enrollProof: enrollProofHex,
        enrollPublicInputs,
        nullifierProof: nullifierProofHex,
        nullifierPublicInputs,
    };

    // — POST /v3/register ────────────────────────────────────────────────
    const res = await app.inject({
        method: "POST",
        url: "/v3/register",
        payload: validPayload,
    });
    check("register: valid proofs + bound commitment => 200", res.statusCode === 200,
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

        // (c) attesterSig recovers to the KEY-DERIVED attester address.
        check("register: response attesterAddr == key-derived attester address",
            body.attesterAddr.toLowerCase() === expectedAttester.toLowerCase(),
            `${body.attesterAddr} vs ${expectedAttester}`);
        const recovered = await recoverMessageAddress({
            message: { raw: body.attesterDigest },
            signature: body.attesterSig,
        });
        check("register: attesterSig recovers (EIP-191) to the key-derived address",
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
            payload: validPayload,
        });
        check("register: duplicate commitment => 409", dupRes.statusCode === 409,
            `status=${dupRes.statusCode}`);
    }

    // (h) FORGED commitment is REJECTED — the heart of the Sybil-binding fix.
    // Submit a commitment that is NOT pedersen(N) while keeping both VALID proofs.
    // The nullifier cross-check (proof commitment != submitted) must reject.
    const forgedRes = await app.inject({
        method: "POST",
        url: "/v3/register",
        payload: { ...validPayload, commitment: bigintToHex32(commitmentBig + 1n) },
    });
    check("register: FORGED commitment (!= pedersen(N)) => 4xx (binding enforced)",
        forgedRes.statusCode >= 400 && forgedRes.statusCode < 500,
        `status=${forgedRes.statusCode} body=${JSON.stringify(forgedRes.json()).slice(0, 160)}`);
    check("register: forged-commitment rejection code is NullifierMismatchedCommitment",
        forgedRes.json().error === "NullifierMismatchedCommitment",
        forgedRes.json().error);

    // (g) tampered enroll proof rejected (enroll gate is real, not a stub).
    const tamperedEnroll = Buffer.from(enrollProofBytes);
    tamperedEnroll[Math.floor(tamperedEnroll.length / 2)] ^= 0xff;
    const badEnrollRes = await app.inject({
        method: "POST",
        url: "/v3/register",
        // different commitment so it isn't a 409 short-circuit
        payload: {
            ...validPayload,
            commitment: bigintToHex32(commitmentBig + 2n),
            enrollProof: "0x" + tamperedEnroll.toString("hex"),
        },
    });
    check("register: tampered enroll proof => 4xx (enroll gate enforced)",
        badEnrollRes.statusCode >= 400 && badEnrollRes.statusCode < 500,
        `status=${badEnrollRes.statusCode}`);

    await app.close();

    // (i) tampered nullifier proof rejected via CRYPTO verify (gate is real).
    // Use a FRESH tree + the correct commitment so the cross-checks pass and the
    // request reaches the bb.js verifier; only the proof bytes are corrupted.
    const app2 = await buildApp({
        node,
        attesterKey: ATTESTER_KEY,
        chainId: CHAIN_ID,
        enrollmentRegistry: ENROLLMENT_REGISTRY,
        logger: false,
    });
    const tamperedNull = Buffer.from(nullifierProofBytes);
    tamperedNull[Math.floor(tamperedNull.length / 2)] ^= 0xff;
    const badNullRes = await app2.inject({
        method: "POST",
        url: "/v3/register",
        payload: { ...validPayload, nullifierProof: "0x" + tamperedNull.toString("hex") },
    });
    check("register: tampered nullifier proof => 4xx (nullifier crypto gate enforced)",
        badNullRes.statusCode >= 400 && badNullRes.statusCode < 500,
        `status=${badNullRes.statusCode} body=${JSON.stringify(badNullRes.json()).slice(0, 160)}`);
    await app2.close();

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
