// e2e-test.mjs — full operator-blind enrollment pipeline, end to end.
//
// This is the INTEGRATION SPINE for the v3 Grumpkin ZK VOPRF enrollment flow.
// It proves all the independently-built pieces compose into ONE coherent
// pipeline, with REAL bb proofs at both ZK stages and the OPRF node invoked
// directly (no HTTP server, to keep the coupling minimal).
//
// PIPELINE (per run, for a given synthetic Diia-style P-256 cert):
//
//   STAGE 1 (client, ZK):  enroll_commit_v2 circuit.
//       From a synthetic cert + private blinding scalar r, prove in-circuit:
//       ECDSA-P256 verify, RNOKPP DER extract, age>=18, in-circuit
//       hash_to_field(SHA-256) -> SvdW H2C, and M = r*H2C(RNOKPP).
//       Output: proof pi1 + PUBLIC blinded commitment point M = (M.x, M.y).
//
//   STAGE 2 (server):       OprfNode.evaluate() called DIRECTLY (service/oprf-node.mjs).
//       Given M (wire hex), returns Y = k*M, a Chaum-Pedersen DLEQ proof
//       {c, z}, and the node public key Kpub = k*G.
//
//   STAGE 3 (client, ZK):   oprf_nullifier circuit.
//       From M, Y, {c,z}, Kpub, and the client's r (and rinv), prove
//       in-circuit: DLEQ verifies (Y = k*M for the same k as Kpub), unblind
//       N = rinv*Y (bound to r via r*N == Y), and commitment = pedersen(N).
//       Output: proof pi2 + the enrollment leaf commitment = pedersen(N).
//
//   ASSERTIONS:
//       (A) pi1 (enroll_commit_v2) bb-verifies.
//       (B) the node eval is internally consistent (Y == k*M, recomputed via lib).
//       (C) pi2 (oprf_nullifier) bb-verifies.
//       (D) the circuit's commitment == pedersen(k*H2C(RNOKPP)) computed
//           INDEPENDENTLY via lib.mjs — i.e. the deterministic enrollment leaf.
//       (E) DETERMINISM / Sybil: a SECOND full run with the SAME cert but a
//           DIFFERENT blinding r yields the SAME commitment.
//       (F) DISTINCTNESS: a run with a DIFFERENT cert (different RNOKPP) yields
//           a DIFFERENT commitment.
//
// SYNTHETIC certs only — NEVER fixtures/diia. Run with cwd in v3-grumpkin.
// Additive: does not touch packages/oprf/src (live v2) nor any circuit source.

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { p256 } from "../node_modules/@noble/curves/p256.js";
import { sha256 } from "../node_modules/@noble/hashes/sha2.js";
import {
    Fp,
    Fn,
    N,
    G,
    Point,
    SVDW_CONSTS,
    mapToCurveSvdW,
    hashToField2,
    hashToCurve,
    scalarLimbs,
    oprfEval,
    dleqProve,
} from "./lib.mjs";
import { OprfNode, pointToHex, pointFromHex } from "./service/oprf-node.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRCUITS = join(HERE, "circuits");
const t0 = Date.now();

// ── tiny PASS/FAIL harness ───────────────────────────────────────────────────
let failures = 0;
function check(name, cond, extra) {
    const tag = cond ? "PASS" : "FAIL";
    if (!cond) failures++;
    console.log(`  [${tag}] ${name}${extra ? "  — " + extra : ""}`);
}
function stage(label) {
    console.log(`\n── ${label} ──`);
}

// ── bb / nargo driver (mirrors the documented per-circuit sequence) ──────────
// bb prints its status (incl. "Proof verified successfully") to STDERR, while
// nargo prints "Circuit output:" to STDOUT — so we capture and return BOTH.
function sh(cmd, args, cwd) {
    const r = spawnSync(cmd, args, { cwd, encoding: "utf8" });
    if (r.status !== 0) {
        throw new Error(`${cmd} ${args.join(" ")} exited ${r.status}\n${r.stdout}\n${r.stderr}`);
    }
    return (r.stdout || "") + (r.stderr || "");
}

// nargo execute -> parse the "Circuit output:" tuple of field elements.
function nargoExecute(circuit) {
    const cwd = join(CIRCUITS, circuit);
    const out = sh("nargo", ["execute"], cwd);
    // Last line: "[name] Circuit output: (0x.., 0x.., ...)"  OR a bare "0x.." for a single Field.
    const m = out.match(/Circuit output:\s*(.+)\s*$/m);
    if (!m) throw new Error(`nargo execute(${circuit}): no Circuit output line\n${out}`);
    const fields = [...m[1].matchAll(/0x[0-9a-fA-F]+/g)].map((x) => BigInt(x[0]));
    return { out, fields };
}

// Full bb prove + verify for one circuit. Returns true iff "Proof verified successfully".
function bbProveVerify(circuit) {
    const cwd = join(CIRCUITS, circuit);
    const j = `target/${circuit}.json`;
    const w = `target/${circuit}.gz`;
    sh("bb", ["write_vk", "-b", j, "-o", "target"], cwd);
    sh("bb", ["prove", "-b", j, "-w", w, "-k", "target/vk", "-o", "target"], cwd);
    const v = sh("bb", ["verify", "-k", "target/vk", "-p", "target/proof", "-i", "target/public_inputs"], cwd);
    return /Proof verified successfully/.test(v);
}

// ── Pedersen over (n.x, n.y), matching the nullifier circuit's pedersen_hash. ─
// Reuses the verified bb.js<->Noir pedersen equivalence (same path as lib.mjs).
let _bb = null;
const toBE32 = (v) => {
    const o = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
    return o;
};
async function pedersen(fields) {
    if (!_bb) {
        const { BarretenbergSync } = await import("@aztec/bb.js");
        _bb = await BarretenbergSync.initSingleton();
    }
    const res = _bb.pedersenHash({ inputs: fields.map((f) => toBE32(Fp.create(f))), hashIndex: 0 });
    let acc = 0n;
    for (const b of res.hash) acc = (acc << 8n) | BigInt(b);
    return acc;
}

// ── synthetic cert builder (mirrors gen-enroll-commit-v2-witness.mjs) ─────────
const CERT_LEN = 768;
const TODAY = "20260530";

function buildCert(rnokpp, dob) {
    const cert = new Uint8Array(CERT_LEN);
    for (let i = 0; i < CERT_LEN; i++) cert[i] = (i * 31 + 7) & 0xff;
    const rnokppOff = 64;
    const oid = [0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0a];
    for (let i = 0; i < oid.length; i++) cert[rnokppOff + i] = oid[i];
    for (let i = 0; i < 10; i++) cert[rnokppOff + 7 + i] = rnokpp.charCodeAt(i);
    const dobOff = 200;
    for (let i = 0; i < 8; i++) cert[dobOff + i] = dob.charCodeAt(i);
    return { cert, rnokppOff, dobOff };
}

// Write circuits/enroll_commit_v2/Prover.toml for this identity + blinding r.
// Returns the JS-side expected M (so we can cross-check the circuit output).
function writeEnrollV2Toml(rnokpp, dob, r) {
    const { cert, rnokppOff, dobOff } = buildCert(rnokpp, dob);
    const msghash = sha256(cert);
    const sk = p256.utils.randomPrivateKey();
    const pubUncompressed = p256.getPublicKey(sk, false);
    const pubX = pubUncompressed.slice(1, 33);
    const pubY = pubUncompressed.slice(33, 65);
    const sigObj = p256.sign(msghash, sk, { prehash: false }).normalizeS();
    const sig = sigObj.toCompactRawBytes();
    if (!p256.verify(sigObj, msghash, pubUncompressed, { prehash: false })) {
        throw new Error("JS-side ECDSA verify failed");
    }

    // u0,u1 derived in-circuit; JS still needs them to produce SvdW sqrt hints.
    const rnokppBytes = new TextEncoder().encode(rnokpp);
    const [u0, u1] = hashToField2(rnokppBytes);
    const m0 = mapToCurveSvdW(u0);
    const m1 = mapToCurveSvdW(u1);
    const Hpt = m0.point.add(m1.point);
    const M = Hpt.multiply(Fn.create(r));

    const { c1, c2, c3, c4 } = SVDW_CONSTS;
    const { lo, hi } = scalarLimbs(r);
    const arr = (u8) => "[" + Array.from(u8).map((b) => `"${b}"`).join(", ") + "]";
    const hintArr = (h) => `["${h.inv_t}", "${h.e1}", "${h.w1}", "${h.e2}", "${h.w2}", "${h.sqrt_x}"]`;

    const toml = `# auto-generated by e2e-test.mjs (SYNTHETIC cert only)
pubkey_x = ${arr(pubX)}
pubkey_y = ${arr(pubY)}
sig = ${arr(sig)}
msghash = ${arr(msghash)}
cert = ${arr(cert)}
rnokpp_oid_off = "${rnokppOff}"
dob_off = "${dobOff}"
today = ${arr(Array.from(TODAY).map((c) => c.charCodeAt(0)))}
c1 = "${c1}"
c2 = "${c2}"
c3 = "${c3}"
c4 = "${c4}"
h0 = ${hintArr(m0.hints)}
h1 = ${hintArr(m1.hints)}
r_lo = "${lo}"
r_hi = "${hi}"
`;
    writeFileSync(join(CIRCUITS, "enroll_commit_v2", "Prover.toml"), toml);
    return { M };
}

// Write circuits/oprf_nullifier/Prover.toml from the node response + r.
function writeNullifierToml({ M, Y, c, z, r, Kpub }) {
    const rinv = Fn.inv(Fn.create(r));
    const aff = (P) => P.toAffine();
    const Ga = aff(G), Ka = aff(Kpub), Ma = aff(M), Ya = aff(Y);
    const cL = scalarLimbs(c), zL = scalarLimbs(z), riL = scalarLimbs(rinv), rL = scalarLimbs(r);
    const toml = `# auto-generated by e2e-test.mjs
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
    writeFileSync(join(CIRCUITS, "oprf_nullifier", "Prover.toml"), toml);
}

// ── one full pipeline run for a given identity + blinding scalar ─────────────
// node: the OprfNode (fixed key k) shared across runs so determinism holds.
// withProofs: run real bb prove/verify (slow); else just nargo execute + math.
async function runPipeline(node, { rnokpp, dob, r, label, withProofs }) {
    stage(label);

    // — STAGE 1: enroll_commit_v2 -> proof pi1 + public M —
    const { M: Mjs } = writeEnrollV2Toml(rnokpp, dob, r);
    const { fields: ec } = nargoExecute("enroll_commit_v2");
    const [Mx, My] = ec; // circuit return is (m.x, m.y)
    const Mcircuit = Point.fromAffine({ x: Mx, y: My });
    check(`[S1] enroll_commit_v2 nargo execute: M matches JS lib (${label})`,
        Mcircuit.equals(Mjs));

    let pi1ok = true;
    if (withProofs) {
        pi1ok = bbProveVerify("enroll_commit_v2");
        check(`[S1] enroll_commit_v2 bb proof pi1 verifies (${label})`, pi1ok);
    }

    // — STAGE 2: node.evaluate(M) directly via service/oprf-node.mjs —
    const Mhex = pointToHex(Mcircuit);
    const resp = await node.evaluate(Mhex);
    const Y = pointFromHex(resp.Y);
    const Kpub = pointFromHex(resp.Kpub);
    const c = resp.dleq.c, z = resp.dleq.z;
    // server correctness: Y == k*M (recomputed independently via lib)
    check(`[S2] node eval: Y == k*M (${label})`, Y.equals(oprfEval(node.k, Mcircuit)));
    check(`[S2] node Kpub == k*G (${label})`, Kpub.equals(node.Kpub));

    // — STAGE 3: oprf_nullifier -> proof pi2 + commitment = pedersen(N) —
    writeNullifierToml({ M: Mcircuit, Y, c, z, r, Kpub });
    const { fields: nf } = nargoExecute("oprf_nullifier");
    const commitment = nf[nf.length - 1]; // circuit return is pedersen(N)

    let pi2ok = true;
    if (withProofs) {
        pi2ok = bbProveVerify("oprf_nullifier");
        check(`[S3] oprf_nullifier bb proof pi2 verifies (${label})`, pi2ok);
    }

    // — independent expected leaf: pedersen(k * H2C(RNOKPP)) via lib —
    const Hpt = hashToCurve(new TextEncoder().encode(rnokpp));
    const Nexpected = Hpt.multiply(node.k); // k*H, the deterministic OPRF output point
    const Naff = Nexpected.toAffine();
    const leafExpected = await pedersen([Naff.x, Naff.y]);
    check(`[S3] circuit commitment == pedersen(k*H2C(RNOKPP)) [independent] (${label})`,
        commitment === leafExpected,
        `circuit=0x${commitment.toString(16).slice(0, 12)}… expected=0x${leafExpected.toString(16).slice(0, 12)}…`);

    return { commitment, pi1ok, pi2ok };
}

// ── main ─────────────────────────────────────────────────────────────────────
async function main() {
    console.log("v3 Grumpkin operator-blind enrollment — END-TO-END (build/unaudited)");
    console.log("circuits: enroll_commit_v2 (in-circuit SHA-256 H2C) + oprf_nullifier\n");

    const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;
    const k = det("crisp-qes-e2e-node-secret-k");
    const node = new OprfNode(k); // FIXED node key across all runs -> determinism holds.
    console.log("OPRF node key fixed; Kpub =", node.publicKeyHex().slice(0, 18) + "…");

    // RUN 1 — identity A, blinding r1. Full proofs.
    const A = { rnokpp: "1234567890", dob: "19900115" };
    const run1 = await runPipeline(node, {
        ...A, r: det("crisp-qes-e2e-blind-r1"), label: "RUN 1 (id A, r1, +proofs)", withProofs: true,
    });

    // RUN 2 — SAME identity A, DIFFERENT blinding r2. Full proofs.
    // Determinism / Sybil: must yield the SAME enrollment leaf as RUN 1.
    const run2 = await runPipeline(node, {
        ...A, r: det("crisp-qes-e2e-blind-r2-different"), label: "RUN 2 (id A, r2, +proofs)", withProofs: true,
    });

    // RUN 3 — DIFFERENT identity B, its own blinding r3.
    // Distinctness: must yield a DIFFERENT leaf. (nargo execute is enough here;
    // the proof machinery is already exercised by RUN 1/2.)
    const B = { rnokpp: "9876543210", dob: "19851231" };
    const run3 = await runPipeline(node, {
        ...B, r: det("crisp-qes-e2e-blind-r3"), label: "RUN 3 (id B, r3)", withProofs: false,
    });

    // ── cross-run assertions ──
    stage("CROSS-RUN ASSERTIONS");
    check("[E] determinism/Sybil: same cert + different r -> SAME leaf",
        run1.commitment === run2.commitment,
        `run1=0x${run1.commitment.toString(16).slice(0, 12)}… run2=0x${run2.commitment.toString(16).slice(0, 12)}…`);
    check("[F] distinctness: different cert -> DIFFERENT leaf",
        run1.commitment !== run3.commitment,
        `run3=0x${run3.commitment.toString(16).slice(0, 12)}…`);

    const wall = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`\n── SUMMARY ──`);
    console.log(`  total wall-clock: ${wall}s`);
    if (failures === 0) {
        console.log("  ALL STAGES PASS — pipeline composes end-to-end.");
        process.exit(0);
    } else {
        console.log(`  ${failures} CHECK(S) FAILED.`);
        process.exit(1);
    }
}

main().catch((e) => {
    console.error("\ne2e-test crashed:", e);
    process.exit(1);
});
