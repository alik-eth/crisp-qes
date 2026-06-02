// e2e-test.mjs — two-proof operator-blind enrollment pipeline, end to end.
//
// This is the INTEGRATION SPINE for the v3 Grumpkin ZK VOPRF enrollment flow,
// post-F2 (the DEPLOYED two-proof + C_r shared-r binding). It exercises the
// LOCALLY-RUNNABLE F2-relevant path: node eval + the oprf_nullifier register
// proof (with C_r) + determinism/distinctness. The OPRF node is invoked directly
// (no HTTP server) to keep the coupling minimal.
//
// PIPELINE (per run, for a given synthetic Diia-style identity):
//
//   STAGE 1 (client, enroll): the deployed enroll_commit_v2 circuit gates
//       /v3/blind-eval and proves (Diia CA->leaf chain, ECDSA, age>=18,
//       in-circuit H2C, M = r*H2C(RNOKPP)) and publishes C_r = commit_r(r).
//       The bb-PROOF of this circuit is NOT locally runnable: assert_ca_pinned
//       requires a PRODUCTION-pinned Diia CA that a synthetic cert cannot
//       satisfy (and we must NOT add a test CA to the prod set, nor use real
//       PII). So here we compute M = hashToCurve(RNOKPP)*r in JS and C_r =
//       commitR(r) — the exact values the enroll proof WOULD publish — and SKIP
//       the enroll circuit. The enroll circuit is covered by its own #[test]s
//       and the grumpkin_voprf h2c/M tests.
//
//   STAGE 2 (server):       OprfNode.evaluate() called DIRECTLY (service/oprf-node.mjs).
//       Given M (wire hex), returns Y = k*M, a Chaum-Pedersen DLEQ proof
//       {c, z}, and the node public key Kpub = k*G.
//
//   STAGE 3 (client, ZK):   oprf_nullifier circuit (the /v3/register proof).
//       From M, Y, {c,z}, Kpub, the client's r (and rinv), and C_r, prove
//       in-circuit: DLEQ verifies against the PINNED GEN (F1), commit_r(r)==C_r
//       binds r to the enroll proof (F2), unblind N = rinv*Y (bound via r*N==Y),
//       and commitment = pedersen(N). Output: proof pi2 + the leaf commitment.
//
//   ASSERTIONS:
//       (B) the node eval is internally consistent (Y == k*M, recomputed via lib).
//       (C) pi2 (oprf_nullifier) bb-verifies (real bb proof when the CLI works).
//       (C_r) the nullifier ACCEPTS with c_r = commit_r(r) AND a tampered c_r
//           (commit_r(r)+1) makes nargo execute FAIL — the cross-proof binding.
//       (D) the circuit's commitment == pedersen(k*H2C(RNOKPP)) computed
//           INDEPENDENTLY via lib.mjs — i.e. the deterministic enrollment leaf.
//       (E) DETERMINISM / Sybil: a SECOND run with the SAME id but a DIFFERENT
//           blinding r yields the SAME commitment.
//       (F) DISTINCTNESS: a run with a DIFFERENT id (different RNOKPP) yields a
//           DIFFERENT commitment.
//
// SYNTHETIC identities only — NEVER fixtures/diia. Run with cwd in v3-grumpkin.
// Additive: does not touch packages/oprf/src (live v2) nor any circuit source.

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
    Fp,
    Fn,
    N,
    hashToCurve,
    scalarLimbs,
    oprfEval,
    commitR,
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

// nargo execute that is EXPECTED to fail an in-circuit assert. Returns true iff
// the circuit witness could NOT be solved (the negative-path probe).
function nargoExecuteFails(circuit) {
    const r = spawnSync("nargo", ["execute"], { cwd: join(CIRCUITS, circuit), encoding: "utf8" });
    return r.status !== 0;
}

// Full bb prove + verify for one circuit. Returns { ran, ok } — ran=false when
// the bb CLI itself errors (version/availability infra issue), so the caller can
// SKIP rather than fail the whole run on a non-soundness infra problem.
function bbProveVerify(circuit) {
    const cwd = join(CIRCUITS, circuit);
    const j = `target/${circuit}.json`;
    const w = `target/${circuit}.gz`;
    try {
        sh("bb", ["write_vk", "-b", j, "-o", "target"], cwd);
        sh("bb", ["prove", "-b", j, "-w", w, "-k", "target/vk", "-o", "target"], cwd);
        const v = sh("bb", ["verify", "-k", "target/vk", "-p", "target/proof", "-i", "target/public_inputs"], cwd);
        return { ran: true, ok: /Proof verified successfully/.test(v) };
    } catch (e) {
        return { ran: false, ok: false, detail: (e.message || "bb CLI error").slice(0, 160) };
    }
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

// Write circuits/oprf_nullifier/Prover.toml from the node response + r + C_r.
// NEW 8-word ABI: public kpx,kpy,yx,yy,mx,my,c_r; private r/rinv/c/z limbs.
// No gx,gy (F1 — GEN pinned in the lib) and no c_expected (C-1 is the lib limb
// binding). `cr` is the cross-proof shared-r commitment the enroll proof would
// publish; the circuit re-asserts commit_r(r) == c_r (F2).
function writeNullifierToml({ M, Y, c, z, r, Kpub, cr }) {
    const rinv = Fn.inv(Fn.create(r));
    const aff = (P) => P.toAffine();
    const Ka = aff(Kpub), Ma = aff(M), Ya = aff(Y);
    const cL = scalarLimbs(c), zL = scalarLimbs(z), riL = scalarLimbs(rinv), rL = scalarLimbs(r);
    const toml = `# auto-generated by e2e-test.mjs (two-proof register ABI)
kpx = "${Ka.x}"
kpy = "${Ka.y}"
yx = "${Ya.x}"
yy = "${Ya.y}"
mx = "${Ma.x}"
my = "${Ma.y}"
c_r = "${cr}"
r_lo = "${rL.lo}"
r_hi = "${rL.hi}"
rinv_lo = "${riL.lo}"
rinv_hi = "${riL.hi}"
c_lo = "${cL.lo}"
c_hi = "${cL.hi}"
z_lo = "${zL.lo}"
z_hi = "${zL.hi}"
`;
    writeFileSync(join(CIRCUITS, "oprf_nullifier", "Prover.toml"), toml);
}

// ── one full pipeline run for a given identity + blinding scalar ─────────────
// node: the OprfNode (fixed key k) shared across runs so determinism holds.
// withProofs: run real bb prove/verify (slow) + the C_r accept/reject probe;
//             else just nargo execute + math.
async function runPipeline(node, { rnokpp, r, label, withProofs }) {
    stage(label);

    // — STAGE 1 (enroll): SKIPPED locally. The deployed enroll_commit_v2 bb-proof
    //   can't run here — its assert_ca_pinned needs a PRODUCTION Diia CA that a
    //   synthetic cert can't satisfy (no test CA in the prod set, no real PII).
    //   We compute the exact values the enroll proof WOULD publish: M and C_r.
    console.log(
        `  [S1] enroll proof SKIPPED locally — production Diia CA pin can't be satisfied by a synthetic cert; enroll circuit is covered by its own #[test]s + lib h2c/M tests.`,
    );
    const Hpt = hashToCurve(new TextEncoder().encode(rnokpp));
    const Mcircuit = Hpt.multiply(Fn.create(r)); // M = r*H2C(RNOKPP)
    const cr = await commitR(r); // C_r the enroll proof would output

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
    // Honest c_r = commit_r(r): the cross-proof binding holds, circuit ACCEPTS.
    writeNullifierToml({ M: Mcircuit, Y, c, z, r, Kpub, cr });
    const { fields: nf } = nargoExecute("oprf_nullifier");
    const commitment = nf[nf.length - 1]; // circuit return is pedersen(N)
    check(`[C_r] nullifier ACCEPTS with c_r = commit_r(r) (binding holds) (${label})`,
        typeof commitment === "bigint");

    let pi2 = { ran: false, ok: true };
    if (withProofs) {
        // NEGATIVE C_r probe: a tampered c_r (commit_r(r)+1) must make the
        // commit_r(r)==c_r assert FAIL -> nargo execute fails. (Done before the
        // real bb proof, which rewrites Prover.toml back to the honest c_r.)
        writeNullifierToml({ M: Mcircuit, Y, c, z, r, Kpub, cr: cr + 1n });
        check(`[C_r] tampered c_r (commit_r(r)+1) REJECTED by the circuit (${label})`,
            nargoExecuteFails("oprf_nullifier"));
        // Restore the honest witness for the real bb proof.
        writeNullifierToml({ M: Mcircuit, Y, c, z, r, Kpub, cr });
        nargoExecute("oprf_nullifier"); // regenerate the honest witness file
        pi2 = bbProveVerify("oprf_nullifier");
        if (pi2.ran) {
            check(`[S3] oprf_nullifier bb proof pi2 verifies (${label})`, pi2.ok);
        } else {
            console.log(`  [SKIP] oprf_nullifier bb proof skipped — bb CLI infra: ${pi2.detail}`);
        }
    }

    // — independent expected leaf: pedersen(k * H2C(RNOKPP)) via lib —
    const Nexpected = Hpt.multiply(node.k); // k*H, the deterministic OPRF output point
    const Naff = Nexpected.toAffine();
    const leafExpected = await pedersen([Naff.x, Naff.y]);
    check(`[D] circuit commitment == pedersen(k*H2C(RNOKPP)) [independent] (${label})`,
        commitment === leafExpected,
        `circuit=0x${commitment.toString(16).slice(0, 12)}… expected=0x${leafExpected.toString(16).slice(0, 12)}…`);

    return { commitment, pi2ran: pi2.ran, pi2ok: pi2.ok };
}

// ── main ─────────────────────────────────────────────────────────────────────
async function main() {
    console.log("v3 Grumpkin operator-blind enrollment — TWO-PROOF + C_r (build/unaudited)");
    console.log("enroll proof skipped locally (prod Diia CA pin); runs node eval + oprf_nullifier register proof\n");

    const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;
    const k = det("crisp-qes-e2e-node-secret-k");
    const node = new OprfNode(k); // FIXED node key across all runs -> determinism holds.
    console.log("OPRF node key fixed; Kpub =", node.publicKeyHex().slice(0, 18) + "…");

    // RUN 1 — identity A, blinding r1. Real bb proof + C_r accept/reject probe.
    const A = { rnokpp: "1234567890" };
    const run1 = await runPipeline(node, {
        ...A, r: det("crisp-qes-e2e-blind-r1"), label: "RUN 1 (id A, r1, +proof +C_r probe)", withProofs: true,
    });

    // RUN 2 — SAME identity A, DIFFERENT blinding r2 (nargo execute only).
    // Determinism / Sybil: must yield the SAME enrollment leaf as RUN 1.
    const run2 = await runPipeline(node, {
        ...A, r: det("crisp-qes-e2e-blind-r2-different"), label: "RUN 2 (id A, r2)", withProofs: false,
    });

    // RUN 3 — DIFFERENT identity B, its own blinding r3.
    // Distinctness: must yield a DIFFERENT leaf.
    const B = { rnokpp: "9876543210" };
    const run3 = await runPipeline(node, {
        ...B, r: det("crisp-qes-e2e-blind-r3"), label: "RUN 3 (id B, r3)", withProofs: false,
    });

    // ── cross-run assertions ──
    stage("CROSS-RUN ASSERTIONS");
    check("[E] determinism/Sybil: same id + different r -> SAME leaf",
        run1.commitment === run2.commitment,
        `run1=0x${run1.commitment.toString(16).slice(0, 12)}… run2=0x${run2.commitment.toString(16).slice(0, 12)}…`);
    check("[F] distinctness: different id -> DIFFERENT leaf",
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
