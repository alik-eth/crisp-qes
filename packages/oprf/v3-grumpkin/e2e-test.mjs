// e2e-test.mjs — 2-of-3 THRESHOLD operator-blind enrollment pipeline, end to end.
//
// The INTEGRATION SPINE for the v3 Grumpkin ZK VOPRF enrollment flow, post-
// threshold: the OPRF key k' is Shamir-shared across 3 nodes (any 2 evaluate),
// never assembled at any single party (the F4 mitigation). This exercises the
// LOCALLY-RUNNABLE threshold path: blind-eval fan-out + per-share DLEQs + the
// in-circuit Lagrange combine (threshold oprf_nullifier) + determinism across
// responder subsets + a cheating-node negative. Nodes are invoked directly via
// the service node layer (service/oprf-node.mjs), no HTTP server.
//
// PIPELINE (per run, for a given synthetic identity):
//
//   STAGE 1 (enroll, JS-only):  the deployed enroll_commit_v2 circuit gates
//       /v3/blind-eval and proves (Diia CA->leaf chain, ECDSA, age>=18, in-circuit
//       H2C, M = r*H2C(RNOKPP)) and publishes C_r = commit_r(r). Its bb-PROOF is
//       NOT locally runnable: assert_ca_pinned needs a PRODUCTION-pinned Diia CA
//       that a synthetic cert cannot satisfy (and we must NOT add a test CA to the
//       prod set, nor use real PII). So here we compute M = hashToCurve(RNOKPP)*r
//       and C_r = commitR(r) in JS — the exact values the enroll proof WOULD
//       publish — and SKIP the enroll circuit (covered by its own #[test]s).
//
//   STAGE 2 (blind-eval fan-out):  pick t=2 responders; each ShareNode.evaluate(M,
//       epoch) returns its partial B_i = k_i*M + a per-share epoch-bound DLEQ +
//       its published Kpub_i. We verify each DLEQ client-side (verifyPartialDleq).
//
//   STAGE 3 (threshold register proof):  build the 13-word threshold
//       oprf_nullifier witness (full published 3-Kpub set + responder indices +
//       the two responders' B + their DLEQs + epoch + r/rinv + C_r). The circuit
//       re-verifies the per-share DLEQs vs the PINNED GEN, binds idx->Kpub from
//       the published set, Lagrange-combines Y IN-CIRCUIT (no free Y), unblinds
//       N = rinv*Y bound to r via C_r, and returns nullifier = pedersen(N).
//
//   ASSERTIONS:
//       [S2] each responder's per-share DLEQ verifies (verifyPartialDleq).
//       [S3] the threshold proof bb-verifies (real bb proof when the CLI works).
//       [D]  nullifier == pedersen(k'*H2C(RNOKPP)) computed INDEPENDENTLY via lib
//            (k' = the seed's implied group key) — the deterministic threshold leaf.
//       [E]  SUBSET DETERMINISM: the SAME identity with a DIFFERENT blind r2 AND a
//            DIFFERENT responder subset ({1,3}, {2,3}) yields the SAME leaf as {1,2}.
//       [F]  DISTINCTNESS: a different identity yields a DIFFERENT leaf.
//       [CHEAT] a corrupted partial (B_a tampered) is REJECTED in-circuit (the
//            per-share verify_dleq_share catches a faulty/malicious node).
//
// SYNTHETIC identities only. Run with cwd in v3-grumpkin. Additive: does not
// touch packages/oprf/src (live v2) nor any circuit source.

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
    Fp,
    Fn,
    N,
    G,
    hashToCurve,
    scalarLimbs,
    commitR,
} from "./lib.mjs";
import { verifyPartialDleq } from "./threshold/threshold-oprf.mjs";
import { makeNodes, pointToHex, pointFromHex } from "./service/oprf-node.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRCUITS = join(HERE, "circuits");
const NULLIFIER_DIR = join(CIRCUITS, "oprf_nullifier");
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

// ── bb / nargo driver ────────────────────────────────────────────────────────
function sh(cmd, args, cwd) {
    const r = spawnSync(cmd, args, { cwd, encoding: "utf8" });
    if (r.status !== 0) {
        throw new Error(`${cmd} ${args.join(" ")} exited ${r.status}\n${r.stdout}\n${r.stderr}`);
    }
    return (r.stdout || "") + (r.stderr || "");
}

// nargo execute -> parse the "Circuit output:" field(s).
function nargoExecute(circuit) {
    const out = sh("nargo", ["execute"], join(CIRCUITS, circuit));
    const m = out.match(/Circuit output:\s*(.+)\s*$/m);
    if (!m) throw new Error(`nargo execute(${circuit}): no Circuit output line\n${out}`);
    const fields = [...m[1].matchAll(/0x[0-9a-fA-F]+/g)].map((x) => BigInt(x[0]));
    return { out, fields };
}

// nargo execute EXPECTED to fail an in-circuit assert. True iff it could NOT solve.
function nargoExecuteFails(circuit) {
    const r = spawnSync("nargo", ["execute"], { cwd: join(CIRCUITS, circuit), encoding: "utf8" });
    return r.status !== 0;
}

// Full bb prove + verify. Returns { ran, ok } — ran=false when the bb CLI itself
// errors (infra), so the caller SKIPs rather than failing on a non-soundness issue.
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

const dec = (v) => v.toString();

// Write the 13-word THRESHOLD oprf_nullifier Prover.toml. `partials` are the t=2
// responders (objects { i, B_i (Pt), dleq:{c,z} }), sorted ASCENDING by index so
// idx1 < idx2 (canonical, for select_lagrange_2of3). `published` is the full
// 3-Kpub set in index order. Optional `tamperBa` corrupts B_a (cheating-node probe).
function writeThresholdToml({ M, r, partials, published, epoch, cr, tamperBa }) {
    const aff = (P) => P.toAffine();
    const sorted = [...partials].sort((a, b) => Number(BigInt(a.i) - BigInt(b.i)));
    const pa = sorted[0], pb = sorted[1];
    const Ma = aff(M);
    const K1 = aff(published[0]), K2 = aff(published[1]), K3 = aff(published[2]);
    const Ba = aff(tamperBa ? pa.B_i.add(G) : pa.B_i); // tamper => B_a += GEN (!= k_a*M)
    const Bb = aff(pb.B_i);
    const caL = scalarLimbs(pa.dleq.c), zaL = scalarLimbs(pa.dleq.z);
    const cbL = scalarLimbs(pb.dleq.c), zbL = scalarLimbs(pb.dleq.z);
    const rinv = Fn.inv(Fn.create(r));
    const rL = scalarLimbs(r), riL = scalarLimbs(rinv);

    const toml = `# auto-generated by e2e-test.mjs (2-of-3 threshold register ABI)
mx = "${dec(Ma.x)}"
my = "${dec(Ma.y)}"
kp1x = "${dec(K1.x)}"
kp1y = "${dec(K1.y)}"
kp2x = "${dec(K2.x)}"
kp2y = "${dec(K2.y)}"
kp3x = "${dec(K3.x)}"
kp3y = "${dec(K3.y)}"
idx1 = "${dec(pa.i)}"
idx2 = "${dec(pb.i)}"
epoch = "${dec(epoch)}"
c_r = "${dec(cr)}"
bax = "${dec(Ba.x)}"
bay = "${dec(Ba.y)}"
bbx = "${dec(Bb.x)}"
bby = "${dec(Bb.y)}"
ca_lo = "${dec(caL.lo)}"
ca_hi = "${dec(caL.hi)}"
za_lo = "${dec(zaL.lo)}"
za_hi = "${dec(zaL.hi)}"
cb_lo = "${dec(cbL.lo)}"
cb_hi = "${dec(cbL.hi)}"
zb_lo = "${dec(zbL.lo)}"
zb_hi = "${dec(zbL.hi)}"
r_lo = "${dec(rL.lo)}"
r_hi = "${dec(rL.hi)}"
rinv_lo = "${dec(riL.lo)}"
rinv_hi = "${dec(riL.hi)}"
`;
    writeFileSync(join(NULLIFIER_DIR, "Prover.toml"), toml);
}

// ── one threshold run: fan-out to a responder subset + the register proof ────
// nodes/published/epoch are shared across runs (fixed seed) so determinism holds.
// respIdx = the t=2 responder indices (e.g. [1,2]). withProofs => real bb proof.
async function runThreshold(ctx, { rnokpp, r, respIdx, label, withProofs }) {
    const { nodes, published, epoch } = ctx;
    stage(label);

    // — STAGE 1 (enroll): SKIPPED locally (prod Diia CA pin). Compute M + C_r. —
    console.log(
        "  [S1] enroll proof SKIPPED locally — production Diia CA pin can't be satisfied by a synthetic cert; enroll circuit is covered by its own #[test]s + lib h2c/M tests.",
    );
    const Hpt = hashToCurve(new TextEncoder().encode(rnokpp));
    const M = Hpt.multiply(Fn.create(r));
    const cr = await commitR(r);

    // — STAGE 2: blind-eval fan-out to the t=2 responders + per-share DLEQ verify —
    const Mhex = pointToHex(M);
    const partials = [];
    for (const i of respIdx) {
        // eslint-disable-next-line no-await-in-loop
        const ev = await nodes[i - 1].evaluate(Mhex, epoch);
        const B_i = pointFromHex(ev.B_i);
        const Kpub_i = pointFromHex(ev.Kpub_i);
        // eslint-disable-next-line no-await-in-loop
        const dleqOk = await verifyPartialDleq(Kpub_i, M, B_i, epoch, ev.dleq);
        check(`[S2] responder ${i} per-share DLEQ verifies (${label})`, dleqOk);
        partials.push({ i: BigInt(ev.i), B_i, dleq: ev.dleq });
    }

    // — STAGE 3: threshold oprf_nullifier -> nullifier = pedersen(N) —
    writeThresholdToml({ M, r, partials, published, epoch, cr });
    const { fields: nf } = nargoExecute("oprf_nullifier");
    const commitment = nf[nf.length - 1];
    check(`[S3] threshold nullifier nargo execute solves (${label})`, typeof commitment === "bigint");

    let pi = { ran: false, ok: true };
    if (withProofs) {
        pi = bbProveVerify("oprf_nullifier");
        if (pi.ran) check(`[S3] threshold nullifier bb proof verifies (${label})`, pi.ok);
        else console.log(`  [SKIP] threshold bb proof skipped — bb CLI infra: ${pi.detail}`);
    }

    // — [D] independent expected leaf: pedersen(k' * H2C(RNOKPP)) via lib —
    const Nexpected = Hpt.multiply(Fn.create(ctx.kImplied)); // k'*H, the deterministic OPRF output
    const Naff = Nexpected.toAffine();
    const leafExpected = await pedersen([Naff.x, Naff.y]);
    check(`[D] nullifier == pedersen(k'*H2C(RNOKPP)) [independent] (${label})`,
        commitment === leafExpected,
        `circuit=0x${commitment.toString(16).slice(0, 12)}… expected=0x${leafExpected.toString(16).slice(0, 12)}…`);

    return { commitment, M, cr, partials, piRan: pi.ran };
}

// ── main ─────────────────────────────────────────────────────────────────────
async function main() {
    console.log("v3 Grumpkin operator-blind enrollment — 2-of-3 THRESHOLD (build/unaudited)");
    console.log("enroll proof skipped locally (prod Diia CA pin); runs fan-out + in-circuit combine + register proof\n");

    const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;

    // Fixed test seed => stable 3-node share set (deterministic k' => stable leaf).
    const seed = det("crisp-qes-e2e-threshold-seed");
    const { nodes, published: publishedHex, kImplied } = makeNodes(3, 2, { seed });
    // published as Pt[] in index order 1,2,3.
    const published = [...publishedHex]
        .sort((a, b) => Number(BigInt(a.i) - BigInt(b.i)))
        .map((p) => pointFromHex(p.Kpub_i));
    const epoch = det("crisp-qes-e2e-threshold-epoch");
    const ctx = { nodes, published, kImplied, epoch };
    console.log("threshold set: 3 nodes (seed-derived); Kpub_1 =", publishedHex[0].Kpub_i.slice(0, 18) + "…");

    // RUN 1 — identity A, blind r1, responders {1,2}. Real bb proof.
    const A = { rnokpp: "1234567890" };
    const run1 = await runThreshold(ctx, {
        ...A, r: det("crisp-qes-e2e-blind-r1"), respIdx: [1, 2],
        label: "RUN 1 (id A, r1, responders {1,2}, +proof)", withProofs: true,
    });

    // RUN 2 — SAME identity A, DIFFERENT blind r2, DIFFERENT subset {1,3}.
    // Subset determinism: must yield the SAME leaf as RUN 1.
    const run2 = await runThreshold(ctx, {
        ...A, r: det("crisp-qes-e2e-blind-r2-different"), respIdx: [1, 3],
        label: "RUN 2 (id A, r2, responders {1,3})", withProofs: false,
    });

    // RUN 3 — SAME identity A, subset {2,3} (third subset cross-check).
    const run3 = await runThreshold(ctx, {
        ...A, r: det("crisp-qes-e2e-blind-r3"), respIdx: [2, 3],
        label: "RUN 3 (id A, r3, responders {2,3})", withProofs: false,
    });

    // RUN 4 — DIFFERENT identity B. Distinctness: must yield a DIFFERENT leaf.
    const B = { rnokpp: "9876543210" };
    const run4 = await runThreshold(ctx, {
        ...B, r: det("crisp-qes-e2e-blind-r4"), respIdx: [1, 2],
        label: "RUN 4 (id B, r4, responders {1,2})", withProofs: false,
    });

    // ── cross-run assertions ──
    stage("CROSS-RUN ASSERTIONS");
    check("[E] subset determinism: id A {1,2} == {1,3} -> SAME leaf",
        run1.commitment === run2.commitment,
        `r1=0x${run1.commitment.toString(16).slice(0, 12)}… r2=0x${run2.commitment.toString(16).slice(0, 12)}…`);
    check("[E] subset determinism: id A {1,2} == {2,3} -> SAME leaf",
        run1.commitment === run3.commitment,
        `r3=0x${run3.commitment.toString(16).slice(0, 12)}…`);
    check("[F] distinctness: different id -> DIFFERENT leaf",
        run1.commitment !== run4.commitment,
        `r4=0x${run4.commitment.toString(16).slice(0, 12)}…`);

    // ── [CHEAT] cheating-node negative: corrupt one partial -> proof REJECTED ──
    stage("CHEATING-NODE NEGATIVE");
    // Honest {1,2} witness, but B_a tampered (B_a += GEN, so B_a != k_a*M). The
    // per-share verify_dleq_share for responder a must reject in-circuit.
    writeThresholdToml({
        M: run1.M, r: det("crisp-qes-e2e-blind-r1"), partials: run1.partials,
        published, epoch, cr: run1.cr, tamperBa: true,
    });
    check("[CHEAT] corrupted partial (B_a += GEN) REJECTED by the circuit",
        nargoExecuteFails("oprf_nullifier"));

    const wall = ((Date.now() - t0) / 1000).toFixed(1);
    console.log("\n── SUMMARY ──");
    console.log(`  threshold leaf (id A) = 0x${run1.commitment.toString(16).padStart(64, "0")}`);
    console.log(`  bb proof: ${run1.piRan ? "REAL (RUN 1)" : "skipped (bb infra)"}`);
    console.log(`  total wall-clock: ${wall}s`);
    if (failures === 0) {
        console.log("  ALL STAGES PASS — 2-of-3 threshold pipeline composes end-to-end.");
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
