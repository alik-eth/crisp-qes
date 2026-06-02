// THRESHOLD adversarial regression guard against the 2-of-3 oprf_nullifier.
//
// The threshold register circuit (grumpkin_voprf::oprf::oprf_nullify_threshold)
// self-attests the t-of-n eval and closes review #7:
//   * per-share epoch-bound DLEQ vs the PINNED GEN for each responder
//     (verify_dleq_share) -- a faulty/malicious node (B_i != k_i*M) is caught;
//   * idx->Kpub bound IN-CIRCUIT from the PUBLISHED set (select_kpub_3) -- a
//     mislabeled (Kpub,idx,B) cannot pass;
//   * combine() index dedup (select_lagrange_2of3 asserts a canonical 2-of-3 set);
//   * session/epoch binding (epoch in every per-share DLEQ transcript).
//
// This builds forged 13-word witnesses and asserts the circuit REJECTS each via
// `nargo execute`. Exits NONZERO if any forgery is ACCEPTED (regression guard).
// Mirrors forge-f2-nullifier-witness.mjs. All forgeries reuse the SAME honest
// seed/epoch/identity as gen-threshold-nullifier-witness.mjs.

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Fn, N, G, hashToCurve, scalarLimbs, commitR, dleqProveShare } from "./lib.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const NULLIFIER_DIR = join(HERE, "circuits", "oprf_nullifier");
const PROVER_TOML = join(NULLIFIER_DIR, "Prover.toml");
const det = (l) => (BigInt("0x" + Buffer.from(l).toString("hex")) % (N - 1n)) + 1n;
const aff = (P) => P.toAffine();
const dec = (v) => v.toString();

// ── honest threshold material (matches gen-threshold-nullifier-witness.mjs) ──
const r = det("crisp-qes-test-r");
const M = hashToCurve(new TextEncoder().encode("1234567890")).multiply(r);
const rinv = Fn.inv(Fn.create(r));
const cR = await commitR(r);
const kPrime = det("crisp-qes-threshold-kprime-epoch1");
const a = det("crisp-qes-threshold-poly-a1");
const f = (x) => Fn.add(Fn.create(kPrime), Fn.mul(Fn.create(a), Fn.create(x)));
const k = { 1: f(1n), 2: f(2n), 3: f(3n) };
const Kpub = {}, B = {};
for (const i of [1, 2, 3]) { Kpub[i] = G.multiply(Fn.create(k[i])); B[i] = M.multiply(Fn.create(k[i])); }
const epoch = det("crisp-qes-threshold-epoch-1");
const D = {};
for (const i of [1, 2, 3]) D[i] = await dleqProveShare(Kpub[i], k[i], M, B[i], epoch, det("crisp-qes-thr-nonce-" + i));

const K1 = aff(Kpub[1]), K2 = aff(Kpub[2]), K3 = aff(Kpub[3]);
const Maff = aff(M);
const rL = scalarLimbs(r), riL = scalarLimbs(rinv);

// Write a 13-word threshold Prover.toml. Fields default to the honest {1,2}
// witness; `o` overrides any field for a forgery.
function writeToml(banner, o = {}) {
    const Ba = aff(o.Ba ?? B[1]), Bb = aff(o.Bb ?? B[2]);
    const Da = o.Da ?? D[1], Db = o.Db ?? D[2];
    const DaL = { c: scalarLimbs(Da.c), z: scalarLimbs(Da.z) };
    const DbL = { c: scalarLimbs(Db.c), z: scalarLimbs(Db.z) };
    const kp = o.kp ?? { 1: K1, 2: K2, 3: K3 };
    writeFileSync(PROVER_TOML, `# ${banner}
mx = "${dec(Maff.x)}"
my = "${dec(Maff.y)}"
kp1x = "${dec(kp[1].x)}"
kp1y = "${dec(kp[1].y)}"
kp2x = "${dec(kp[2].x)}"
kp2y = "${dec(kp[2].y)}"
kp3x = "${dec(kp[3].x)}"
kp3y = "${dec(kp[3].y)}"
idx1 = "${dec(o.idx1 ?? 1n)}"
idx2 = "${dec(o.idx2 ?? 2n)}"
epoch = "${dec(o.epoch ?? epoch)}"
c_r = "${dec(o.cr ?? cR)}"
bax = "${dec(Ba.x)}"
bay = "${dec(Ba.y)}"
bbx = "${dec(Bb.x)}"
bby = "${dec(Bb.y)}"
ca_lo = "${dec(DaL.c.lo)}"
ca_hi = "${dec(DaL.c.hi)}"
za_lo = "${dec(DaL.z.lo)}"
za_hi = "${dec(DaL.z.hi)}"
cb_lo = "${dec(DbL.c.lo)}"
cb_hi = "${dec(DbL.c.hi)}"
zb_lo = "${dec(DbL.z.lo)}"
zb_hi = "${dec(DbL.z.hi)}"
r_lo = "${dec(rL.lo)}"
r_hi = "${dec(rL.hi)}"
rinv_lo = "${dec(riL.lo)}"
rinv_hi = "${dec(riL.hi)}"
`);
}

function nargoExecute() {
    const res = spawnSync("nargo", ["execute"], { cwd: NULLIFIER_DIR, encoding: "utf8" });
    return { rejected: res.status !== 0, out: (res.stdout || "") + (res.stderr || "") };
}

let failures = 0;
function expectReject(label, expectedMsg) {
    const { rejected, out } = nargoExecute();
    const tripped = expectedMsg ? out.includes(expectedMsg) : true;
    if (rejected && tripped) {
        console.log(`  [REJECTED] ${label}${expectedMsg ? ` -> tripped: "${expectedMsg}"` : ""}`);
    } else if (rejected) {
        console.log(`  [REJECTED] ${label} (expected "${expectedMsg}"; verify the assert)`);
        console.log(out.split("\n").filter((l) => /assert|Failed|constraint/i.test(l)).slice(0, 3).join("\n"));
        failures++;
    } else {
        console.error(`  [ACCEPTED] ${label} -> #7 REGRESSION: the forgery was NOT rejected!`);
        failures++;
    }
}

console.log("Threshold (2-of-3) adversarial re-verify against oprf_nullifier:\n");

// (F-share) CHEATING NODE: responder 1's partial is forged under an ATTACKER key
// k', with an HONEST-looking per-share DLEQ for k' (vs the attacker's Kpub). But
// the witness labels it idx1=1, so select_kpub_3 picks the PUBLISHED Kpub_1 and
// verify_dleq_share checks (Kpub_1, M, k'*M) -> B_a != k_1*M -> C-1 fails.
{
    const kAtt = det("crisp-qes-threshold-ATTACKER-k");
    const KpubAtt = G.multiply(Fn.create(kAtt));
    const BAtt = M.multiply(Fn.create(kAtt));
    const DAtt = await dleqProveShare(KpubAtt, kAtt, M, BAtt, epoch, det("crisp-qes-thr-att-nonce"));
    writeToml("F-share: B_a = k_attacker*M (honest DLEQ for wrong k) under idx1=1", { Ba: BAtt, Da: DAtt });
    expectReject("(F-share) cheating node: B_a != k_1*M");
}

// (F-dup) DUPLICATE INDEX: idx1 == idx2 == 1 -> select_lagrange_2of3 rejects.
writeToml("F-dup: idx1 == idx2 == 1", { idx1: 1n, idx2: 1n, Bb: B[1], Db: D[1] });
expectReject("(F-dup) duplicate responder index", "invalid 2-of-3 responder set");

// (F-epoch) STALE EPOCH: honest partials/DLEQs (built for epoch E), but the
// public epoch field set to E+1 -> the epoch-bound transcript C-1 binding fails.
writeToml("F-epoch: honest DLEQs for E, public epoch = E+1", { epoch: epoch + 1n });
expectReject("(F-epoch) stale epoch (DLEQ for E, verified at E+1)");

// (F-kpubswap) KPUB SWAP: swap published Kpub_1 <-> Kpub_2 so idx->kpub selects a
// key the DLEQ wasn't made against -> verify_dleq_share fails. (Demonstrates the
// in-circuit idx->kpub binding; responders/DLEQs are otherwise honest {1,2}.)
writeToml("F-kpubswap: published Kpub_1 <-> Kpub_2 swapped", { kp: { 1: K2, 2: K1, 3: K3 } });
expectReject("(F-kpubswap) idx->kpub bound to published set");

if (failures > 0) {
    console.error(`\n${failures} threshold forgery/forgeries NOT properly rejected.`);
    process.exit(1);
}
console.log("\nAll threshold forgeries REJECTED (#7 closed: per-share DLEQ + dedup + epoch + idx->kpub).");
