// End-to-end roundtrip for the v3 Grumpkin VOPRF service (build, unaudited).
//
// Exercises the full client<->node flow using ONLY ../lib.mjs primitives on the
// client side, so any divergence between the server (which also uses lib.mjs)
// and an independent client computation surfaces as a FAIL:
//
//   1. client blinds a test input:   M = r * H2C(input)
//   2. POST /v3/blind-eval -> { Y, dleq:{c,z}, Kpub }
//   3. client verifies the DLEQ proof against Kpub  (Chaum-Pedersen)
//   4. client unblinds:               N = rinv * Y
//   5. determinism: assert N == k_pub-consistent  k*H2C(input)
//      (checked via N == r^-1 * (k*M) == k*H, and independently that the
//       server's Y == k*M by recomputing with the known dev key)
//
// The server runs IN-PROCESS (buildApp + app.inject) so no port is needed and
// the test is hermetic. Prints PASS/FAIL per check; exits non-zero on any FAIL.

import {
    G, N, Fn, hashToCurve, oprfEval, dleqProve,
    Point,
} from "../lib.mjs";
import { buildApp } from "./server.mjs";
import { OprfNode, pointToHex, pointFromHex } from "./oprf-node.mjs";

let failures = 0;
function check(name, cond, extra) {
    const tag = cond ? "PASS" : "FAIL";
    if (!cond) failures++;
    console.log(`  [${tag}] ${name}${extra ? "  — " + extra : ""}`);
}

// Pedersen Fiat-Shamir challenge recompute — must equal lib's dleqProve `c`.
// We re-derive it the same way dleqProve does, but from the verifier's
// reconstructed a1', a2'. Reuse lib by calling dleqProve is NOT valid (it needs
// k), so we replicate only the transcript hash via a tiny helper that defers to
// the same pedersen path lib uses. Simplest correct approach: verify the
// algebraic relation z*G == a1 + c*Kpub and z*M == a2 + c*Y, where we recover
// a1 = z*G - c*Kpub and a2 = z*M - c*Y, then recompute c via the SAME pedersen
// transcript and require it matches. We import the transcript hasher from lib
// indirectly by re-running dleqProve-style hashing through a local copy is
// avoided; instead we test the two equations AND a full c-recompute using a
// freshly proven reference, below.

async function main() {
    console.log("v3 Grumpkin VOPRF roundtrip (build, unaudited)\n");

    // Deterministic test material (mirrors gen-nullifier-witness.mjs det()).
    const det = (label) =>
        (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;
    const k = det("crisp-qes-v3-roundtrip-node-k");
    const r = det("crisp-qes-v3-roundtrip-blind-r");
    const input = new TextEncoder().encode("1234567890"); // test RNOKPP

    // Node with KNOWN key so the test can independently recompute k*M and k*H.
    const node = new OprfNode(k);
    const Kpub = node.Kpub;
    const app = await buildApp({ node, logger: false });

    // — 1. client blinds ─────────────────────────────────────────────────
    const H = hashToCurve(input);             // H2C(input)
    const M = H.multiply(Fn.create(r));       // M = r*H
    const Mhex = pointToHex(M);

    // — 2. POST /v3/blind-eval (in-process inject) ───────────────────────
    const res = await app.inject({
        method: "POST",
        url: "/v3/blind-eval",
        payload: { M: Mhex, proof: { placeholder: "deferred" } },
    });
    check("server responded 200", res.statusCode === 200, `status=${res.statusCode}`);
    const body = res.json();

    // — wire round-trips ─────────────────────────────────────────────────
    const Y = pointFromHex(body.Y);
    const KpubWire = pointFromHex(body.Kpub);
    const c = BigInt(body.dleq.c);
    const z = BigInt(body.dleq.z);
    check("Kpub on wire == node Kpub", KpubWire.equals(Kpub));
    check("point hex round-trips (M)", pointFromHex(Mhex).equals(M));

    // — server correctness: Y == k*M ─────────────────────────────────────
    const Yexpected = oprfEval(k, M);
    check("server Y == k*M", Y.equals(Yexpected));

    // — 3. verify DLEQ proof against Kpub ────────────────────────────────
    // dleqProve set: a1 = t*G, a2 = t*M, z = t + c*k (mod N).
    // Verifier recovers a1' = z*G - c*Kpub, a2' = z*M - c*Y, then recomputes
    // the Fiat-Shamir challenge c' over the same transcript and requires c'==c.
    const cN = Fn.create(c);
    const zN = Fn.create(z);
    const a1v = G.multiply(zN).add(Kpub.multiply(Fn.create(N - cN)));   // z*G - c*Kpub
    const a2v = M.multiply(zN).add(Y.multiply(Fn.create(N - cN)));      // z*M - c*Y

    // Recompute c' using the SAME transcript+pedersen path lib uses. We obtain
    // it by re-deriving the challenge with a known-good reference proof: run
    // dleqProve with the SAME nonce t implied by a1v ( = z - c*k ), which we
    // can compute since the test owns k. c' must equal c.
    const tRecovered = Fn.sub(zN, Fn.mul(cN, Fn.create(k))); // t = z - c*k mod N
    const a1ref = G.multiply(tRecovered);
    const a2ref = M.multiply(tRecovered);
    check("DLEQ: recovered a1 (z*G - c*Kpub) == t*G", a1v.equals(a1ref));
    check("DLEQ: recovered a2 (z*M - c*Y) == t*M", a2v.equals(a2ref));

    // Full Fiat-Shamir check: feed the verifier-reconstructed points back
    // through dleqProve's challenge derivation (re-prove with same t, same
    // k) and confirm the challenge it produces equals the c we received.
    const reproven = await dleqProve(k, Kpub, M, Y, tRecovered);
    check("DLEQ: Fiat-Shamir challenge c recomputes", reproven.c === c);
    check("DLEQ: response z recomputes", reproven.z === z);

    // — 4. client unblinds: N = rinv * Y ─────────────────────────────────
    const rinv = Fn.inv(Fn.create(r));
    const Npt = Y.multiply(rinv);

    // — 5. determinism / correctness: N == k * H2C(input) ────────────────
    const Nexpected = H.multiply(Fn.create(k)); // k*H, the true OPRF output
    check("unblind: N == k*H2C(input) (OPRF determinism)", Npt.equals(Nexpected));

    // Determinism across a second independent blind r2: same input -> same N.
    const r2 = det("crisp-qes-v3-roundtrip-blind-r2");
    const M2 = H.multiply(Fn.create(r2));
    const res2 = await app.inject({
        method: "POST", url: "/v3/blind-eval", payload: { M: pointToHex(M2) },
    });
    const Y2 = pointFromHex(res2.json().Y);
    const N2 = Y2.multiply(Fn.inv(Fn.create(r2)));
    check("determinism: different blind r2 -> same unblinded N", N2.equals(Npt));

    // — negative: malformed M rejected (proof gating deferred but M gated) ─
    const bad = await app.inject({
        method: "POST", url: "/v3/blind-eval", payload: { M: "0xdeadbeef" },
    });
    check("rejects malformed M with 400", bad.statusCode === 400, `status=${bad.statusCode}`);

    // — negative: off-curve point rejected ───────────────────────────────
    const offCurve = "0x" + "01".padStart(64, "0") + "02".padStart(64, "0");
    const bad2 = await app.inject({
        method: "POST", url: "/v3/blind-eval", payload: { M: offCurve },
    });
    check("rejects off-curve point with 400", bad2.statusCode === 400, `status=${bad2.statusCode}`);

    await app.close();

    console.log("");
    if (failures === 0) {
        console.log("ALL CHECKS PASS");
        process.exit(0);
    } else {
        console.log(`${failures} CHECK(S) FAILED`);
        process.exit(1);
    }
}

main().catch((e) => {
    console.error("roundtrip crashed:", e);
    process.exit(1);
});
