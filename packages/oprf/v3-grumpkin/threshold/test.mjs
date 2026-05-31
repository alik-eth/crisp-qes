// CRISP-QES v3 — Threshold OPRF validation (n=7, t=5).
// Asserts: threshold consistency across subsets, match vs single-key OPRF,
// and sub-threshold (t-1) failure. Prints PASS/FAIL per check.
//
// Run with cwd = v3-grumpkin so ../lib.mjs resolves @noble/@aztec from
// packages/oprf/node_modules:
//   node threshold/test.mjs

import { oprfEval, hashToCurve } from "../lib.mjs";
import {
    shamirSplit, dkgKeygen, partialEval, combine,
    sharePublicKey, groupPublicKey, lagrangeCoeff, Fn,
} from "./threshold-oprf.mjs";

const N_NODES = 7;
const T = 5;

let pass = 0, fail = 0;
const check = (name, ok, extra = "") => {
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? "  — " + extra : ""}`);
    ok ? pass++ : fail++;
};

// Enumerate all size-k subsets of [1..n].
function subsets(n, k) {
    const out = [];
    const rec = (start, chosen) => {
        if (chosen.length === k) { out.push([...chosen]); return; }
        for (let i = start; i <= n; i++) { chosen.push(i); rec(i + 1, chosen); chosen.pop(); }
    };
    rec(1, []);
    return out;
}

// ---------------------------------------------------------------------------
console.log(`\nCRISP-QES v3 Threshold OPRF over Grumpkin  (n=${N_NODES}, t=${T})\n`);

// Blinded client element M = hashToCurve(input). (Threshold OPRF operates on the
// already-blinded point exactly as the single-key node does — blinding is a
// client-side step orthogonal to the key split.)
const M = hashToCurve(new TextEncoder().encode("crisp-qes-threshold-test-input"));

// ===========================================================================
// PART A — Trusted-dealer Shamir split.
// A single dealer knows k, splits it, then forgets it. Simplest to validate the
// math; the dealer is a single point of trust at setup only (see DKG note below).
// ===========================================================================
{
    console.log("--- A. trusted-dealer Shamir split ---");
    const k = (() => { // a fixed-ish test key in [1,N)
        const b = new Uint8Array(32); globalThis.crypto.getRandomValues(b);
        let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x);
        return Fn.create(v || 1n);
    })();

    const { shares } = shamirSplit(k, N_NODES, T);

    // Ground truth from the single-key OPRF in lib.mjs.
    const Ysingle = oprfEval(k, M);

    // (4) group public key from k, and the Lagrange combination of share pubkeys.
    const Kpub = groupPublicKey(k);
    const allIdx = shares.map((s) => s.i);
    let KpubFromShares = null;
    for (const s of shares.slice(0, T)) { // any t share-pubkeys reconstruct Kpub in the exponent
        const idxT = shares.slice(0, T).map((x) => x.i);
        const lam = lagrangeCoeff(s.i, idxT);
        const term = sharePublicKey(s).multiply(Fn.create(lam));
        KpubFromShares = KpubFromShares === null ? term : KpubFromShares.add(term);
    }
    check("group pubkey: Lagrange(Kpub_i) == k*G", KpubFromShares.equals(Kpub));

    // Threshold consistency: every size-t subset must combine to the SAME Y,
    // and that Y must equal the single-key OPRF output.
    const subs = subsets(N_NODES, T);
    let allSame = true, allMatch = true, firstY = null;
    for (const sub of subs) {
        const partials = sub.map((idx) => partialEval(shares[idx - 1], M));
        const Y = combine(partials);
        if (firstY === null) firstY = Y; else if (!Y.equals(firstY)) allSame = false;
        if (!Y.equals(Ysingle)) allMatch = false;
    }
    check(`threshold consistency: all C(${N_NODES},${T})=${subs.length} subsets give same Y`, allSame);
    check("matches single-key OPRF: combined Y == k*M (oprfEval)", allMatch,
        `Y.x=${firstY.toAffine().x.toString(16).slice(0, 16)}…`);

    // Sub-threshold failure: t-1 partials with the t-1-point Lagrange basis must
    // NOT yield k*M (the interpolation is for the wrong polynomial degree).
    const subT1 = [1, 2, 3, 4]; // t-1 = 4 nodes
    const partialsT1 = subT1.map((idx) => partialEval(shares[idx - 1], M));
    const Ybad = combine(partialsT1);
    check("sub-threshold fails: t-1 partials != k*M", !Ybad.equals(Ysingle),
        `Ybad.x=${Ybad.toAffine().x.toString(16).slice(0, 16)}…`);
}

// ===========================================================================
// PART B — DKG-style keygen (additive, no single dealer ever holds k).
// Same three assertions; here NO party knows k (we expose kImplied only to check).
// ===========================================================================
{
    console.log("\n--- B. DKG-style keygen (no single keyholder) ---");
    const { shares, kImplied } = dkgKeygen(N_NODES, T);
    const Ysingle = oprfEval(kImplied, M);

    const subs = subsets(N_NODES, T);
    let allSame = true, allMatch = true, firstY = null;
    for (const sub of subs) {
        const partials = sub.map((idx) => partialEval(shares[idx - 1], M));
        const Y = combine(partials);
        if (firstY === null) firstY = Y; else if (!Y.equals(firstY)) allSame = false;
        if (!Y.equals(Ysingle)) allMatch = false;
    }
    check(`threshold consistency: all ${subs.length} subsets give same Y`, allSame);
    check("matches single-key OPRF: combined Y == k_implied*M", allMatch,
        `Y.x=${firstY.toAffine().x.toString(16).slice(0, 16)}…`);

    const Ybad = combine([1, 2, 3, 4].map((idx) => partialEval(shares[idx - 1], M)));
    check("sub-threshold fails: t-1 partials != k_implied*M", !Ybad.equals(Ysingle));
}

// ===========================================================================
console.log(`\n${fail === 0 ? "ALL PASS" : "SOME FAILED"}  (${pass} passed, ${fail} failed)\n`);
process.exit(fail === 0 ? 0 : 1);
