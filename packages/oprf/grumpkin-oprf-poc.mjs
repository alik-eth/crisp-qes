// Phase-0 PoC (task #39, Scenario B): 2HashDH VOPRF over Grumpkin.
// Validates the protocol end-to-end -- determinism (the Sybil property),
// unblind correctness, distinctness, DLEQ -- using the REAL RFC-9380 SvdW
// hash-to-curve from ./grumpkin-h2c.mjs (no longer try-and-increment).
//
// Still feasibility-grade: the H2C constants/DST aren't finalized and the
// suite hasn't had a security review -- that's the standing cost of leaving
// RFC-9497. But the construction is now RFC-9380-shaped, not a placeholder.
//
// Grumpkin: y^2 = x^3 - 17 over F_p (p = BN254 scalar field). Group order n =
// BN254 base field. Cofactor 1 (no subgroup clearing, unlike ristretto255).

import { Point, Fp, n, G, hashToCurveGrumpkin } from "./grumpkin-h2c.mjs";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes } from "@noble/hashes/utils";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils";

const Fn = Field(n);
import { Field } from "@noble/curves/abstract/modular";

let cnt = 0;
const randScalar = () =>
    (bytesToNumberBE(sha256(numberToBytesBE(BigInt(Date.now()) ^ (BigInt(cnt++) << 64n), 32))) % (n - 1n)) + 1n;
const modn = (x) => ((x % n) + n) % n;
const invn = (x) => Fn.inv(modn(x));

// --- 2HashDH VOPRF ---
const k = randScalar();          // server secret key
const Kpub = G.multiply(k);      // server public key

const clientBlind = (input) => { const P = hashToCurveGrumpkin(input); const r = randScalar(); return { P, r, B: P.multiply(r) }; };
const serverEval = (B) => B.multiply(k);
const clientUnblind = (E, r) => E.multiply(invn(r));
const finalize = (input, Npoint) => sha256(concatBytes(input, Npoint.toBytes(true)));

// --- DLEQ (Chaum-Pedersen): prove E=k*B and Kpub=k*G share k ---
const challenge = (...pts) => modn(bytesToNumberBE(sha256(concatBytes(...pts.map((P) => P.toBytes(true))))));
function dleqProve(B, E) {
    const t = randScalar();
    const c = challenge(G, Kpub, B, E, G.multiply(t), B.multiply(t));
    return { c, z: modn(t + modn(c * k)) };
}
function dleqVerify(B, E, { c, z }) {
    const A1 = G.multiply(z).add(Kpub.multiply(modn(-c)));
    const A2 = B.multiply(z).add(E.multiply(modn(-c)));
    return challenge(G, Kpub, B, E, A1, A2) === c;
}

// === checks ===
const rnokpp = new TextEncoder().encode("1234567890");
let pass = true;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); pass &&= ok; };

const s1 = clientBlind(rnokpp), s2 = clientBlind(rnokpp);
const N1 = finalize(rnokpp, clientUnblind(serverEval(s1.B), s1.r));
const N2 = finalize(rnokpp, clientUnblind(serverEval(s2.B), s2.r));
check("determinism: same RNOKPP + same k -> same OPRF output (Sybil property)", bytesToNumberBE(N1) === bytesToNumberBE(N2));
check("unblind correctness: r^-1 * (k*r*P) == k*P", clientUnblind(serverEval(s1.B), s1.r).equals(s1.P.multiply(k)));

const m2 = new TextEncoder().encode("9999999999");
const o = clientBlind(m2);
const No = finalize(m2, clientUnblind(serverEval(o.B), o.r));
check("distinctness: different RNOKPP -> different output", bytesToNumberBE(N1) !== bytesToNumberBE(No));

const proof = dleqProve(s1.B, serverEval(s1.B));
check("DLEQ verifies for honest eval", dleqVerify(s1.B, serverEval(s1.B), proof));
check("DLEQ rejects tampered eval (wrong key)", !dleqVerify(s1.B, s1.B.multiply(k + 1n), proof));

void Fp; void Point;
console.log(`\n${pass ? "ALL PASS - 2HashDH VOPRF over Grumpkin with RFC-9380 SvdW H2C" : "FAILURES"}`);
process.exit(pass ? 0 : 1);
