// Phase-0 PoC (task #39, Scenario B): does a 2HashDH VOPRF work cleanly over
// Grumpkin (the SNARK-friendly curve we chose)? This validates the *protocol*
// end-to-end in JS — determinism (the Sybil property), correctness, DLEQ —
// before committing to re-implementing the OPRF off ristretto255.
//
// NOT production crypto. Hash-to-curve here is try-and-increment (fine for a
// feasibility check on a cofactor-1 curve; a real build needs RFC-9380 SSWU +
// a security review — that's the standing caveat for leaving RFC-9497).
//
// Grumpkin: y^2 = x^3 - 17 over F_p (p = BN254 scalar field). Group order n =
// BN254 base field. Cofactor 1 (cleaner than ristretto: no subgroup clearing).

import { weierstrassPoints } from "@noble/curves/abstract/weierstrass";
import { Field } from "@noble/curves/abstract/modular";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes } from "@noble/hashes/utils";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils";

const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const n = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Fp = Field(p);
const b = Fp.create(-17n);

// Find a generator: cofactor 1 => any curve point generates the whole group.
function onCurveY(x) {
    const rhs = Fp.add(Fp.mul(Fp.mul(x, x), x), b); // x^3 + b  (a=0)
    if (!Fp.isValid(rhs) || !isSquare(rhs)) return null;
    return Fp.sqrt(rhs);
}
function isSquare(v) { try { Fp.sqrt(v); return true; } catch { return false; } }

let Gx = 1n, Gy = null;
for (let x = 1n; x < 50n; x++) { const y = onCurveY(Fp.create(x)); if (y !== null) { Gx = Fp.create(x); Gy = y; break; } }
if (Gy === null) throw new Error("no generator found");

const { Point } = weierstrassPoints({
    a: 0n, b, Fp, n, h: 1n, Gx, Gy,
});
const G = Point.BASE;

const randScalar = () => (bytesToNumberBE(sha256(numberToBytesBE(BigInt(Math.floor(Date.now())) ^ (BigInt(cnt++) << 64n), 32))) % (n - 1n)) + 1n;
let cnt = 0;
const modn = (x) => ((x % n) + n) % n;
const invn = (x) => Field(n).inv(modn(x));

// --- hash-to-curve (try-and-increment; PoC only) ---
function hashToCurve(inputBytes) {
    for (let ctr = 0; ctr < 256; ctr++) {
        const x = Fp.create(bytesToNumberBE(sha256(concatBytes(inputBytes, new Uint8Array([ctr])))));
        const y = onCurveY(x);
        if (y !== null) return Point.fromAffine({ x, y });
    }
    throw new Error("h2c failed");
}

// --- 2HashDH VOPRF ---
const k = randScalar();          // server secret key
const Kpub = G.multiply(k);      // server public key

function clientBlind(input) {
    const P = hashToCurve(input);
    const r = randScalar();
    return { P, r, B: P.multiply(r) };        // B = r*P
}
function serverEval(B) { return B.multiply(k); }        // E = k*B
function clientUnblind(E, r) { return E.multiply(invn(r)); }  // r^-1 * E = k*P
function finalize(input, Npoint) {
    return sha256(concatBytes(input, Npoint.toBytes(true)));
}

// --- DLEQ (Chaum-Pedersen): prove E=k*B and Kpub=k*G share k ---
function ptBytes(P) { return P.toBytes(true); }
function challenge(...pts) { return modn(bytesToNumberBE(sha256(concatBytes(...pts.map(ptBytes))))); }
function dleqProve(B, E) {
    const t = randScalar();
    const A1 = G.multiply(t), A2 = B.multiply(t);
    const c = challenge(G, Kpub, B, E, A1, A2);
    const z = modn(t + modn(c * k));
    return { c, z };
}
function dleqVerify(B, E, { c, z }) {
    const A1 = G.multiply(z).add(Kpub.multiply(modn(-c)));   // z*G - c*Kpub
    const A2 = B.multiply(z).add(E.multiply(modn(-c)));      // z*B - c*E
    return challenge(G, Kpub, B, E, A1, A2) === c;
}

// === checks ===
const rnokpp = new TextEncoder().encode("1234567890");
let pass = true;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); pass &&= ok; };

// 1. Determinism: two independent blindings of the same input -> same output.
const s1 = clientBlind(rnokpp), s2 = clientBlind(rnokpp);
const N1 = finalize(rnokpp, clientUnblind(serverEval(s1.B), s1.r));
const N2 = finalize(rnokpp, clientUnblind(serverEval(s2.B), s2.r));
check("determinism: same RNOKPP + same k -> same OPRF output (Sybil property)", bytesToNumberBE(N1) === bytesToNumberBE(N2));

// 2. Unblind correctness: k*P recovered.
check("unblind correctness: r^-1 * (k*r*P) == k*P", clientUnblind(serverEval(s1.B), s1.r).equals(s1.P.multiply(k)));

// 3. Distinctness: different RNOKPP -> different output.
const other = clientBlind(new TextEncoder().encode("9999999999"));
const No = finalize(new TextEncoder().encode("9999999999"), clientUnblind(serverEval(other.B), other.r));
check("distinctness: different RNOKPP -> different output", bytesToNumberBE(N1) !== bytesToNumberBE(No));

// 4. DLEQ verifies, and a tampered evaluation is rejected.
const proof = dleqProve(s1.B, serverEval(s1.B));
check("DLEQ verifies for honest eval", dleqVerify(s1.B, serverEval(s1.B), proof));
check("DLEQ rejects tampered eval (wrong key)", !dleqVerify(s1.B, s1.B.multiply(k + 1n), proof));

console.log(`\nGrumpkin generator: x=${Gx}`);
console.log(`group order prime, cofactor 1: no subgroup clearing needed (vs ristretto255).`);
console.log(`\n${pass ? "ALL PASS - 2HashDH VOPRF works over Grumpkin" : "FAILURES - see above"}`);
process.exit(pass ? 0 : 1);
