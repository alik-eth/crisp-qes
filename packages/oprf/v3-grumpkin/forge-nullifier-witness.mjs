// C-1 forgery probe: build the witness the audit used to forge a DLEQ for a
// FAKE Y (Y != k*M), with arbitrary z + c limbs and c_expected := pedersen(...).
// Pre-fix this passed (forgery). Post-fix the binding assert
// (c_lo + c_hi*2^128 == ch) must make `nargo execute` FAIL.
import { writeFileSync } from "node:fs";
import { Fp, N, Fn, G, hashToCurve, scalarLimbs } from "./lib.mjs";
import { bytesToNumberBE } from "@noble/curves/utils";

const toBE32 = (v) => { const o = new Uint8Array(32); for (let i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
let _bb = null;
async function pedersen(fields) {
  if (!_bb) { const { BarretenbergSync } = await import("@aztec/bb.js"); _bb = await BarretenbergSync.initSingleton(); }
  return bytesToNumberBE(_bb.pedersenHash({ inputs: fields.map((f) => toBE32(Fp.create(f))), hashIndex: 0 }).hash);
}

const k = 1234567n;                       // honest node key
const Kpub = G.multiply(Fn.create(k));
const r = 7654321n, rinv = Fn.inv(Fn.create(r));
const H = hashToCurve(new TextEncoder().encode("1234567890"));
const M = H.multiply(Fn.create(r));       // M = r*H2C(input)
const Yfake = M.multiply(Fn.create(k + 1n)); // FAKE: Y != k*M

// attacker picks z and c FREELY (not from any discrete log)
const z = 42n, c = 99n;
const negKpub = Kpub.negate(), negY = Yfake.negate();
const a1 = G.multiply(Fn.create(z)).add(negKpub.multiply(Fn.create(c)));   // z*G - c*Kpub
const a2 = M.multiply(Fn.create(z)).add(negY.multiply(Fn.create(c)));      // z*M - c*Yfake
const Ga = G.toAffine(), Ka = Kpub.toAffine(), Ma = M.toAffine(), Ya = Yfake.toAffine(), a1a = a1.toAffine(), a2a = a2.toAffine();
const cexp = await pedersen([Ga.x, Ga.y, Ka.x, Ka.y, Ma.x, Ma.y, Ya.x, Ya.y, a1a.x, a1a.y, a2a.x, a2a.y]);

const cl = scalarLimbs(c), zl = scalarLimbs(z), ril = scalarLimbs(rinv), rl = scalarLimbs(r);
writeFileSync(new URL("./circuits/oprf_nullifier/Prover.toml", import.meta.url), `# FORGERY probe (expect FAIL post-fix)
gx="${Ga.x}"
gy="${Ga.y}"
kpx="${Ka.x}"
kpy="${Ka.y}"
mx="${Ma.x}"
my="${Ma.y}"
yx="${Ya.x}"
yy="${Ya.y}"
c_lo="${cl.lo}"
c_hi="${cl.hi}"
z_lo="${zl.lo}"
z_hi="${zl.hi}"
rinv_lo="${ril.lo}"
rinv_hi="${ril.hi}"
r_lo="${rl.lo}"
r_hi="${rl.hi}"
c_expected="${cexp}"
`);
console.log("forgery witness written: arbitrary c=" + c + ", c_expected=ch=" + cexp.toString().slice(0, 16) + "...");
console.log("c_lo+c_hi*2^128 == c =", c, "!= ch  -> new binding assert must fail");
