// F2 FORGERY witness for the STANDALONE oprf_nullifier (verification only; does
// NOT modify the circuit). Same honest M,Kpub,Y,DLEQ as gen-nullifier-witness,
// but rinv := 2*r^-1 (mod n) instead of r^-1, and r is set to (2*r^-1)^-1 so the
// standalone's r*N==Y group equation STILL HOLDS (because the standalone's r is
// a FREE witness unrelated to the enrollment blind). This is exactly F2: the
// standalone ACCEPTS, minting a DIFFERENT nullifier N = 2*r^-1 * Y for one
// identity. The grumpkin_voprf library REJECTS the analogous input because it
// reuses the SAME r that blinded H2C(id) (so r != (2*r^-1)^-1 there).

import { writeFileSync } from "node:fs";
import { Fn, N, G, hashToCurve, scalarLimbs, oprfEval, dleqProve } from "./lib.mjs";

const RNOKPP = new TextEncoder().encode("1234567890");
const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;
const rEnroll = det("crisp-qes-test-r");        // the blind that formed M
const k = det("crisp-qes-node-secret-k");
const t = det("crisp-qes-dleq-nonce-t");

const Kpub = G.multiply(k);
const M = hashToCurve(RNOKPP).multiply(rEnroll); // honest M = rEnroll*H2C(id)
const Y = oprfEval(k, M);
const { c, z } = await dleqProve(k, Kpub, M, Y, t);

// F2: pick rinv = 2 * rEnroll^-1 (NOT rEnroll^-1). N' = rinv*Y = 2*k*H2C(id).
const rinvForged = Fn.mul(Fn.inv(Fn.create(rEnroll)), 2n);
// Standalone's r is FREE: set it to rinvForged^-1 so r*N'==Y still holds.
const rFree = Fn.inv(rinvForged);
const Nforged = Y.multiply(rinvForged);

const aff = (P) => P.toAffine();
const Ga = aff(G), Ka = aff(Kpub), Ma = aff(M), Ya = aff(Y);
const cL = scalarLimbs(c), zL = scalarLimbs(z);
const riL = scalarLimbs(rinvForged), rL = scalarLimbs(rFree);

const toml = `# F2 FORGERY (standalone oprf_nullifier): rinv=2*r^-1, free r=(2*r^-1)^-1.
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

writeFileSync(new URL("./circuits/oprf_nullifier/Prover.toml", import.meta.url), toml);
const Naff = aff(Nforged);
console.log("wrote F2 FORGERY Prover.toml (standalone oprf_nullifier)");
console.log("forged N (=2*k*H2C) =", Naff.x.toString(), Naff.y.toString());
