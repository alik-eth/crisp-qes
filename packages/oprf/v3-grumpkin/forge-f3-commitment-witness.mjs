// F3 FORGERY witness for oprf_commitment: non-canonical SvdW constants.
// Uses an attacker-chosen (c1,c2,c3,c4) suite that maps the SAME identity
// (u0,u1) to a DIFFERENT on-curve H2C' => DIFFERENT M, with all in-circuit
// asserts satisfied. The UNFIXED circuit accepts (it only checks hint/constant
// consistency, never that the constants are canonical).

import { writeFileSync } from "node:fs";
import { N, hashToField2, scalarLimbs } from "./lib.mjs";
import { forgedMap, forgedSuite } from "./forge-f3-lib.mjs";

const RNOKPP = new TextEncoder().encode("1234567890");
const r = (BigInt("0x" + Buffer.from("crisp-qes-test-r").toString("hex")) % (N - 1n)) + 1n;

const [u0, u1] = hashToField2(RNOKPP);
const { c1, c2, c3, c4 } = forgedSuite();
const m0 = forgedMap(u0, c1, c2, c3, c4);
const m1 = forgedMap(u1, c1, c2, c3, c4);
const Hpt = m0.point.add(m1.point);   // forged H2C'
const M = Hpt.multiply(r);
const Maff = M.toAffine();

const { lo, hi } = scalarLimbs(r);
const hintArr = (h) => `["${h.inv_t}", "${h.e1}", "${h.w1}", "${h.e2}", "${h.w2}", "${h.sqrt_x}"]`;

const toml = `# F3 FORGERY (oprf_commitment): non-canonical SvdW suite. UNFIXED circuit accepts.
u0 = "${u0}"
u1 = "${u1}"
c1 = "${c1}"
c2 = "${c2}"
c3 = "${c3}"
c4 = "${c4}"
h0 = ${hintArr(m0.hints)}
h1 = ${hintArr(m1.hints)}
r_lo = "${lo}"
r_hi = "${hi}"
mx = "${Maff.x}"
my = "${Maff.y}"
`;

writeFileSync(new URL("./circuits/oprf_commitment/Prover.toml", import.meta.url), toml);
console.log("wrote F3 FORGERY Prover.toml (oprf_commitment)");
console.log("forged M.x =", Maff.x.toString());
console.log("forged M.y =", Maff.y.toString());
