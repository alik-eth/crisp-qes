// Generate Prover.toml for the enroll_commit_v2 circuit with the Diia
// trust-chain additions. The witness now carries the leaf certificate TBS
// (CA-authenticated), a SYNTHETIC test-CA signature over it, the pinned-style
// CA pubkey, and the offsets of the leaf SPKI / RNOKPP OID / DOB INSIDE the
// leaf TBS. RNOKPP/DOB are read from the authenticated leaf_tbs (the free
// cert[] input is gone).
//
// SOUNDNESS: the SYNTHETIC test CA used here is NOT one of the production
// pinned Diia keys, so `nargo execute` against the production circuit (whose
// pinned set is the real Diia keys) WILL fail assert_ca_pinned -- that is
// expected. The happy-path PROVING with the synthetic CA is validated by the
// in-circuit #[test] functions (which pass the synthetic pinned set). This
// generator's Prover.toml is primarily for negative-path `nargo execute`
// checks and for the witness-shape reference.
//
// Variants (env WITNESS_VARIANT):
//   happy            - well-formed witness (chain consistent; will fail
//                      assert_ca_pinned in production main as noted above).
//   bad_pubkey       - (negative c) pubkey_x/y != leaf SPKI in leaf_tbs.
//   bad_rnokpp_oob   - (negative d) rnokpp_oid_off points outside leaf_tbs_len.
//
// SYNTHETIC disposable cert only. Run with cwd in v3-grumpkin.

import { writeFileSync } from "node:fs";
import { p256 } from "./node_modules/@noble/curves/p256.js";
import { sha256 } from "./node_modules/@noble/hashes/sha2.js";
import {
  N,
  Fn,
  G,
  mapToCurveSvdW,
  hashToField2,
  scalarLimbs,
  oprfEval,
  dleqProve,
} from "./lib.mjs";

const VARIANT = process.env.WITNESS_VARIANT || "happy";

// Must match the circuit globals.
const LEAF_TBS_LEN = 1536;
const SA_LEN = 2048;

const RNOKPP = "1234567890";
const DOB = "19900115";
const TODAY = "20260530";

// --- synthetic leaf keypair (the cert subject's key, signs signedAttrs) ---
const leafSeed = sha256(new TextEncoder().encode("crisp-qes-synthetic-test-leaf-v1"));
const leafSk = leafSeed;
const leafPubUncompressed = p256.getPublicKey(leafSk, false); // 04 || X || Y
const leafPubX = leafPubUncompressed.slice(1, 33);
const leafPubY = leafPubUncompressed.slice(33, 65);

// --- synthetic test CA (signs the leaf TBS); NOT a production pinned key ---
const caSeed = sha256(new TextEncoder().encode("crisp-qes-synthetic-test-ca-v1"));
const caSk = caSeed;
const caPubUncompressed = p256.getPublicKey(caSk, false);
const caPubX = caPubUncompressed.slice(1, 33);
const caPubY = caPubUncompressed.slice(33, 65);

// --- build the leaf TBS carrying SPKI + RNOKPP + DOB ---
const leafTbsLen = 900;
const leafTbs = new Uint8Array(LEAF_TBS_LEN);
for (let i = 0; i < leafTbsLen; i++) leafTbs[i] = (i * 17 + 5) & 0xff;

const spkiMarkerOff = 100; // 0x04 marker
const leafSpkiOff = spkiMarkerOff + 1; // X[0]
leafTbs[spkiMarkerOff] = 0x04;
leafTbs.set(leafPubX, leafSpkiOff);
leafTbs.set(leafPubY, leafSpkiOff + 32);

let rnokppOff = 300;
const oid = [0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x10];
for (let i = 0; i < oid.length; i++) leafTbs[rnokppOff + i] = oid[i];
const TINUA = "TINUA-";
for (let i = 0; i < TINUA.length; i++) leafTbs[rnokppOff + 7 + i] = TINUA.charCodeAt(i);
for (let i = 0; i < 10; i++) leafTbs[rnokppOff + 13 + i] = RNOKPP.charCodeAt(i);

const dobOff = 500;
for (let i = 0; i < 8; i++) leafTbs[dobOff + i] = DOB.charCodeAt(i);

// CA signs sha256_var(leaf_tbs, leaf_tbs_len).
const eLeaf = sha256(leafTbs.subarray(0, leafTbsLen));
const caSigObj = p256.sign(eLeaf, caSk, { prehash: false }).normalizeS();
const leafCertSig = caSigObj.toCompactRawBytes();
if (!p256.verify(caSigObj, eLeaf, caPubUncompressed, { prehash: false })) {
  throw new Error("synthetic CA sig self-verify failed");
}

// --- OPRF / hash-to-curve material ---
// Deterministic test scalars in [1, N) (mirror gen-nullifier-witness.mjs):
//   r = client blinding scalar (the SAME r that blinds M AND unblinds N),
//   k = node OPRF secret, t = DLEQ proof nonce.
const det = (label) => (BigInt("0x" + Buffer.from(label).toString("hex")) % (N - 1n)) + 1n;
const r = det("crisp-qes-test-r");
const k = det("crisp-qes-node-secret-k");
const t = det("crisp-qes-dleq-nonce-t");

const rnokppBytes = new TextEncoder().encode(RNOKPP);
const [u0, u1] = hashToField2(rnokppBytes);
const m0 = mapToCurveSvdW(u0);
const m1 = mapToCurveSvdW(u1);
const Hpt = m0.point.add(m1.point);

const Kpub = G.multiply(k); // node public key Kpub = k*G
const M = Hpt.multiply(r); // blinded element M = r*H2C(RNOKPP)
const Maff = M.toAffine();
const Y = oprfEval(k, M); // node response Y = k*M
const { c, z } = await dleqProve(k, Kpub, M, Y, t); // Chaum-Pedersen DLEQ
const rinv = Fn.inv(Fn.create(r)); // r^-1 (mod n); the circuit forces this via r*N==Y

const Ka = Kpub.toAffine();
const Ya = Y.toAffine();

// --- bound challenge (v3) -------------------------------------------------
const INTENT = "crisp-qes-enroll-v3";
const EPOCH = "v3-2026";
const be32 = (v) => v.toString(16).padStart(64, "0");
const Mhex = `0x${be32(Maff.x)}${be32(Maff.y)}`;
const challenge = new TextEncoder().encode(
  `{"intent":"${INTENT}","epoch":"${EPOCH}","blindedInput":"${Mhex}"}`,
);
const messageDigest = sha256(challenge); // 32 bytes

// Minimal synthetic signedAttrs: [pad 8][04 20 <messageDigest>][pad 8].
const SA_USED = 8 + 2 + 32 + 8; // 50 bytes used
const signedAttrs = new Uint8Array(SA_LEN);
for (let i = 0; i < 8; i++) signedAttrs[i] = (i * 13 + 1) & 0xff;
const msgDigestOff = 8;
signedAttrs[msgDigestOff] = 0x04;
signedAttrs[msgDigestOff + 1] = 0x20;
signedAttrs.set(messageDigest, msgDigestOff + 2);
for (let i = 0; i < 8; i++) signedAttrs[42 + i] = (i * 7 + 3) & 0xff;
const msghash = sha256(signedAttrs.subarray(0, SA_USED));

// signedAttrs is signed by the LEAF key (which the circuit binds to the SPKI).
const sigObj = p256.sign(msghash, leafSk, { prehash: false }).normalizeS();
let sig = sigObj.toCompactRawBytes();
if (!p256.verify(sigObj, msghash, leafPubUncompressed, { prehash: false })) {
  throw new Error("JS-side leaf ECDSA verify failed");
}

// --- scalar limbs for the new ABI ---
const { lo, hi } = scalarLimbs(r);
const cL = scalarLimbs(c);
const zL = scalarLimbs(z);
const riL = scalarLimbs(rinv);

// --- apply negative-variant tampering ---
let outPubX = leafPubX;
let outPubY = leafPubY;
if (VARIANT === "bad_pubkey") {
  // (negative c): claim a DIFFERENT pubkey than the leaf SPKI in leaf_tbs, and
  // re-sign signedAttrs with that key so only the cert<->pubkey bind fails.
  const otherSk = sha256(new TextEncoder().encode("crisp-qes-attacker-key"));
  const otherPub = p256.getPublicKey(otherSk, false);
  outPubX = otherPub.slice(1, 33);
  outPubY = otherPub.slice(33, 65);
  sig = p256.sign(msghash, otherSk, { prehash: false }).normalizeS().toCompactRawBytes();
}
if (VARIANT === "bad_rnokpp_oob") {
  // (negative d): point rnokpp_oid_off into the UNAUTHENTICATED padding region
  // (>= leaf_tbs_len). The circuit's `rnokpp_oid_off + 23 <= leaf_tbs_len`
  // bound must reject this. Plant a valid-looking RNOKPP block there so only
  // the bound check (not the digit asserts) is what fails.
  rnokppOff = leafTbsLen + 50; // 950, outside [0, 900)
  for (let i = 0; i < oid.length; i++) leafTbs[rnokppOff + i] = oid[i];
  for (let i = 0; i < TINUA.length; i++) leafTbs[rnokppOff + 7 + i] = TINUA.charCodeAt(i);
  for (let i = 0; i < 10; i++) leafTbs[rnokppOff + 13 + i] = RNOKPP.charCodeAt(i);
}

const arr = (u8) => "[" + Array.from(u8).map((b) => `"${b}"`).join(", ") + "]";
const hintArr = (h) => `["${h.inv_t}", "${h.e1}", "${h.w1}", "${h.e2}", "${h.w2}", "${h.sqrt_x}"]`;

const toml = `# auto-generated by gen-enroll-commit-v2-witness.mjs (v3 FUSED OPRF + Diia chain)
# SYNTHETIC disposable cert + signedAttrs + synthetic test CA. Never a real Diia cert.
# New ABI (Task 2): SvdW c1..c4 removed (pinned in grumpkin_voprf); node OPRF
# Kpub/Y + DLEQ (c,z) + rinv added for the fused single-proof OPRF.
# WITNESS_VARIANT = ${VARIANT}
pubkey_x = ${arr(outPubX)}
pubkey_y = ${arr(outPubY)}
sig = ${arr(sig)}
signed_attrs = ${arr(signedAttrs)}
signed_attrs_len = "${SA_USED}"
msg_digest_off = "${msgDigestOff}"
leaf_tbs = ${arr(leafTbs)}
leaf_tbs_len = "${leafTbsLen}"
ca_pubkey_x = ${arr(caPubX)}
ca_pubkey_y = ${arr(caPubY)}
leaf_cert_sig = ${arr(leafCertSig)}
leaf_spki_off = "${leafSpkiOff}"
rnokpp_oid_off = "${rnokppOff}"
dob_off = "${dobOff}"
today = ${arr(Array.from(TODAY).map((c) => c.charCodeAt(0)))}
kpx = "${Ka.x}"
kpy = "${Ka.y}"
yx = "${Ya.x}"
yy = "${Ya.y}"
h0 = ${hintArr(m0.hints)}
h1 = ${hintArr(m1.hints)}
r_lo = "${lo}"
r_hi = "${hi}"
c_lo = "${cL.lo}"
c_hi = "${cL.hi}"
z_lo = "${zL.lo}"
z_hi = "${zL.hi}"
rinv_lo = "${riL.lo}"
rinv_hi = "${riL.hi}"
`;

writeFileSync(new URL("./circuits/enroll_commit_v2/Prover.toml", import.meta.url), toml);
console.log("wrote Prover.toml (variant:", VARIANT, ")");
console.log("RNOKPP        =", RNOKPP, " DOB =", DOB, " today =", TODAY);
console.log("leaf_tbs_len  =", leafTbsLen, " leaf_spki_off =", leafSpkiOff, " rnokpp_off =", rnokppOff);
console.log("NOTE: synthetic CA != production pinned Diia keys; production main()");
console.log("      assert_ca_pinned WILL reject this witness (expected).");
