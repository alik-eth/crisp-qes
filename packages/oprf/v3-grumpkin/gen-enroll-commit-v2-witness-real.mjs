// REAL-cert witness generator for enroll_commit_v2 (Diia trust-chain circuit).
//
// Reads a REAL Diia .p7s (path in env P7S_PATH), parses it with the proven SDK
// parseP7s, and emits circuits/enroll_commit_v2/Prover.toml with the NEW chain
// fields (leaf_tbs / ca_pubkey / leaf_cert_sig / leaf_spki_off) so the real
// Diia CA->leaf->key->challenge chain is exercised end-to-end against the
// PRODUCTION pinned set.
//
// PII DISCIPLINE: this script NEVER prints RNOKPP, DOB, or any cert bytes. It
// prints only structural sizes, offsets, and pass/fail verdicts. The written
// Prover.toml contains PII-derived bytes and is gitignored (verified) -- do not
// commit it.
//
// Run:  P7S_PATH="/abs/path/to/file.p7s" node gen-enroll-commit-v2-witness-real.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { p256 } from "./node_modules/@noble/curves/p256.js";
import { sha256 } from "./node_modules/@noble/hashes/sha2.js";
import { parseP7s } from "../../sdk/dist/index.js";
import { N, SVDW_CONSTS, mapToCurveSvdW, hashToField2, scalarLimbs } from "./lib.mjs";

const LEAF_TBS_LEN = 1536; // circuit global
const SA_LEN = 2048; // circuit global

// Production pinned Diia QTSP CA keys (must match circuit DIIA_PINNED_CA).
const PINNED = [
  {
    name: "UA-43395033-2311",
    x: "8500048265e919c1738e873572c1f6443895a0c03985fc71bd96a6f62a53bcc8",
    y: "69d23ca6e6a2a7dc443bbb2a0b914ee35f1c74e282ecd8e6c5287c7a3d4aee10",
  },
  {
    name: "UA-43395033-2503",
    x: "c8b3546f4a34c021a31b3578057d1de304cbf1743a391b2032cd5b7d37184148",
    y: "c2440ea2fba10872b0bc90a92371ad50f59d0e9c0216ed52fd259b8a8cc9ee54",
  },
];

const P7S_PATH = process.env.P7S_PATH;
if (!P7S_PATH) throw new Error("set P7S_PATH to the .p7s file");

const i2osp32 = (v) => {
  const o = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
  return o;
};
const toHex = (u8) => Buffer.from(u8).toString("hex");
const lowSCompact = ({ r, s }) => new p256.Signature(r, s).normalizeS().toCompactRawBytes();

// --- offset finders (mirror packages/web/src/lib/p7sWitness.ts) -------------
function indexOf(hay, needle, from = 0) {
  const last = hay.length - needle.length;
  outer: for (let i = from; i <= last; i++) {
    for (let k = 0; k < needle.length; k++) if (hay[i + k] !== needle[k]) continue outer;
    return i;
  }
  return -1;
}
const RNOKPP_OID = Uint8Array.from([0x06, 0x03, 0x55, 0x04, 0x05]);
const RNOKPP_PREFIX = Uint8Array.from([0x13, 0x10, 0x54, 0x49, 0x4e, 0x55, 0x41, 0x2d]); // 13 10 "TINUA-"
const DOB_OID = Uint8Array.from([0x06, 0x0c, 0x2a, 0x86, 0x67, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x01, 0x04, 0x0b, 0x01]);

function findRnokppOidOffset(buf) {
  let from = 0;
  for (;;) {
    const oidAt = indexOf(buf, RNOKPP_OID, from);
    if (oidAt < 0) break;
    const strAt = oidAt + RNOKPP_OID.length;
    let ok = strAt + RNOKPP_PREFIX.length <= buf.length;
    for (let k = 0; ok && k < RNOKPP_PREFIX.length; k++) if (buf[strAt + k] !== RNOKPP_PREFIX[k]) ok = false;
    if (ok) {
      const d = strAt + RNOKPP_PREFIX.length;
      let allDigits = d + 10 <= buf.length;
      for (let k = 0; allDigits && k < 10; k++) { const b = buf[d + k]; if (b < 0x30 || b > 0x39) allDigits = false; }
      if (allDigits) return oidAt;
    }
    from = oidAt + 1;
  }
  throw new Error("RNOKPP run not found in leaf TBS");
}
function findDobOffset(buf) {
  const oidAt = indexOf(buf, DOB_OID, 0);
  const from = oidAt >= 0 ? oidAt + DOB_OID.length : 0;
  // first 8-contiguous-ASCII-digit run after the DOB OID
  for (let i = from; i + 8 <= buf.length; i++) {
    let ok = true;
    for (let k = 0; k < 8; k++) { const b = buf[i + k]; if (b < 0x30 || b > 0x39) { ok = false; break; } }
    if (ok) return i;
  }
  throw new Error("DOB 8-digit run not found in leaf TBS");
}

// ===========================================================================
const p7sBytes = new Uint8Array(readFileSync(P7S_PATH));
const parsed = parseP7s(p7sBytes);

// --- leaf TBS (CA-authenticated buffer) ---
const tbs = parsed.leafTbsBytes;
if (tbs.length > LEAF_TBS_LEN) throw new Error(`leaf TBS ${tbs.length} B > LEAF_TBS_LEN ${LEAF_TBS_LEN}`);
const leafTbs = new Uint8Array(LEAF_TBS_LEN);
leafTbs.set(tbs, 0);
const leafTbsLen = tbs.length;

// --- CA pubkey: the issuer that signed the leaf TBS (intermediate) ---
const inter = parsed.intermediatePubkey;
let caPubX, caPubY, caUncompressed, caMatch = null;
if (inter) {
  caPubX = i2osp32(inter.x); caPubY = i2osp32(inter.y);
} else {
  // No intermediate embedded: try each pinned CA against the leaf cert sig.
  caPubX = null;
}
const eLeaf = sha256(leafTbs.subarray(0, leafTbsLen));
const leafCertSig = lowSCompact(parsed.leafCertSignature);

function caVerify(xHex, yHex) {
  const unc = new Uint8Array(65); unc[0] = 0x04;
  unc.set(Buffer.from(xHex, "hex"), 1); unc.set(Buffer.from(yHex, "hex"), 33);
  const sigObj = new p256.Signature(parsed.leafCertSignature.r, parsed.leafCertSignature.s).normalizeS();
  return p256.verify(sigObj, eLeaf, unc, { prehash: false });
}

if (caPubX) {
  const xh = toHex(caPubX), yh = toHex(caPubY);
  caMatch = PINNED.find((p) => p.x === xh && p.y === yh) || null;
} else {
  // pick whichever pinned CA verifies the leaf cert signature
  const hit = PINNED.find((p) => caVerify(p.x, p.y));
  if (hit) { caPubX = Buffer.from(hit.x, "hex"); caPubY = Buffer.from(hit.y, "hex"); caMatch = hit; }
}

// --- leaf SPKI offset (auto-detect 0x04 marker placement) ---
const spkiGuess = parsed.leafPubkeyOffset;
let leafSpkiOff = -1;
const pubX = i2osp32(parsed.pubkey.x), pubY = i2osp32(parsed.pubkey.y);
for (const off of [spkiGuess, spkiGuess + 1]) {
  if (off >= 1 && off + 64 <= leafTbsLen && leafTbs[off - 1] === 0x04) {
    let ok = true;
    for (let k = 0; k < 32; k++) if (leafTbs[off + k] !== pubX[k] || leafTbs[off + 32 + k] !== pubY[k]) { ok = false; break; }
    if (ok) { leafSpkiOff = off; break; }
  }
}

// --- RNOKPP / DOB offsets inside the authenticated leaf TBS ---
const rnokppOff = findRnokppOidOffset(leafTbs.subarray(0, leafTbsLen));
const dobOff = findDobOffset(leafTbs.subarray(0, leafTbsLen));
const rnokppDigits = Buffer.from(leafTbs.subarray(rnokppOff + 13, rnokppOff + 23)).toString("latin1");

// --- signer ECDSA over signedAttrs ---
const sig = lowSCompact(parsed.signature);
if (parsed.signedAttrs.length > SA_LEN) throw new Error(`signedAttrs ${parsed.signedAttrs.length} > SA_LEN`);
const signedAttrs = new Uint8Array(SA_LEN);
signedAttrs.set(parsed.signedAttrs, 0);
const signedAttrsLen = parsed.signedAttrs.length;
const msgDigestOff = parsed.messageDigestOffset - 2;
const mdOk = signedAttrs[msgDigestOff] === 0x04 && signedAttrs[msgDigestOff + 1] === 0x20;

// --- JS-side crypto self-checks (the same the circuit will enforce) ---
const leafUnc = new Uint8Array(65); leafUnc[0] = 0x04; leafUnc.set(pubX, 1); leafUnc.set(pubY, 33);
const msghash = sha256(signedAttrs.subarray(0, signedAttrsLen));
const signerOk = p256.verify(new p256.Signature(parsed.signature.r, parsed.signature.s).normalizeS(), msghash, leafUnc, { prehash: false });
const caSigOk = caMatch ? caVerify(caMatch.x, caMatch.y) : false;

// --- OPRF / hash-to-curve over the RNOKPP digits ---
const [u0, u1] = hashToField2(new TextEncoder().encode(rnokppDigits));
const m0 = mapToCurveSvdW(u0), m1 = mapToCurveSvdW(u1);
const Hpt = m0.point.add(m1.point);
const r = (BigInt("0x" + Buffer.from("crisp-qes-real-e2e-r").toString("hex")) % (N - 1n)) + 1n;
const M = Hpt.multiply(r).toAffine();
const { c1, c2, c3, c4 } = SVDW_CONSTS;
const { lo, hi } = scalarLimbs(r);

const TODAY = "20260531";

// ---- structural report (NO PII) ----
console.log("=== parseP7s (structural, no PII) ===");
console.log("leaf_tbs_len      :", leafTbsLen, "(<= " + LEAF_TBS_LEN + ")");
console.log("signed_attrs_len  :", signedAttrsLen);
console.log("msg_digest_off    :", msgDigestOff, "04 20 header ok:", mdOk);
console.log("leaf_spki_off     :", leafSpkiOff, "(SDK guess:", spkiGuess + ")", leafSpkiOff >= 0 ? "BOUND-OK" : "*** SPKI BIND FAILED ***");
console.log("rnokpp_oid_off    :", rnokppOff, " dob_off:", dobOff);
console.log("intermediate emb. :", inter ? "yes" : "no (tried pinned against leaf sig)");
console.log("CA pin match      :", caMatch ? caMatch.name : "*** NONE — leaf not signed by a pinned Diia CA ***");
console.log("JS leaf-cert sig  :", caSigOk ? "VERIFIES (CA->leaf)" : "*** FAIL ***");
console.log("JS signer sig     :", signerOk ? "VERIFIES (leaf->signedAttrs)" : "*** FAIL ***");
console.log("M (blinded, safe) : x=" + M.x.toString(16).slice(0, 16) + "... y=" + M.y.toString(16).slice(0, 16) + "...");

const arr = (u8) => "[" + Array.from(u8).map((b) => `"${b}"`).join(", ") + "]";
const hintArr = (h) => `["${h.inv_t}", "${h.e1}", "${h.w1}", "${h.e2}", "${h.w2}", "${h.sqrt_x}"]`;
const toml = `# auto-generated by gen-enroll-commit-v2-witness-real.mjs  (REAL Diia .p7s)
# CONTAINS PII-derived bytes (leaf TBS has RNOKPP + DOB). gitignored; never commit.
pubkey_x = ${arr(pubX)}
pubkey_y = ${arr(pubY)}
sig = ${arr(sig)}
signed_attrs = ${arr(signedAttrs)}
signed_attrs_len = "${signedAttrsLen}"
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
c1 = "${c1}"
c2 = "${c2}"
c3 = "${c3}"
c4 = "${c4}"
h0 = ${hintArr(m0.hints)}
h1 = ${hintArr(m1.hints)}
r_lo = "${lo}"
r_hi = "${hi}"
`;
writeFileSync(new URL("./circuits/enroll_commit_v2/Prover.toml", import.meta.url), toml);
console.log("\nwrote Prover.toml (REAL cert). Ready for `nargo execute`.");
if (!caMatch || !caSigOk || !signerOk || leafSpkiOff < 0 || !mdOk) {
  console.log("\n*** PRE-CHECK FAILED — nargo execute will reject. See markers above. ***");
  process.exit(2);
}
console.log("PRE-CHECK PASSED — all JS-side chain checks green.");
