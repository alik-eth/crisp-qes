// Generate a SYNTHETIC Diia-chain test tuple for the enroll_commit_v2 Noir
// #[test] functions. Produces a valid (synthetic_ca_pubkey, leaf_cert_sig,
// leaf_tbs) tuple where a SYNTHETIC test CA signs a synthetic leaf TBS that
// carries the RNOKPP OID block, DOB, and the leaf SPKI P-256 point.
//
// CRITICAL: the synthetic CA private key lives ONLY here (and is regenerated
// deterministically from a fixed seed). It is NEVER added to main()'s pinned
// DIIA_PINNED_CA set. The Noir tests pass this synthetic CA as the `pinned`
// parameter to assert_diia_chain; production main() passes the real Diia set.
//
// Emits Noir array literals to paste into src/main.nr's #[test] block.
// Run with cwd in v3-grumpkin: node gen-chain-test-tuple.mjs

import { p256 } from "./node_modules/@noble/curves/p256.js";
import { sha256 } from "./node_modules/@noble/hashes/sha2.js";

const LEAF_TBS_LEN = 1536;

// --- deterministic synthetic test CA (NOT a Diia key) ---
// Fixed 32-byte seed so the test tuple is reproducible across runs.
const caSeed = sha256(new TextEncoder().encode("crisp-qes-synthetic-test-ca-v1"));
const caSk = caSeed; // 32 bytes, valid P-256 scalar with overwhelming prob.
const caPubUncompressed = p256.getPublicKey(caSk, false);
const caPubX = caPubUncompressed.slice(1, 33);
const caPubY = caPubUncompressed.slice(33, 65);

// --- synthetic leaf keypair (the cert subject's key) ---
const leafSeed = sha256(new TextEncoder().encode("crisp-qes-synthetic-test-leaf-v1"));
const leafSk = leafSeed;
const leafPubUncompressed = p256.getPublicKey(leafSk, false); // 04 || X || Y
const leafPubX = leafPubUncompressed.slice(1, 33);
const leafPubY = leafPubUncompressed.slice(33, 65);

// --- build the synthetic leaf TBS carrying RNOKPP + DOB + SPKI ---
const RNOKPP = "1234567890";
const DOB = "19900115";

const leafTbsLen = 900; // < LEAF_TBS_LEN; exercises sha256_var over a subrange.
const leafTbs = new Uint8Array(LEAF_TBS_LEN);
for (let i = 0; i < leafTbsLen; i++) leafTbs[i] = (i * 17 + 5) & 0xff;

// SPKI uncompressed point: 04 || X(32) || Y(32). leaf_spki_off points at X[0].
const spkiMarkerOff = 100; // the 0x04 marker
const leafSpkiOff = spkiMarkerOff + 1; // X[0]
leafTbs[spkiMarkerOff] = 0x04;
leafTbs.set(leafPubX, leafSpkiOff);
leafTbs.set(leafPubY, leafSpkiOff + 32);

// RNOKPP OID block: 06 03 55 04 05  13 10  "TINUA-"  <10 digits> (23 bytes).
const rnokppOff = 300;
const oid = [0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x10];
for (let i = 0; i < oid.length; i++) leafTbs[rnokppOff + i] = oid[i];
const TINUA = "TINUA-";
for (let i = 0; i < TINUA.length; i++) leafTbs[rnokppOff + 7 + i] = TINUA.charCodeAt(i);
for (let i = 0; i < 10; i++) leafTbs[rnokppOff + 13 + i] = RNOKPP.charCodeAt(i);

// DOB: 8 ASCII digits.
const dobOff = 500;
for (let i = 0; i < 8; i++) leafTbs[dobOff + i] = DOB.charCodeAt(i);

// --- CA signs sha256_var(leaf_tbs, leaf_tbs_len) ---
const eLeaf = sha256(leafTbs.subarray(0, leafTbsLen));
const caSigObj = p256.sign(eLeaf, caSk, { prehash: false }).normalizeS();
const leafCertSig = caSigObj.toCompactRawBytes();
if (!p256.verify(caSigObj, eLeaf, caPubUncompressed, { prehash: false })) {
  throw new Error("synthetic CA sig self-verify failed");
}

// --- emit COMPACT Noir literals for the assert_diia_chain unit test ---
// The chain unit test only needs the synthetic CA pubkey, the CA signature, and
// the leaf-TBS digest e_leaf (assert_diia_chain takes e_leaf, not leaf_tbs).
const noirArr = (u8) => "[" + Array.from(u8).map((b) => b).join(", ") + "]";

console.log("// --- SYNTHETIC test-CA chain tuple (gen-chain-test-tuple.mjs) ---");
console.log(`let ca_x: [u8; 32] = ${noirArr(caPubX)};`);
console.log(`let ca_y: [u8; 32] = ${noirArr(caPubY)};`);
console.log(`let leaf_cert_sig: [u8; 64] = ${noirArr(leafCertSig)};`);
console.log(`let e_leaf: [u8; 32] = ${noirArr(eLeaf)};`);

// The synthetic leaf TBS layout (offsets, RNOKPP, DOB) is mirrored in the
// witness generator (gen-enroll-commit-v2-witness.mjs) and the Noir #[test]
// builders, so no extra artifact is emitted here -- just the pasteable Noir
// literals above. Useful echo for cross-checking:
console.error(
  `synthetic layout: leafTbsLen=${leafTbsLen} leafSpkiOff=${leafSpkiOff} rnokppOff=${rnokppOff} dobOff=${dobOff} RNOKPP=${RNOKPP} DOB=${DOB}`,
);
