# v3 bound-challenge enrollment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the v2 enrollment interface (enter RNOKPP → download personal challenge → sign in Diia → upload `.p7s`) on top of the v3 operator-blind crypto, binding the live QES signature to this session **inside the `enroll_commit_v2` ZK proof**.

**Architecture:** The circuit computes `sha256(signedAttrs)` in-circuit (replacing today's free-witness `msghash`, closing a soundness gap), extracts the PKCS#9 `messageDigest` from `signedAttrs`, and **returns it as a public output**. The stateless OPRF service reconstructs the challenge from the public blinded point `M` + intent + epoch, hashes it, and asserts it equals that returned digest — so a stale/leaked `.p7s` cannot enroll without signing *this session's* challenge. The service never sees the cert (operator-blind preserved).

**Tech Stack:** Noir 1.0.0-beta.19 (`nargo`), Barretenberg `bb` 4.0.0-nightly.20260120 + `@aztec/bb.js` 4.0.0-nightly.20260120 (UltraHonk, **default/Poseidon flavor**), Fastify service (`packages/oprf/v3-grumpkin`), React/Vite web (`packages/web`), `@crisp-qes/sdk` `parseP7s`.

**Spec:** `docs/superpowers/specs/2026-05-31-v3-bound-challenge-enrollment-design.md`

---

## File structure

**Modify:**
- `packages/oprf/v3-grumpkin/circuits/enroll_commit_v2/src/main.nr` — add `signed_attrs`/`signed_attrs_len`/`msg_digest_off` params, in-circuit `sha256_var`, messageDigest extraction, 4-tuple public return.
- `packages/oprf/v3-grumpkin/gen-enroll-commit-v2-witness.mjs` — synthetic `signedAttrs` carrying `messageDigest = sha256(challenge(M))`; emit new witness fields.
- `packages/oprf/v3-grumpkin/service/proof-gate.mjs` — `PUBLIC_INPUT_WORD_COUNT` 14→16; add digest indices + extractor.
- `packages/oprf/v3-grumpkin/service/server.mjs` — challenge-digest check in `/v3/blind-eval` and `/v3/register`.
- `packages/web/src/lib/p7sWitness.ts` — add the three new witness fields from `parseP7s`.
- `packages/web/src/lib/v3enroll.ts` — thread RNOKPP + `r` + challenge; (public M check stays at [12,13]).
- `packages/web/src/pages/V3Enroll.tsx` — graft the v2 staged UI.

**Create:**
- `packages/oprf/v3-grumpkin/service/challenge.mjs` — `buildEnrollV3ChallengeBytes(Mhex, epoch)` + `expectedDigestLimbs`, shared by service checks + tests.
- `packages/oprf/v3-grumpkin/service/gen-fixtures.mjs` — regenerate `target/{proof,public_inputs,vk,vk_hash}` via bb.js (default flavor, version-matched to the service).
- `packages/web/src/lib/enrollmentChallengeV3.ts` — `buildChallengeBytesV3(M, epoch)` (byte-identical to the service).
- `packages/web/src/lib/enrollmentChallengeV3.test.ts`, `packages/web/src/lib/p7sWitness.boundchallenge.test.ts`.
- `packages/oprf/v3-grumpkin/service/challenge-test.mjs`.

**Regenerated artifacts (committed):** `circuits/enroll_commit_v2/target/{enroll_commit_v2.json,enroll_commit_v2.gz,proof,public_inputs,vk,vk_hash}`, copied to `packages/web/public/v3/enroll_commit_v2.json` (+ `dist/v3` via build).

---

## Conventions used throughout

- `SA_LEN = 512` — fixed circuit bound on `signedAttrs` (real Diia `signedAttrs` is ~100–300 B; confirm with one real sample in Task 1, shrink if comfortably smaller).
- Intent string: `crisp-qes-enroll-v3`. Epoch: `v3-2026`.
- Challenge bytes (byte-exact both sides), UTF-8, no whitespace, no trailing newline, fixed key order:
  `{"intent":"crisp-qes-enroll-v3","epoch":"<epoch>","blindedInput":"0x<128hex>"}`
  where `<128hex>` = Grumpkin `M` affine `x(32B BE)‖y(32B BE)`.
- digest limbs: `digest_hi = BE16(sha256(challenge)[0..16])`, `digest_lo = BE16(sha256(challenge)[16..32])`.
- Public-input vector after this change (16 words): `today[8]` (0–7), `c1..c4` (8–11), `M.x` (12), `M.y` (13), `digest_hi` (14), `digest_lo` (15).

---

## Task 1: Circuit — bind the signed challenge in-circuit

**Files:**
- Modify: `packages/oprf/v3-grumpkin/circuits/enroll_commit_v2/src/main.nr`

- [ ] **Step 1: Add the `SA_LEN` global** next to `CERT_LEN` (after line ~`global CERT_LEN: u32 = 2048;`):

```noir
// Bound on the CMS signedAttrs blob the ECDSA signature actually covers
// (real Diia signedAttrs ~100-300 B). Hashed in-circuit with sha256_var so
// only `signed_attrs_len` bytes are digested (padding bytes are ignored).
global SA_LEN: u32 = 512;
```

- [ ] **Step 2: Replace the `msghash` parameter** in `fn main` with the three new private inputs. Change this block:

```noir
    sig: [u8; 64],
    msghash: [u8; 32], // = sha256(signedAttrs), witnessed (Phase-2 of the cert side is out of scope)
    // --- the QES certificate DER (PRIVATE) ---
```

to:

```noir
    sig: [u8; 64],
    // --- CMS signedAttrs the ECDSA signature covers (PRIVATE) ---
    // msghash is now COMPUTED in-circuit as sha256_var(signed_attrs, len),
    // closing the prior free-witness gap. msg_digest_off locates the PKCS#9
    // messageDigest OCTET STRING value (04 20 <32B>) inside signed_attrs.
    signed_attrs: [u8; SA_LEN],
    signed_attrs_len: u32,
    msg_digest_off: u32,
    // --- the QES certificate DER (PRIVATE) ---
```

- [ ] **Step 3: Change the return type** from `-> pub (Field, Field) {` to:

```noir
) -> pub (Field, Field, Field, Field) {
```

- [ ] **Step 4: Replace the ECDSA block** (lines ~153-155) to compute `msghash` in-circuit:

```noir
    // ---- (a) ECDSA-P256 verify over the IN-CIRCUIT signedAttrs hash. ----
    // sha256_var digests exactly `signed_attrs_len` bytes (vendored
    // noir-lang/sha256 v0.3.0). Binding the signature to the hash we compute
    // (rather than a witnessed digest) is what makes the challenge binding sound.
    let msghash: [u8; 32] = sha256::sha256_var(signed_attrs, signed_attrs_len);
    let sig_ok = std::ecdsa_secp256r1::verify_signature(pubkey_x, pubkey_y, sig, msghash);
    assert(sig_ok);

    // ---- (a') extract PKCS#9 messageDigest from signedAttrs. ----
    // The value is DER OCTET STRING `04 20 <32 bytes>` at msg_digest_off.
    assert(signed_attrs[msg_digest_off] == 0x04);
    assert(signed_attrs[msg_digest_off + 1] == 0x20);
    let mut digest_hi: Field = 0; // bytes [0..16]
    let mut digest_lo: Field = 0; // bytes [16..32]
    for k in 0..16 {
        digest_hi = digest_hi * 256 + signed_attrs[msg_digest_off + 2 + k] as Field;
    }
    for k in 0..16 {
        digest_lo = digest_lo * 256 + signed_attrs[msg_digest_off + 18 + k] as Field;
    }
```

Note: `signed_attrs[msg_digest_off + ...]` indexing with a dynamic offset is the same pattern `read_at(cert, off, k)` already uses; if the compiler requires it, route these reads through a `read_at`-style helper over `signed_attrs`.

- [ ] **Step 5: Change the final return** (last line of `main`) from `(m.x, m.y)` to:

```noir
    (m.x, m.y, digest_hi, digest_lo)
```

- [ ] **Step 6: Compile and check it builds**

Run: `cd packages/oprf/v3-grumpkin/circuits/enroll_commit_v2 && nargo compile`
Expected: success; `target/enroll_commit_v2.json` regenerated. No type errors.

- [ ] **Step 7: Record circuit size + prove-memory sanity (NOT a gate)**

Run: `nargo info`
Expected: prints ACIR/opcode counts; note the delta vs the prior build (a few SHA-256 blocks larger). This is informational — the only budget is prove memory < 1 GB, verified end-to-end in Task 3.

- [ ] **Step 8: Commit**

```bash
git add packages/oprf/v3-grumpkin/circuits/enroll_commit_v2/src/main.nr
git commit -m "circuit(v3 #39): bind signed challenge in enroll_commit_v2 (in-circuit sha256(signedAttrs) + messageDigest output)"
```

---

## Task 2: Synthetic witness generator — emit signedAttrs bound to a challenge

The generator must produce a synthetic `signedAttrs` whose `messageDigest = sha256(challenge(M))`, sign `sha256(signedAttrs)`, and emit the new witness fields. The circuit only constrains: `04 20 <32B>` at `msg_digest_off`, and `sig` valid over `sha256_var(signed_attrs, len)` — so a minimal synthetic `signedAttrs` buffer suffices.

**Files:**
- Modify: `packages/oprf/v3-grumpkin/gen-enroll-commit-v2-witness.mjs`

- [ ] **Step 1: Add the challenge + synthetic signedAttrs builder.** After the `const M = Hpt.multiply(r); const Maff = M.toAffine();` lines, insert:

```javascript
// --- bound challenge (v3) -------------------------------------------------
// Byte-exact with service/challenge.mjs and web enrollmentChallengeV3.ts.
const INTENT = "crisp-qes-enroll-v3";
const EPOCH = "v3-2026";
const be32 = (v) => v.toString(16).padStart(64, "0");
const Mhex = `0x${be32(Maff.x)}${be32(Maff.y)}`;
const challenge = new TextEncoder().encode(
  `{"intent":"${INTENT}","epoch":"${EPOCH}","blindedInput":"${Mhex}"}`,
);
const messageDigest = sha256(challenge); // 32 bytes

// Minimal synthetic signedAttrs: [pad 8][04 20 <messageDigest>][pad 8].
// The circuit only checks the OCTET STRING at msg_digest_off + the ECDSA over
// sha256_var(signed_attrs, len). msgDigestOff points at the 0x04 tag.
const SA_USED = 8 + 2 + 32 + 8; // 50 bytes used
const SA_LEN = 512;             // must equal the circuit global
const signedAttrs = new Uint8Array(SA_LEN);
for (let i = 0; i < 8; i++) signedAttrs[i] = (i * 13 + 1) & 0xff;
const msgDigestOff = 8;
signedAttrs[msgDigestOff] = 0x04;
signedAttrs[msgDigestOff + 1] = 0x20;
signedAttrs.set(messageDigest, msgDigestOff + 2);
for (let i = 0; i < 8; i++) signedAttrs[42 + i] = (i * 7 + 3) & 0xff;
const msghash = sha256(signedAttrs.subarray(0, SA_USED)); // sha256_var hashes [0..len]
```

- [ ] **Step 2: Re-sign over the new `msghash`.** REPLACE the existing block that does `const msghash = sha256(cert); ... p256.sign(msghash, ...)` so it signs the signedAttrs hash instead of the cert hash:

```javascript
const sk = p256.utils.randomPrivateKey();
const pubUncompressed = p256.getPublicKey(sk, false);
const pubX = pubUncompressed.slice(1, 33);
const pubY = pubUncompressed.slice(33, 65);
const sigObj = p256.sign(msghash, sk, { prehash: false }).normalizeS();
const sig = sigObj.toCompactRawBytes();
if (!p256.verify(sigObj, msghash, pubUncompressed, { prehash: false })) {
  throw new Error("JS-side ECDSA verify failed");
}
```

(Delete the old `const msghash = sha256(cert);` line near the top so `cert` is no longer the signed message — the cert is still witnessed for RNOKPP/DOB extraction, just not signed.)

- [ ] **Step 3: Emit the new witness fields** in the generated TOML. Add to the `toml` template (after `sig = ...` and removing the standalone `msghash = ...` line, since msghash is no longer a circuit input):

```javascript
const toml = `# auto-generated by gen-enroll-commit-v2-witness.mjs (v3 bound-challenge)
# SYNTHETIC disposable cert + signedAttrs. Never a real Diia cert.
pubkey_x = ${arr(pubX)}
pubkey_y = ${arr(pubY)}
sig = ${arr(sig)}
signed_attrs = ${arr(signedAttrs)}
signed_attrs_len = "${SA_USED}"
msg_digest_off = "${msgDigestOff}"
cert = ${arr(cert)}
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
```

- [ ] **Step 4: Log the expected digest** for cross-checking in tests. After the existing `console.log` of M.x/M.y, add:

```javascript
const digestHi = BigInt("0x" + Buffer.from(messageDigest.subarray(0, 16)).toString("hex"));
const digestLo = BigInt("0x" + Buffer.from(messageDigest.subarray(16, 32)).toString("hex"));
console.log("expected public digest limbs (return [2],[3]):");
console.log("  digest_hi =", digestHi.toString());
console.log("  digest_lo =", digestLo.toString());
```

- [ ] **Step 5: Generate the witness TOML + execute**

Run:
```bash
cd packages/oprf/v3-grumpkin
node gen-enroll-commit-v2-witness.mjs
cd circuits/enroll_commit_v2 && nargo execute
```
Expected: `wrote Prover.toml`, then `nargo execute` succeeds and writes `target/enroll_commit_v2.gz` (the witness). No assertion failures — proves the new circuit accepts the synthetic bound witness.

- [ ] **Step 6: Commit**

```bash
git add packages/oprf/v3-grumpkin/gen-enroll-commit-v2-witness.mjs
git commit -m "test(v3 #39): synthetic enroll_commit_v2 witness carries challenge-bound signedAttrs"
```

---

## Task 3: Regenerate proof/vk fixtures via bb.js (default flavor) + verify + prove-memory check

**Files:**
- Create: `packages/oprf/v3-grumpkin/service/gen-fixtures.mjs`

- [ ] **Step 1: Write the fixture generator** (uses the same bb.js + default flavor the service verifies with, so flavor can never drift — this is the lesson from the 2026-05-31 evm-flavor bug):

```javascript
// Regenerate committed enroll_commit_v2 fixtures (proof, public_inputs, vk,
// vk_hash) with @aztec/bb.js DEFAULT flavor — byte-for-byte the flavor the
// service's ProofGate verifies with. Run with cwd in v3-grumpkin AFTER
// `nargo execute` has produced target/enroll_commit_v2.gz.
//   node service/gen-fixtures.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";

const T = join(dirname(fileURLToPath(import.meta.url)), "..", "circuits", "enroll_commit_v2", "target");
const bytecode = JSON.parse(readFileSync(join(T, "enroll_commit_v2.json"), "utf8")).bytecode;
const witness = new Uint8Array(readFileSync(join(T, "enroll_commit_v2.gz")));

const api = await Barretenberg.new({ threads: 1 });
const backend = new UltraHonkBackend(bytecode, api);
const { proof, publicInputs } = await backend.generateProof(witness); // DEFAULT flavor
const vk = await backend.getVerificationKey();
await api.destroy();

// proof: flat bytes. public_inputs: flat 32B BE words. vk: bytes. vk_hash: sha256(vk).
writeFileSync(join(T, "proof"), Buffer.from(proof));
const pi = Buffer.concat(publicInputs.map((w) => Buffer.from(w.replace(/^0x/, ""), "hex")));
writeFileSync(join(T, "public_inputs"), pi);
writeFileSync(join(T, "vk"), Buffer.from(vk));
writeFileSync(join(T, "vk_hash"), createHash("sha256").update(Buffer.from(vk)).digest());
console.log(`wrote fixtures: proof=${proof.length}B pi=${publicInputs.length} words vk=${vk.length}B`);
console.log(`public digest words [14]=${publicInputs[14]} [15]=${publicInputs[15]}`);
```

- [ ] **Step 2: Generate fixtures + measure prove memory (sanity, < 1 GB)**

Run: `cd packages/oprf/v3-grumpkin && /usr/bin/time -v node service/gen-fixtures.mjs 2>&1 | grep -E "wrote fixtures|digest words|Maximum resident"`
Expected: `wrote fixtures: ... pi=16 words ...`; `Maximum resident set size` comfortably under 1048576 KB (1 GB). The 16-word count confirms the new public layout. Note the digest words [14],[15].

- [ ] **Step 3: Verify the regenerated proof in-process (the service's exact path)**

Run: `node service/inprocess-verify-test.mjs`
Expected: `[VERIFIED] UltraHonkVerifierBackend.verifyProof (explicit vk)` and the tampered variant `[rejected]`. Confirms proof+vk+default-flavor verify cleanly.

- [ ] **Step 4: Cross-check the digest limbs** match the generator's expectation. Compare the `digest words [14],[15]` printed in Step 2 against the `digest_hi/digest_lo` printed by `gen-enroll-commit-v2-witness.mjs` (Task 2 Step 4). They MUST be equal.
Expected: equal. (If not, the byte-packing in the circuit or generator disagrees — fix before proceeding.)

- [ ] **Step 5: Copy circuit bytecode to the web public dir**

Run: `cp circuits/enroll_commit_v2/target/enroll_commit_v2.json ../../web/public/v3/enroll_commit_v2.json`
Expected: web now serves the new circuit (so the browser prover and service VK match — verified by hash).

Run: `node -e "const fs=require('fs'),c=require('crypto');const h=p=>c.createHash('sha256').update(JSON.parse(fs.readFileSync(p,'utf8')).bytecode).digest('hex').slice(0,16);console.log(h('circuits/enroll_commit_v2/target/enroll_commit_v2.json'),h('../../web/public/v3/enroll_commit_v2.json'))"`
Expected: the two hashes are identical.

- [ ] **Step 6: Commit**

```bash
git add packages/oprf/v3-grumpkin/service/gen-fixtures.mjs \
        packages/oprf/v3-grumpkin/circuits/enroll_commit_v2/target/enroll_commit_v2.json \
        packages/web/public/v3/enroll_commit_v2.json
# target/{proof,public_inputs,vk,vk_hash,*.gz} are gitignored in the service; they
# are baked at docker build. Commit only tracked files (verify with `git status`).
git commit -m "build(v3 #39): regenerate enroll_commit_v2 fixtures (default flavor) for 16-word bound-challenge layout"
```

---

## Task 4: Shared challenge module + unit test (service side)

**Files:**
- Create: `packages/oprf/v3-grumpkin/service/challenge.mjs`
- Create: `packages/oprf/v3-grumpkin/service/challenge-test.mjs`

- [ ] **Step 1: Write the failing test**

```javascript
// packages/oprf/v3-grumpkin/service/challenge-test.mjs
import assert from "node:assert/strict";
import { buildEnrollV3ChallengeBytes, expectedDigestLimbs } from "./challenge.mjs";

const Mhex =
  "0x" + "11".repeat(32) + "22".repeat(32); // 128 hex
const bytes = buildEnrollV3ChallengeBytes(Mhex, "v3-2026");
assert.equal(
  new TextDecoder().decode(bytes),
  `{"intent":"crisp-qes-enroll-v3","epoch":"v3-2026","blindedInput":"${Mhex}"}`,
  "challenge bytes must be byte-exact",
);

const { hi, lo } = expectedDigestLimbs(Mhex, "v3-2026");
assert.equal(typeof hi, "bigint");
assert.equal(typeof lo, "bigint");
assert.ok(hi < (1n << 128n) && lo < (1n << 128n), "limbs are 16-byte");

// Rejects bad M shape.
assert.throws(() => buildEnrollV3ChallengeBytes("0xdeadbeef", "v3-2026"));
console.log("challenge-test PASS");
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd packages/oprf/v3-grumpkin && node service/challenge-test.mjs`
Expected: FAIL — `Cannot find module './challenge.mjs'`.

- [ ] **Step 3: Write the module**

```javascript
// packages/oprf/v3-grumpkin/service/challenge.mjs
// Byte-exact reconstruction of the v3 enrollment challenge the citizen signs in
// Diia. Stateless: rebuilt from the public blinded point M + intent + epoch.
// MUST stay byte-identical to web/src/lib/enrollmentChallengeV3.ts.
import { createHash } from "node:crypto";

export const ENROLL_V3_INTENT = "crisp-qes-enroll-v3";

export function buildEnrollV3ChallengeBytes(Mhex, epoch) {
  // M is a Grumpkin affine point: 0x + 64 bytes (x||y) = 128 hex chars.
  if (typeof Mhex !== "string" || !/^0x[0-9a-f]{128}$/.test(Mhex.toLowerCase())) {
    throw new Error("buildEnrollV3ChallengeBytes: M must be 0x + 128 lowercase hex (x||y)");
  }
  if (!epoch || /["\\]/.test(epoch)) {
    throw new Error("buildEnrollV3ChallengeBytes: epoch non-empty, no quote/backslash");
  }
  return new TextEncoder().encode(
    `{"intent":"${ENROLL_V3_INTENT}","epoch":"${epoch}","blindedInput":"${Mhex.toLowerCase()}"}`,
  );
}

export function expectedDigestLimbs(Mhex, epoch) {
  const d = createHash("sha256").update(buildEnrollV3ChallengeBytes(Mhex, epoch)).digest();
  const hi = BigInt("0x" + d.subarray(0, 16).toString("hex"));
  const lo = BigInt("0x" + d.subarray(16, 32).toString("hex"));
  return { hi, lo };
}
```

(Delete the unused `M_HEX` regex line — kept here only to flag the 128-hex shape; the active check is inline.)

- [ ] **Step 4: Run it to verify it passes**

Run: `node service/challenge-test.mjs`
Expected: `challenge-test PASS`.

- [ ] **Step 5: Commit**

```bash
git add packages/oprf/v3-grumpkin/service/challenge.mjs packages/oprf/v3-grumpkin/service/challenge-test.mjs
git commit -m "feat(v3 #39): stateless v3 enrollment challenge module + test"
```

---

## Task 5: Proof gate — 16-word layout + digest extractor

**Files:**
- Modify: `packages/oprf/v3-grumpkin/service/proof-gate.mjs`

- [ ] **Step 1: Update the public-input constants.** Replace:

```javascript
export const M_X_WORD_INDEX = 12;
export const PUBLIC_INPUT_WORD_COUNT = 14;
```

with:

```javascript
export const M_X_WORD_INDEX = 12;
// enroll_commit_v2 now returns (M.x, M.y, digest_hi, digest_lo); the two digest
// limbs are the signedAttrs messageDigest the circuit bound to the signature.
export const DIGEST_HI_WORD_INDEX = 14;
export const DIGEST_LO_WORD_INDEX = 15;
export const PUBLIC_INPUT_WORD_COUNT = 16;
```

- [ ] **Step 2: Add a digest extractor** next to `extractMFromPublicInputs`:

```javascript
// Extract the messageDigest the proof bound (as a single 32-byte bigint) from
// the enroll proof's public words [14],[15] (hi*2^128 + lo).
export function extractDigestFromPublicInputs(words) {
    if (!Array.isArray(words) || words.length !== PUBLIC_INPUT_WORD_COUNT) {
        throw new Error(`publicInputs must have exactly ${PUBLIC_INPUT_WORD_COUNT} words`);
    }
    const toBig = (w) => BigInt("0x" + wordToBE32(w).toString("hex"));
    return {
        hi: toBig(words[DIGEST_HI_WORD_INDEX]),
        lo: toBig(words[DIGEST_LO_WORD_INDEX]),
    };
}
```

- [ ] **Step 3: Verify the gate still accepts the regenerated proof** (the 16-word `extractMFromPublicInputs` length check now expects 16; the regenerated fixture has 16). Add a quick check script inline:

Run:
```bash
cd packages/oprf/v3-grumpkin && node -e '
import("./service/proof-gate.mjs").then(async (g) => {
  const fs = await import("node:fs");
  const T = "circuits/enroll_commit_v2/target";
  const pi = new Uint8Array(fs.readFileSync(`${T}/public_inputs`));
  const words = [];
  for (let i = 0; i < pi.length; i += 32) words.push("0x" + Buffer.from(pi.subarray(i, i+32)).toString("hex"));
  console.log("word count:", words.length);
  const m = g.extractMFromPublicInputs(words);
  const d = g.extractDigestFromPublicInputs(words);
  console.log("M.x ok:", typeof m.x === "bigint", "digest hi/lo ok:", typeof d.hi === "bigint" && typeof d.lo === "bigint");
});'
```
Expected: `word count: 16`, `M.x ok: true digest hi/lo ok: true`.

- [ ] **Step 4: Commit**

```bash
git add packages/oprf/v3-grumpkin/service/proof-gate.mjs
git commit -m "feat(v3 #39): proof-gate 16-word layout + digest extractor"
```

---

## Task 6: Service — enforce the challenge binding at blind-eval (and register)

**Files:**
- Modify: `packages/oprf/v3-grumpkin/service/server.mjs`

- [ ] **Step 1: Import the challenge helpers + digest extractor.** Add to the imports near `verifyEnrollCommitProof`:

```javascript
import { extractDigestFromPublicInputs } from "./proof-gate.mjs";
import { expectedDigestLimbs } from "./challenge.mjs";
```

(`verifyEnrollCommitProof` is already imported; add the two names — merge into the existing `proof-gate.mjs` import if present.)

- [ ] **Step 2: Add the epoch constant** near the top config of `buildApp` (mirror the existing `chainId`/`enrollmentRegistry` reads):

```javascript
const enrollEpoch = process.env.OPRF_ENROLLMENT_EPOCH_V3 ?? "v3-2026";
```

- [ ] **Step 3: Add a shared challenge-binding check** (a local helper inside `buildApp`, after `gate` is set up):

```javascript
// Reconstruct the v3 challenge from the PUBLIC M + intent + epoch, sha256 it,
// and require it equals the digest the enroll proof bound (public words 14/15).
// Stateless + operator-blind: we never see the cert, only M (which we have).
function challengeDigestOk(Mhex, publicInputs) {
    let bound, expected;
    try {
        bound = extractDigestFromPublicInputs(publicInputs);
        expected = expectedDigestLimbs(Mhex.toLowerCase(), enrollEpoch);
    } catch {
        return false;
    }
    return bound.hi === expected.hi && bound.lo === expected.lo;
}
```

- [ ] **Step 4: Enforce it in `/v3/blind-eval`**, immediately AFTER `if (!gateResult.ok) { ... }` and BEFORE `req.log.info("v3 blind-eval proof accepted");`:

```javascript
        if (!challengeDigestOk(M, publicInputs)) {
            req.log.info("v3 blind-eval challenge digest mismatch");
            return reply.code(409).send({
                error: "ChallengeMismatch",
                detail:
                    "proof's bound messageDigest != sha256(challenge) for this M/epoch; " +
                    "re-sign the downloaded challenge for this session",
            });
        }
```

- [ ] **Step 5: Enforce it in `/v3/register` too** (defense in depth). In the `/v3/register` handler, after the enroll proof is verified and `M` is known from the enroll public inputs, add the same `challengeDigestOk(<Mhex from enroll publicInputs>, enrollPublicInputs)` guard returning `409 ChallengeMismatch`. (Reconstruct `Mhex` from `enrollPublicInputs[12],[13]` via `bigintToHex32`-style 32-byte BE concat: `0x${x}${y}`.)

```javascript
        // bind the registered leaf to the live-signed challenge as well.
        const exHex = enrollPublicInputs[12].replace(/^0x/, "").padStart(64, "0");
        const eyHex = enrollPublicInputs[13].replace(/^0x/, "").padStart(64, "0");
        if (!challengeDigestOk(`0x${exHex}${eyHex}`, enrollPublicInputs)) {
            return reply.code(409).send({ error: "ChallengeMismatch", detail: "enroll proof challenge digest mismatch" });
        }
```

- [ ] **Step 6: Test — blind-eval rejects a proof whose challenge doesn't match.** Use the regenerated fixture (which IS bound to `M`+`v3-2026`) for the positive case and a wrong-epoch env for the negative. Run the existing gating test plus an inline check:

Run:
```bash
cd packages/oprf/v3-grumpkin && node -e '
import("./service/server.mjs").then(async ({ buildApp }) => {
  const fs = await import("node:fs");
  const T = "circuits/enroll_commit_v2/target";
  const proof = "0x" + Buffer.from(fs.readFileSync(`${T}/proof`)).toString("hex");
  const pib = new Uint8Array(fs.readFileSync(`${T}/public_inputs`));
  const publicInputs = []; for (let i=0;i<pib.length;i+=32) publicInputs.push("0x"+Buffer.from(pib.subarray(i,i+32)).toString("hex"));
  const x = publicInputs[12].slice(2).padStart(64,"0"), y = publicInputs[13].slice(2).padStart(64,"0");
  const M = `0x${x}${y}`;
  const { OprfNode } = await import("./service/oprf-node.mjs");
  const app = await buildApp({ node: new OprfNode(123n), logger: false });
  const r = await app.inject({ method:"POST", url:"/v3/blind-eval", payload:{ M, proof, publicInputs }});
  console.log("status:", r.statusCode, "(expect 200 — challenge matches v3-2026)");
  await app.close();
});'
```
Expected: `status: 200` (the fixture is bound to `v3-2026`). Then re-run with `OPRF_ENROLLMENT_EPOCH_V3=wrong-epoch` prefixed → expect `status: 409`.

- [ ] **Step 7: Commit**

```bash
git add packages/oprf/v3-grumpkin/service/server.mjs
git commit -m "feat(v3 #39): enforce bound-challenge digest at /v3/blind-eval + /v3/register (409 ChallengeMismatch)"
```

---

## Task 7: Web — challenge module + witness fields

**Files:**
- Create: `packages/web/src/lib/enrollmentChallengeV3.ts`
- Create: `packages/web/src/lib/enrollmentChallengeV3.test.ts`
- Modify: `packages/web/src/lib/p7sWitness.ts`
- Create: `packages/web/src/lib/p7sWitness.boundchallenge.test.ts`

- [ ] **Step 1: Write the failing challenge test**

```typescript
// packages/web/src/lib/enrollmentChallengeV3.test.ts
import { describe, it, expect } from "vitest";
import { buildChallengeBytesV3, pointToChallengeHex } from "./enrollmentChallengeV3.js";
import { hashToCurve } from "./grumpkin.js";

describe("enrollmentChallengeV3", () => {
  it("is byte-exact with the documented wire format", () => {
    const M = hashToCurve(new TextEncoder().encode("1234567890")).multiply(7n);
    const hex = pointToChallengeHex(M);
    const bytes = buildChallengeBytesV3(M, "v3-2026");
    expect(new TextDecoder().decode(bytes)).toBe(
      `{"intent":"crisp-qes-enroll-v3","epoch":"v3-2026","blindedInput":"${hex}"}`,
    );
    expect(hex).toMatch(/^0x[0-9a-f]{128}$/);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/web && npx vitest run src/lib/enrollmentChallengeV3.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the module** (byte-identical to `service/challenge.mjs`)

```typescript
// packages/web/src/lib/enrollmentChallengeV3.ts
// v3 enrollment challenge the citizen signs in Diia. Byte-identical to
// packages/oprf/v3-grumpkin/service/challenge.mjs. The OPRF service rebuilds
// these exact bytes from the public M + intent + epoch and asserts the enroll
// proof's bound messageDigest == sha256(these bytes).
import type { Pt } from "./grumpkin.js";

const INTENT = "crisp-qes-enroll-v3";

/** Grumpkin affine M -> 0x + x(32B BE) || y(32B BE) = 128 lowercase hex. */
export function pointToChallengeHex(M: Pt): string {
  const a = M.toAffine();
  const be32 = (v: bigint) => v.toString(16).padStart(64, "0");
  return `0x${be32(a.x)}${be32(a.y)}`;
}

export function buildChallengeBytesV3(M: Pt, epoch: string): Uint8Array {
  const hex = pointToChallengeHex(M);
  return new TextEncoder().encode(
    `{"intent":"${INTENT}","epoch":"${epoch}","blindedInput":"${hex}"}`,
  );
}

export const ENROLL_V3_EPOCH = "v3-2026";
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/lib/enrollmentChallengeV3.test.ts`
Expected: PASS.

- [ ] **Step 5: Extend `buildP7sEnrollWitness`** to emit the three new fields. In `packages/web/src/lib/p7sWitness.ts`, inside `buildP7sEnrollWitness`, after `const msghash = parsed.signedAttrsSha256;` add:

```typescript
    // --- bound-challenge fields (v3) ------------------------------------
    // The circuit hashes signed_attrs in-circuit (sha256_var) and extracts the
    // PKCS#9 messageDigest at msg_digest_off. parseP7s already re-tags
    // signedAttrs to the CMS hash-input SET form and locates the digest value.
    if (parsed.signedAttrs.length > SA_LEN) {
        throw new Error(
            `p7sWitness: signedAttrs (${parsed.signedAttrs.length} B) exceeds SA_LEN (${SA_LEN}); bump both.`,
        );
    }
    const signedAttrsPadded = new Uint8Array(SA_LEN);
    signedAttrsPadded.set(parsed.signedAttrs, 0);
    // messageDigestOffset points at the 32-byte value; the circuit expects the
    // 0x04 0x20 OCTET STRING header, i.e. value offset minus 2.
    const msgDigestOff = parsed.messageDigestOffset - 2;
    if (signedAttrsPadded[msgDigestOff] !== 0x04 || signedAttrsPadded[msgDigestOff + 1] !== 0x20) {
        throw new Error("p7sWitness: messageDigest is not a 04 20 OCTET STRING at the expected offset");
    }
```

Add the `SA_LEN` constant near `CERT_LEN`:

```typescript
// Must equal the circuit global SA_LEN in enroll_commit_v2/src/main.nr.
export const SA_LEN = 512;
```

Then change the returned `witness` object: REMOVE `msghash: u8arr(msghash),` and ADD:

```typescript
        signed_attrs: u8arr(signedAttrsPadded),
        signed_attrs_len: parsed.signedAttrs.length.toString(),
        msg_digest_off: msgDigestOff.toString(),
```

(`msghash` is no longer a circuit input; `parsed.signedAttrsSha256` may stay computed but unused, or drop the line.)

- [ ] **Step 6: Write the witness-shape test**

```typescript
// packages/web/src/lib/p7sWitness.boundchallenge.test.ts
import { describe, it, expect } from "vitest";
import { buildP7sEnrollWitness, SA_LEN } from "./p7sWitness.js";
import { makeSyntheticDiiaP7s } from "./testFixtures.js"; // existing synthetic .p7s builder used by p7sWitness.test.ts

describe("buildP7sEnrollWitness bound-challenge fields", () => {
  it("emits signed_attrs / signed_attrs_len / msg_digest_off and no msghash", () => {
    const { p7sBytes, dob } = makeSyntheticDiiaP7s({ rnokpp: "1234567890", dob: "19900115" });
    const { witness } = buildP7sEnrollWitness(p7sBytes, dob, { r: 7n });
    expect(Array.isArray(witness.signed_attrs)).toBe(true);
    expect((witness.signed_attrs as string[]).length).toBe(SA_LEN);
    expect(witness.msghash).toBeUndefined();
    const off = Number(witness.msg_digest_off);
    expect((witness.signed_attrs as string[])[off]).toBe("4");   // 0x04
    expect((witness.signed_attrs as string[])[off + 1]).toBe("32"); // 0x20
  });
});
```

(If `testFixtures.makeSyntheticDiiaP7s` does not exist, reuse whatever synthetic-`.p7s` helper `p7sWitness.test.ts` already imports — check that file first and mirror its import.)

- [ ] **Step 7: Run the witness tests**

Run: `npx vitest run src/lib/p7sWitness.boundchallenge.test.ts src/lib/p7sWitness.test.ts`
Expected: PASS (new test green; existing `p7sWitness.test.ts` updated/green — if the existing test asserts a `msghash` field, update it to the new fields in the same commit).

- [ ] **Step 8: Commit**

```bash
git add packages/web/src/lib/enrollmentChallengeV3.ts packages/web/src/lib/enrollmentChallengeV3.test.ts \
        packages/web/src/lib/p7sWitness.ts packages/web/src/lib/p7sWitness.boundchallenge.test.ts \
        packages/web/src/lib/p7sWitness.test.ts
git commit -m "feat(v3 #39): web v3 challenge module + signed_attrs witness fields"
```

---

## Task 8: Web — graft the v2 staged interface onto V3Enroll

**Files:**
- Modify: `packages/web/src/pages/V3Enroll.tsx`
- Modify: `packages/web/src/lib/v3enroll.ts`

The current `V3Enroll` jumps straight to `.p7s` upload. Restructure it to the v2 stages: enter RNOKPP → compute `M` + download challenge → sign in Diia → upload `.p7s` (which must carry `messageDigest == sha256(challenge)`) → run proofs.

- [ ] **Step 1: Thread the precomputed blinding into the run.** In `packages/web/src/lib/v3enroll.ts`, change `runRealEnrollment` to accept an optional fixed `r` so the page computes `M` (and the challenge) BEFORE the upload, then reuses the same `r` for the proof. Update the signature:

```typescript
export async function runRealEnrollment(
    p7sBytes: Uint8Array,
    dobDigits: string,
    submitEnrollment: SubmitEnrollmentFn,
    onStage: (stage: RealRunStage) => void,
    opts: { r?: bigint } = {},
): Promise<RealEnrollResult> {
```

and pass it through to the witness builder:

```typescript
    bundle = buildP7sEnrollWitness(p7sBytes, dobDigits, { r: opts.r });
```

- [ ] **Step 2: Restructure `V3Enroll.tsx` stages.** Replace the `Substage` type and add RNOKPP + challenge state:

```typescript
type Substage = "identify" | "challenge" | "upload" | "running" | "enrolled" | "saving" | "saved";
const RNOKPP_RE = /^[0-9]{10}$/;
```

Add state (with the existing `useState` block):

```typescript
    const [rnokppInput, setRnokppInput] = useState("");
    const [blindState, setBlindState] = useState<{ r: bigint; rnokpp: string } | null>(null);
```

- [ ] **Step 3: Add the challenge-generation handler** (mirrors v2 `Verify.tsx onGenerate`, but Grumpkin `M`):

```typescript
    const onGenerate = useCallback(() => {
        setError(null);
        const rnokpp = rnokppInput.trim();
        if (!RNOKPP_RE.test(rnokpp)) { setError("RNOKPP must be exactly 10 digits."); return; }
        try {
            const r = randomScalarPublic();                 // see Step 4
            const M = hashToCurve(new TextEncoder().encode(rnokpp)).multiply(r);
            const bytes = buildChallengeBytesV3(M, ENROLL_V3_EPOCH);
            const ab = new ArrayBuffer(bytes.byteLength);
            new Uint8Array(ab).set(bytes);
            const url = URL.createObjectURL(new Blob([ab], { type: "text/plain" }));
            const a = document.createElement("a");
            a.href = url; a.download = "crisp-qes-challenge.txt";
            document.body.appendChild(a); a.click(); a.remove();
            URL.revokeObjectURL(url);
            setBlindState({ r, rnokpp });
            setStage("challenge");
        } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    }, [rnokppInput]);
```

Add imports at the top:

```typescript
import { hashToCurve, N } from "../lib/grumpkin.js";
import { buildChallengeBytesV3, ENROLL_V3_EPOCH } from "../lib/enrollmentChallengeV3.js";
```

- [ ] **Step 4: Add a crypto-random scalar helper** in `V3Enroll.tsx` (module scope):

```typescript
function randomScalarPublic(): bigint {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    let v = 0n;
    for (const b of buf) v = (v << 8n) | BigInt(b);
    return (v % (N - 1n)) + 1n;
}
```

- [ ] **Step 5: Gate the `.p7s` upload on the entered RNOKPP.** In the existing `onFile` handler, after `extractRnokpp` succeeds, require it matches `blindState.rnokpp` (mirror v2 `Verify.tsx`):

```typescript
            if (!blindState || certRnokpp !== blindState.rnokpp) {
                setError(
                    `The certificate's RNOKPP (${certRnokpp}) doesn't match the one you typed` +
                        (blindState ? ` (${blindState.rnokpp}).` : "."),
                );
                return;
            }
```

- [ ] **Step 6: Pass the fixed `r` into the run.** In `onRun`, change the `runRealEnrollment(...)` call to pass `{ r: blindState!.r }` as the 5th arg:

```typescript
            const res = await runRealEnrollment(p7sBytes, dob, async (a) => {
                const r = await submitEnrollment(a);
                return r.ok ? { ok: true as const, txHash: r.txHash } : { ok: false as const, code: r.code, detail: r.detail };
            }, (s) => setStages((prev) => ({ ...prev, [s.key]: s })), { r: blindState!.r });
```

- [ ] **Step 7: Update the JSX** so the screens render per stage: `identify` (RNOKPP input + "Generate challenge" button calling `onGenerate`), `challenge`/`upload` (instructions to sign `crisp-qes-challenge.txt` in Diia + the existing dropzone), then the existing `running`/`enrolled`/`saved` panels. Reuse the v2 `Verify.tsx` copy/markup for the `identify` and `challenge` screens. (Mechanical JSX; no new logic.)

- [ ] **Step 8: Typecheck**

Run: `cd packages/web && npx tsc --noEmit -p tsconfig.json`
Expected: exit 0.

- [ ] **Step 9: Commit**

```bash
git add packages/web/src/pages/V3Enroll.tsx packages/web/src/lib/v3enroll.ts
git commit -m "feat(v3 #39): v2-style staged enrollment UI (RNOKPP -> challenge -> sign -> upload) on v3 crypto"
```

---

## Task 9: End-to-end — update register-test, full roundtrip, deploy

**Files:**
- Modify: `packages/oprf/v3-grumpkin/service/register-test.mjs` (fixtures/public-input count)

- [ ] **Step 1: Update `register-test.mjs` for 16 enroll public-input words.** Wherever it builds or asserts the enroll `publicInputs`, ensure it uses the regenerated 16-word fixture and the new `OPRF_ENROLLMENT_EPOCH_V3=v3-2026` challenge binding. (The pre-existing `NullifierMismatchedM` failures came from stale fixtures regenerated in Task 3; with fresh fixtures bound to the same `M`, they clear.)

Run: `cd packages/oprf/v3-grumpkin && node service/register-test.mjs`
Expected: all checks PASS (including the previously-failing nullifier-M cross-check, now consistent).

- [ ] **Step 2: Service gating test**

Run: `node service/gating-test.mjs`
Expected: PASS.

- [ ] **Step 3: Full web test suite**

Run: `cd packages/web && npx vitest run`
Expected: all green.

- [ ] **Step 4: Local end-to-end smoke (service in-process).** Confirm the regenerated proof drives a full blind-eval → 200 with the challenge gate ON (already exercised in Task 6 Step 6). Re-run that inline check.
Expected: `status: 200`.

- [ ] **Step 5: Deploy service**

Run: `cd packages/oprf/v3-grumpkin && flyctl deploy --now`
Expected: rolling deploy succeeds; both machines healthy. (Docker rebuilds the circuit fixtures it bakes — confirm `enroll_commit_v2.json` copied in Task 3 is committed so the image bakes the new circuit.)

- [ ] **Step 6: Deploy web** (build context = repo root, per the 2026-05-31 deploy note)

Run: `cd /data/Develop/crisp-qes && flyctl deploy . --config packages/web/fly.toml --dockerfile packages/web/Dockerfile --now`
Expected: deploy succeeds.

- [ ] **Step 7: Verify deployed circuit parity**

Run:
```bash
curl -s https://crisp-qes-web.fly.dev/v3/enroll_commit_v2.json -o /tmp/w.json
node -e "const fs=require('fs'),c=require('crypto');console.log(c.createHash('sha256').update(JSON.parse(fs.readFileSync('/tmp/w.json','utf8')).bytecode).digest('hex').slice(0,16))"
```
Expected: matches the local `circuits/enroll_commit_v2/target/enroll_commit_v2.json` bytecode hash (deployed web ↔ deployed service circuit agree).

- [ ] **Step 8: Commit + update memory**

```bash
git add packages/oprf/v3-grumpkin/service/register-test.mjs
git commit -m "test(v3 #39): register-test on 16-word bound-challenge layout; refresh fixtures"
```

Update `~/.claude/projects/-data-Develop-crisp-qes/memory/project_v3_grumpkin_oprf.md`: record that v3 enrollment now uses the v2-style bound-challenge UX (enter RNOKPP → download `crisp-qes-challenge.txt` → sign in Diia → upload), the circuit binds `sha256(signedAttrs)` + returns `messageDigest` (public words 14/15), the service enforces `409 ChallengeMismatch` (epoch `v3-2026`, env `OPRF_ENROLLMENT_EPOCH_V3`), and the `cert[]`↔`pubkey` linkage remains an open audit item.

---

## Notes for the implementer

- **Flavor discipline:** every proof here is verified off-chain by bb.js **default** flavor. Never add `verifierTarget:"evm"` to the v3 worker or fixture generator — that caused the 2026-05-31 `Conversion err`. The sign worker (`prove.worker.ts`) keeps EVM because it's on-chain.
- **Byte-exactness:** `service/challenge.mjs` and `web/src/lib/enrollmentChallengeV3.ts` MUST emit identical bytes. The shared test in Task 4 + Task 7 pin the format; if you touch one, re-run both.
- **`SA_LEN`:** if a real Diia `signedAttrs` exceeds 512 B (unlikely), bump the global in `main.nr` AND `SA_LEN` in `p7sWitness.ts` together, then regenerate fixtures (Task 3).
- **Offset convention:** `parseP7s.messageDigestOffset` points at the 32-byte VALUE; the circuit's `msg_digest_off` points at the `0x04` tag (value offset − 2). Task 6/7 use this consistently.
