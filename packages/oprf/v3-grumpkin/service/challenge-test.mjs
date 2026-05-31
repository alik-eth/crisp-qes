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
