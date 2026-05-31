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
