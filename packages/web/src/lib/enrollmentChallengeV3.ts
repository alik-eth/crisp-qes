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
