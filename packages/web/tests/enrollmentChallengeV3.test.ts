import { describe, it, expect } from "vitest";
import {
    buildChallengeBytesV3,
    pointToChallengeHex,
} from "../src/lib/enrollmentChallengeV3";
import { hashToCurve } from "../src/lib/grumpkin";

describe("enrollmentChallengeV3", () => {
    it("is byte-exact with the documented wire format", () => {
        const M = hashToCurve(new TextEncoder().encode("1234567890")).multiply(
            7n,
        );
        const hex = pointToChallengeHex(M);
        const bytes = buildChallengeBytesV3(M, "v3-2026");
        expect(new TextDecoder().decode(bytes)).toBe(
            `{"intent":"crisp-qes-enroll-v3","epoch":"v3-2026","blindedInput":"${hex}"}`,
        );
        expect(hex).toMatch(/^0x[0-9a-f]{128}$/);
    });
});
