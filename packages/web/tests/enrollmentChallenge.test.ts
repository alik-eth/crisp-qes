// Byte-exact contract test for the v2 enrollment challenge file.
//
// The OPRF service rebuilds these same bytes server-side and asserts
// `sha256(challengeBytes) == p7s.signedAttrs.messageDigest`. Any drift
// in key order, whitespace, hex casing, or 0x-prefix between the two
// implementations breaks every in-flight .p7s. This test pins the
// client output so a regression here is caught BEFORE deploy.
//
// Reference vector (also quoted in the PR description so the OPRF agent
// can verify against it):
//
//   blindedInput = 0xab repeated 32 times
//   epoch        = "v2-2026"
//
//   ↓ buildChallengeBytes
//
//   {"intent":"crisp-qes-enroll-v2","epoch":"v2-2026","blindedInput":"0xabababababababababababababababababababababababababababababababab"}
//
//   134 UTF-8 bytes, no trailing newline.

import { describe, expect, it } from "vitest";
import { buildChallengeBytes, CHALLENGE_INTENT } from "../src/lib/enrollmentChallenge";

const ALL_AB = new Uint8Array(32).fill(0xab);

describe("buildChallengeBytes", () => {
    it("emits the pinned byte sequence for the AB-vector", () => {
        const bytes = buildChallengeBytes(ALL_AB, "v2-2026");
        const expected =
            `{"intent":"crisp-qes-enroll-v2","epoch":"v2-2026","blindedInput":"0xabababababababababababababababababababababababababababababababab"}`;
        const text = new TextDecoder("utf-8").decode(bytes);
        expect(text).toBe(expected);
        expect(bytes.length).toBe(134);
    });

    it("uses lowercase hex with 0x prefix and exactly 64 hex chars", () => {
        const mixed = new Uint8Array(32);
        for (let i = 0; i < 32; i++) mixed[i] = i; // 0x00..0x1f
        const text = new TextDecoder("utf-8").decode(
            buildChallengeBytes(mixed, "v2-2026"),
        );
        const m = text.match(/"blindedInput":"(0x[0-9a-f]{64})"/);
        expect(m).not.toBeNull();
        expect(m![1]).toBe(
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
    });

    it("interpolates the epoch verbatim", () => {
        const text = new TextDecoder("utf-8").decode(
            buildChallengeBytes(ALL_AB, "v3-2027"),
        );
        expect(text).toContain(`"epoch":"v3-2027"`);
        // Key order pinned: intent, epoch, blindedInput.
        expect(text.indexOf(`"intent"`)).toBeLessThan(text.indexOf(`"epoch"`));
        expect(text.indexOf(`"epoch"`)).toBeLessThan(
            text.indexOf(`"blindedInput"`),
        );
    });

    it("rejects non-32-byte input", () => {
        expect(() => buildChallengeBytes(new Uint8Array(31), "v2-2026")).toThrow(
            /32 bytes/,
        );
        expect(() => buildChallengeBytes(new Uint8Array(33), "v2-2026")).toThrow(
            /32 bytes/,
        );
    });

    it("intent is hardcoded to the v2 string", () => {
        expect(CHALLENGE_INTENT).toBe("crisp-qes-enroll-v2");
    });
});
