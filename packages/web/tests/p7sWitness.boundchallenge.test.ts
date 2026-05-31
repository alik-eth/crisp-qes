// Bound-challenge witness fields for buildP7sEnrollWitness (v3, task #39).
//
// The existing p7sWitness.test.ts deliberately does NOT fabricate a CAdES
// envelope (pkijs is not a web dep, and a hand-rolled p7s would test the
// fixture, not the parser), so there is NO synthetic-.p7s helper to reuse for
// the full buildP7sEnrollWitness path. We therefore exercise the end-to-end
// path against the SAME real Diia fixture the SDK's p7s.test.ts uses, skipping
// when it is absent (CI without local fixtures stays green). A synthetic cert
// buffer alone cannot satisfy parseP7s — it needs a full SignedData/SignerInfo
// with a PKCS#9 messageDigest, which the new bound-challenge fields read.
//
// CONCERN (flagged to the orchestrator): this fixture's signedAttrs is ~1388 B,
// which EXCEEDS the circuit's SA_LEN (512). When signedAttrs fits SA_LEN we
// assert the three new fields on a real witness; when it overflows we assert
// the SA_LEN guard fires AND independently verify (via parseP7s) that the
// 04 20 OCTET STRING header sits at messageDigestOffset - 2 — i.e. the exact
// offset math buildP7sEnrollWitness uses. Either way the new code path is
// exercised. See report: real enrollment signedAttrs may need SA_LEN bumped.

import { existsSync, readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { parseP7s } from "@crisp-qes/sdk";
import { buildP7sEnrollWitness, SA_LEN } from "../src/lib/p7sWitness";

// Same fixture path + skip-gate as packages/sdk/tests/p7s.test.ts.
const DIIA_P7S_PATH =
    "/home/alikvovk/Develop/identityescroworg/fixtures/qes/admin-binding.qkb.json.p7s";
const hasFixture = existsSync(DIIA_P7S_PATH);
const maybe = hasFixture ? describe : describe.skip;

// DOB embedded in this fixture (leading 8 digits of the SubjectDirectory-
// Attributes DOB string), confirmed by introspecting the parsed leaf cert.
const FIXTURE_DOB = "19990426";

maybe("buildP7sEnrollWitness bound-challenge fields", () => {
    const p7sBytes = hasFixture
        ? new Uint8Array(readFileSync(DIIA_P7S_PATH))
        : new Uint8Array(0);

    it("emits signed_attrs / signed_attrs_len / msg_digest_off and no msghash", () => {
        const parsed = parseP7s(p7sBytes);
        const fits = parsed.signedAttrs.length <= SA_LEN;

        if (fits) {
            const { witness } = buildP7sEnrollWitness(p7sBytes, FIXTURE_DOB, {
                r: 7n,
            });
            expect(Array.isArray(witness.signed_attrs)).toBe(true);
            expect((witness.signed_attrs as string[]).length).toBe(SA_LEN);

            // The old free-msghash field must be gone.
            expect(witness.msghash).toBeUndefined();

            const len = Number(witness.signed_attrs_len);
            expect(len).toBe(parsed.signedAttrs.length);
            expect(len).toBeLessThanOrEqual(SA_LEN);

            // u8arr renders bytes as decimal: 0x04 -> "4", 0x20 -> "32".
            const off = Number(witness.msg_digest_off);
            expect((witness.signed_attrs as string[])[off]).toBe("4");
            expect((witness.signed_attrs as string[])[off + 1]).toBe("32");
        } else {
            // signedAttrs overflows SA_LEN: the guard must fire...
            expect(() =>
                buildP7sEnrollWitness(p7sBytes, FIXTURE_DOB, { r: 7n }),
            ).toThrow(/exceeds SA_LEN/);

            // ...and the offset math the builder uses must still be correct:
            // the 04 20 OCTET STRING header sits at messageDigestOffset - 2.
            const off = parsed.messageDigestOffset - 2;
            expect(parsed.signedAttrs[off]).toBe(0x04);
            expect(parsed.signedAttrs[off + 1]).toBe(0x20);
        }
    });
});
