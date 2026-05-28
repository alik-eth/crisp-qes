// Tests for the .p7s CAdES parser.
//
// We exercise it against a real Diia signature when one is available on
// disk at the upstream identityescroworg path. Fixtures contain legal
// identity material per spec §4 ("fixtures/diia/" gitignored) so the file
// is NEVER copied into this repo — the test reads it by absolute path and
// skips itself when the file is absent (CI without local fixtures stays
// green).

import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseP7s } from "../src/p7s.js";

const DIIA_P7S_PATH =
    "/home/alikvovk/Develop/identityescroworg/fixtures/qes/admin-binding.qkb.json.p7s";

const hasFixture = existsSync(DIIA_P7S_PATH);
const maybe = hasFixture ? describe : describe.skip;

maybe("parseP7s — real Diia fixture", () => {
    const bytes = hasFixture
        ? new Uint8Array(readFileSync(DIIA_P7S_PATH))
        : new Uint8Array(0);
    const parsed = parseP7s(bytes);

    it("extracts a TINUA-prefixed subject serial", () => {
        const ascii = new TextDecoder("utf-8").decode(parsed.subjectSerial);
        expect(ascii.startsWith("TINUA-")).toBe(true);
    });

    it("returns a 32-byte messageDigest", () => {
        expect(parsed.messageDigest).toBeInstanceOf(Uint8Array);
        expect(parsed.messageDigest.length).toBe(32);
    });

    it("returns 32-byte P-256 pubkey coordinates", () => {
        // toString(16) gives a hex without leading zeroes — pad to 64 to
        // assert "fits in 32 bytes" semantically rather than literally.
        const xHex = parsed.pubkey.x.toString(16).padStart(64, "0");
        const yHex = parsed.pubkey.y.toString(16).padStart(64, "0");
        expect(xHex.length).toBe(64);
        expect(yHex.length).toBe(64);
        expect(parsed.pubkey.x).toBeGreaterThan(0n);
        expect(parsed.pubkey.y).toBeGreaterThan(0n);
    });

    it("returns nonzero ECDSA r and s", () => {
        expect(parsed.signature.r).toBeGreaterThan(0n);
        expect(parsed.signature.s).toBeGreaterThan(0n);
    });

    it("signedAttrsSha256 equals sha256(signedAttrs)", () => {
        const digest = new Uint8Array(
            createHash("sha256").update(parsed.signedAttrs).digest(),
        );
        expect(toHex(parsed.signedAttrsSha256)).toBe(toHex(digest));
        expect(parsed.signedAttrsSha256.length).toBe(32);
    });

    it("signedAttrs starts with the SET tag (0x31), not [0] IMPLICIT (0xA0)", () => {
        // Confirms the tag-rewrite required for the EIP-7212 / CAdES
        // signed-form. The 0xA0 byte is the on-the-wire encoding pkijs
        // surfaces by default; if we got that, sha256(signedAttrs) would
        // be wrong and on-chain verification would fail.
        expect(parsed.signedAttrs[0]).toBe(0x31);
    });

    it("leafCertDer is a non-trivial Certificate SEQUENCE", () => {
        expect(parsed.leafCertDer.length).toBeGreaterThan(200);
        expect(parsed.leafCertDer[0]).toBe(0x30); // SEQUENCE
    });

    it("intermediateCertDer is either null or a Certificate SEQUENCE", () => {
        if (parsed.intermediateCertDer === null) return;
        expect(parsed.intermediateCertDer.length).toBeGreaterThan(200);
        expect(parsed.intermediateCertDer[0]).toBe(0x30);
    });
});

describe("parseP7s — error cases", () => {
    it("rejects garbage bytes", () => {
        expect(() => parseP7s(new Uint8Array([1, 2, 3, 4]))).toThrow();
    });

    it("rejects an empty buffer", () => {
        expect(() => parseP7s(new Uint8Array(0))).toThrow();
    });
});

if (!hasFixture) {
    // eslint-disable-next-line no-console
    console.warn(
        `[parseP7s tests] Diia fixture not found at ${DIIA_P7S_PATH}; ` +
            "skipping real-signature assertions. This is expected in CI.",
    );
}

function toHex(b: Uint8Array): string {
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
