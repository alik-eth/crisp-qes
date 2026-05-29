// Unit tests for the v2.1-prod payload-binding gate (task #29).
//
// The binding check inside `verifyAttestation` compares the inner
// `signedAttrs.messageDigest` of the Diia .p7s against a caller-supplied
// `expectedDigest = sha256(canonical_enrollment_binding_bytes)`. The canonical
// binding is the UTF-8 of the compact JSON
//   {"intent":"crisp-qes-enroll-v2","epoch":"<epoch>","blindedInput":"0x<64-hex>"}
// — keys in that exact order, no whitespace, no trailing newline.
//
// Why the round-trip happy path is in this file rather than an end-to-end
// /oprf/blind-eval test: the current `petition-1-binding.bin.p7s` fixture was
// signed over a non-JSON 28-byte enrollment binding, so its messageDigest
// CANNOT equal sha256(canonical_JSON_binding) for any reachable blindedInput
// (sha-256 preimage resistance). Until a JSON-binding-signed fixture lands,
// we exercise the binding logic at the unit level by extracting the fixture's
// real messageDigest and feeding it back as `expectedDigest` — which proves
// the byte-equality path accepts a real Diia .p7s when the caller computed
// the digest correctly.
//
// TODO: end-to-end binding test fixture — regenerate
//   fixtures/diia/petition-1-binding.bin as the canonical JSON binding for a
//   fixed (epoch, blindedInput) pair, then re-sign in Diia, then add the
//   true round-trip happy-path test in app.test.ts.

import { existsSync, readFileSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";

import { parseP7s } from "@crisp-qes/sdk";

import {
    AttestationError,
    buildEnrollmentBindingBytes,
    verifyAttestation,
} from "../src/attestation.js";

const FIXTURE_PATH =
    "/data/Develop/crisp-qes/fixtures/diia/petition-1-binding.bin.p7s";
const hasFixture = existsSync(FIXTURE_PATH);
const maybe = hasFixture ? describe : describe.skip;

function loadFixture(): Uint8Array {
    return new Uint8Array(readFileSync(FIXTURE_PATH));
}

describe("buildEnrollmentBindingBytes", () => {
    it("emits the pinned JSON shape byte-for-byte", () => {
        const epoch = "v2-2026";
        const blindedInput = `0x${"ab".repeat(32)}`;
        const bytes = buildEnrollmentBindingBytes(epoch, blindedInput);
        const decoded = new TextDecoder("utf-8").decode(bytes);
        // Key order, no whitespace, no trailing newline.
        expect(decoded).toBe(
            `{"intent":"crisp-qes-enroll-v2","epoch":"v2-2026","blindedInput":"${blindedInput}"}`,
        );
        // Sanity: matches a hand-rolled JSON.stringify with the same key
        // order (we don't use JSON.stringify in src because we want to
        // guarantee byte-equality against the web client's reconstruction
        // independent of Node/V8 stringify behavior).
        const ref = JSON.stringify({
            intent: "crisp-qes-enroll-v2",
            epoch,
            blindedInput,
        });
        expect(decoded).toBe(ref);
    });

    it("rejects a blindedInput that isn't lowercase 0x-prefixed 64 hex chars", () => {
        // Missing 0x prefix.
        expect(() =>
            buildEnrollmentBindingBytes("v2-2026", "ab".repeat(32)),
        ).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
        // Uppercase hex — the wire format mandates lowercase so the
        // server-side reconstruction is unambiguous.
        expect(() =>
            buildEnrollmentBindingBytes("v2-2026", `0x${"AB".repeat(32)}`),
        ).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
        // Wrong length.
        expect(() =>
            buildEnrollmentBindingBytes("v2-2026", `0x${"ab".repeat(31)}`),
        ).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
    });

    it("rejects an epoch containing a quote or backslash", () => {
        const okBlinded = `0x${"00".repeat(32)}`;
        expect(() =>
            buildEnrollmentBindingBytes('v2"injected', okBlinded),
        ).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
        expect(() =>
            buildEnrollmentBindingBytes("v2\\injected", okBlinded),
        ).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
        expect(() => buildEnrollmentBindingBytes("", okBlinded)).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
    });
});

maybe("verifyAttestation — payload binding (task #29)", () => {
    it("accepts the real Diia fixture when expectedDigest equals the fixture's actual messageDigest", () => {
        // Extract the fixture's messageDigest and feed it back as the
        // expectedDigest. This proves the bytesEq path inside the
        // attestation gate accepts a real Diia signedAttrs payload — which
        // is exactly what will happen once a JSON-binding-signed fixture
        // lands (the citizen's web client computes
        // sha256(buildEnrollmentBindingBytes(epoch, blindedInput)) and the
        // server reconstructs the same bytes).
        const p7sBytes = loadFixture();
        const parsed = parseP7s(p7sBytes);
        const expectedDigest = parsed.messageDigest;
        const v = verifyAttestation(p7sBytes, { expectedDigest });
        expect(v.subjectSerialAscii.startsWith("TINUA-")).toBe(true);
    });

    it("rejects with PayloadMismatch when expectedDigest does not match signedAttrs.messageDigest", () => {
        const p7sBytes = loadFixture();
        // sha256 of the canonical binding for an arbitrary (epoch,
        // blindedInput) pair — guaranteed not to equal the fixture's
        // messageDigest by sha-256 preimage resistance.
        const expectedDigest = sha256(
            buildEnrollmentBindingBytes(
                "v2-2026",
                `0x${"01".repeat(32)}`,
            ),
        );
        expect(() =>
            verifyAttestation(p7sBytes, { expectedDigest }),
        ).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
    });

    it("rejects with PayloadMismatch when expectedDigest is not 32 bytes", () => {
        const p7sBytes = loadFixture();
        const tooShort = new Uint8Array(31);
        expect(() =>
            verifyAttestation(p7sBytes, { expectedDigest: tooShort }),
        ).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
        const tooLong = new Uint8Array(33);
        expect(() =>
            verifyAttestation(p7sBytes, { expectedDigest: tooLong }),
        ).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
    });

    it("skips the binding check when expectedDigest is null (back-compat for non-binding tests)", () => {
        const p7sBytes = loadFixture();
        const v = verifyAttestation(p7sBytes, { expectedDigest: null });
        expect(v.subjectSerialAscii.startsWith("TINUA-")).toBe(true);
    });

    it("skips the binding check when called with the default options object", () => {
        // The function signature defaults to `{ expectedDigest: null }` —
        // existing call sites that pre-date task #29 keep compiling.
        const p7sBytes = loadFixture();
        const v = verifyAttestation(p7sBytes);
        expect(v.subjectSerialAscii.startsWith("TINUA-")).toBe(true);
    });
});

describe("AttestationError", () => {
    it("constructs PayloadMismatch instances with a readable name + code", () => {
        const e = new AttestationError("PayloadMismatch", "demo");
        expect(e.name).toBe("AttestationError");
        expect(e.code).toBe("PayloadMismatch");
        expect(e.message).toBe("demo");
    });
});

// Diagnostic helper for the web team: emitting the hex of the canonical
// binding for a small fixed input so the web client can byte-match its own
// reconstruction. Not an assertion, but a tripwire — if anyone changes the
// JSON key order or whitespace policy this constant flips and the diff is
// loud in code review.
describe("canonical binding — wire-format tripwire", () => {
    it("hex digest for (epoch=v2-2026, blindedInput=0x00…00) is the pinned constant", () => {
        const bytes = buildEnrollmentBindingBytes(
            "v2-2026",
            `0x${"00".repeat(32)}`,
        );
        const digestHex = bytesToHex(sha256(bytes));
        // If this expectation ever fails, the wire format changed. Coordinate
        // with the web team's `oprfClient.ts` before updating the constant.
        const literal =
            `{"intent":"crisp-qes-enroll-v2","epoch":"v2-2026","blindedInput":"0x${"00".repeat(32)}"}`;
        const refHex = bytesToHex(
            sha256(new TextEncoder().encode(literal)),
        );
        expect(digestHex).toBe(refHex);
    });
});
