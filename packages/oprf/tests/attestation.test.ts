// Unit tests for the v2.1 attestation gate:
//   A — leaf cert ECDSA verify over signedAttrs (task #28)
//   B — chain of trust against the Diia LOTL root (task #27)
//   C — signingTime freshness window (task #30)
//   D — messageDigest payload binding (task #29)
//
// All four exercise the real user fixture at fixtures/diia/petition-1-binding.bin.p7s.
// The trust-root suite additionally needs the Diia LOTL bundle from
// @crisp-qes/lotl-flattener (diia_ecdsa.p7b). When either fixture is missing the
// suite skips, so CI without local fixtures stays green.
//
// Why the round-trip happy path for D lives at the unit level rather than as
// an end-to-end /oprf/blind-eval test: the current `petition-1-binding.bin.p7s`
// fixture was signed over a non-JSON 28-byte enrollment binding, so its
// messageDigest CANNOT equal sha256(canonical_JSON_binding) for any reachable
// blindedInput (sha-256 preimage resistance). We exercise the binding logic
// here by extracting the fixture's real messageDigest and feeding it back as
// `expectedDigest` — proves the bytesEq path inside the attestation gate
// accepts a real Diia signedAttrs payload when the caller computes the digest
// correctly.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";

import {
    AttestationError,
    buildEnrollmentBindingBytes,
    buildTrustedCa,
    parseTrustRootPemBundle,
    verifyAttestation,
    type TrustedCa,
} from "../src/attestation.js";

import { parseP7b } from "@crisp-qes/lotl-flattener";
import { parseP7s } from "@crisp-qes/sdk";

const FIXTURE_PATH =
    "/data/Develop/crisp-qes/fixtures/diia/petition-1-binding.bin.p7s";
const P7B_PATH = resolve(
    process.cwd(),
    "../lotl-flattener/fixtures/diia_ecdsa.p7b",
);
const hasFixture = existsSync(FIXTURE_PATH);
const hasP7b = existsSync(P7B_PATH);
const maybe = hasFixture && hasP7b ? describe : describe.skip;
const maybeFixture = hasFixture ? describe : describe.skip;

function loadFixture(): Uint8Array {
    return new Uint8Array(readFileSync(FIXTURE_PATH));
}

function loadDiiaTrustRoots(): TrustedCa[] {
    const der = new Uint8Array(readFileSync(P7B_PATH));
    return parseP7b(der).map((c) => buildTrustedCa(c));
}

/**
 * The fixture's signingTime is fixed at .p7s creation time and is older than
 * any real freshness window. For tests that want the freshness check to
 * succeed, we anchor `now` to a moment just after that signingTime.
 */
function fixtureNow(): Date {
    const parsed = parseP7s(loadFixture());
    if (!parsed.signingTime) {
        throw new Error("fixture has no signingTime — bad fixture");
    }
    // 10 seconds after the actual signing — well inside any reasonable window.
    return new Date(parsed.signingTime.getTime() + 10_000);
}

maybeFixture("verifyAttestation — task #28: ECDSA over signedAttrs", () => {
    it("accepts the real fixture with trust + freshness checks disabled", () => {
        const v = verifyAttestation(loadFixture(), {
            trustRoots: [],
            signingTimeMaxAgeSec: 0,
        });
        expect(v.subjectSerialAscii.startsWith("TINUA-")).toBe(true);
    });

    it("rejects a fixture whose leaf signature value was tampered with", () => {
        // Flip a byte deep inside the SignerInfo signature OCTET STRING.
        const tampered = new Uint8Array(loadFixture());
        tampered[tampered.length - 1] ^= 0x01;
        expect(() =>
            verifyAttestation(tampered, {
                trustRoots: [],
                signingTimeMaxAgeSec: 0,
            }),
        ).toThrow(
            expect.objectContaining({
                code: "SignatureInvalid",
            }),
        );
    });
});

maybe("verifyAttestation — task #27: chain-of-trust", () => {
    it("accepts the fixture when its issuer is in the Diia trust set", () => {
        const v = verifyAttestation(loadFixture(), {
            trustRoots: loadDiiaTrustRoots(),
            signingTimeMaxAgeSec: 0,
        });
        expect(v.chainAnchor).not.toBeNull();
    });

    it("rejects when the trust set is non-empty but doesn't cover the issuer", () => {
        const all = loadDiiaTrustRoots();
        const filtered = all.filter(
            (t) =>
                !t.commonName.includes("Qualified Trust Services Provider") ||
                t.commonName.startsWith("TSA-") ||
                t.commonName.startsWith("OCSP-"),
        );
        expect(filtered.length).toBeGreaterThan(0);
        expect(filtered.length).toBeLessThan(all.length);

        expect(() =>
            verifyAttestation(loadFixture(), {
                trustRoots: filtered,
                signingTimeMaxAgeSec: 0,
            }),
        ).toThrow(
            expect.objectContaining({
                code: "ChainInvalid",
            }),
        );
    });

    it("rejects with ChainInvalid when the trust set's subject DNs are zeroed", () => {
        const all = loadDiiaTrustRoots();
        const tampered: TrustedCa[] = all.map((t) => ({
            ...t,
            subjectDer: new Uint8Array(t.subjectDer.length),
        }));
        expect(() =>
            verifyAttestation(loadFixture(), {
                trustRoots: tampered,
                signingTimeMaxAgeSec: 0,
            }),
        ).toThrow(
            expect.objectContaining({
                code: "ChainInvalid",
            }),
        );
    });
});

maybeFixture("verifyAttestation — task #30: signingTime freshness", () => {
    it("accepts when signingTime is within the freshness window", () => {
        const v = verifyAttestation(loadFixture(), {
            trustRoots: [],
            signingTimeMaxAgeSec: 600,
            now: fixtureNow(),
        });
        expect(v.signingTime).not.toBeNull();
    });

    it("rejects when signingTime is older than the threshold", () => {
        expect(() =>
            verifyAttestation(loadFixture(), {
                trustRoots: [],
                signingTimeMaxAgeSec: 1,
                now: new Date(),
            }),
        ).toThrow(
            expect.objectContaining({
                code: "Stale",
            }),
        );
    });

    it("rejects when signingTime is too far in the future", () => {
        const fakeNow = new Date(fixtureNow().getTime() - 10 * 60 * 1000);
        expect(() =>
            verifyAttestation(loadFixture(), {
                trustRoots: [],
                signingTimeMaxAgeSec: 600,
                signingTimeClockSkewSec: 60,
                now: fakeNow,
            }),
        ).toThrow(
            expect.objectContaining({
                code: "Stale",
            }),
        );
    });
});

describe("parseTrustRootPemBundle", () => {
    it("rejects an empty PEM input", () => {
        expect(() => parseTrustRootPemBundle("")).toThrow(/no PEM/i);
    });

    it("round-trips a single Diia CA cert through PEM", () => {
        if (!hasP7b) return; // skip silently if the bundle isn't shipped
        const trustRoots = loadDiiaTrustRoots();
        const der = trustRoots[0]!.certDer;
        const b64 = Buffer.from(der).toString("base64");
        const wrapped = b64.match(/.{1,64}/g)!.join("\n");
        const pem = `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
        const round = parseTrustRootPemBundle(pem);
        expect(round.length).toBe(1);
        expect(round[0]!.commonName).toBe(trustRoots[0]!.commonName);
    });
});

describe("buildEnrollmentBindingBytes", () => {
    it("emits the pinned JSON shape byte-for-byte", () => {
        const epoch = "v2-2026";
        const blindedInput = `0x${"ab".repeat(32)}`;
        const bytes = buildEnrollmentBindingBytes(epoch, blindedInput);
        const decoded = new TextDecoder("utf-8").decode(bytes);
        expect(decoded).toBe(
            `{"intent":"crisp-qes-enroll-v2","epoch":"v2-2026","blindedInput":"${blindedInput}"}`,
        );
        const ref = JSON.stringify({
            intent: "crisp-qes-enroll-v2",
            epoch,
            blindedInput,
        });
        expect(decoded).toBe(ref);
    });

    it("rejects a blindedInput that isn't lowercase 0x-prefixed 64 hex chars", () => {
        expect(() =>
            buildEnrollmentBindingBytes("v2-2026", "ab".repeat(32)),
        ).toThrow(expect.objectContaining({ code: "PayloadMismatch" }));
        expect(() =>
            buildEnrollmentBindingBytes("v2-2026", `0x${"AB".repeat(32)}`),
        ).toThrow(expect.objectContaining({ code: "PayloadMismatch" }));
        expect(() =>
            buildEnrollmentBindingBytes("v2-2026", `0x${"ab".repeat(31)}`),
        ).toThrow(expect.objectContaining({ code: "PayloadMismatch" }));
    });

    it("rejects an epoch containing a quote or backslash", () => {
        const okBlinded = `0x${"00".repeat(32)}`;
        expect(() =>
            buildEnrollmentBindingBytes('v2"injected', okBlinded),
        ).toThrow(expect.objectContaining({ code: "PayloadMismatch" }));
        expect(() =>
            buildEnrollmentBindingBytes("v2\\injected", okBlinded),
        ).toThrow(expect.objectContaining({ code: "PayloadMismatch" }));
        expect(() => buildEnrollmentBindingBytes("", okBlinded)).toThrow(
            expect.objectContaining({ code: "PayloadMismatch" }),
        );
    });
});

maybeFixture("verifyAttestation — task #29: payload binding", () => {
    it("accepts the real Diia fixture when expectedDigest equals the fixture's actual messageDigest", () => {
        // Proves the bytesEq path accepts a real Diia signedAttrs payload —
        // which is what will happen once a JSON-binding-signed fixture lands.
        const p7sBytes = loadFixture();
        const parsed = parseP7s(p7sBytes);
        const expectedDigest = parsed.messageDigest;
        const v = verifyAttestation(p7sBytes, {
            trustRoots: [],
            signingTimeMaxAgeSec: 0,
            expectedDigest,
        });
        expect(v.subjectSerialAscii.startsWith("TINUA-")).toBe(true);
    });

    it("rejects with PayloadMismatch when expectedDigest does not match signedAttrs.messageDigest", () => {
        const p7sBytes = loadFixture();
        const expectedDigest = sha256(
            buildEnrollmentBindingBytes(
                "v2-2026",
                `0x${"01".repeat(32)}`,
            ),
        );
        expect(() =>
            verifyAttestation(p7sBytes, {
                trustRoots: [],
                signingTimeMaxAgeSec: 0,
                expectedDigest,
            }),
        ).toThrow(expect.objectContaining({ code: "PayloadMismatch" }));
    });

    it("rejects with PayloadMismatch when expectedDigest is not 32 bytes", () => {
        const p7sBytes = loadFixture();
        const tooShort = new Uint8Array(31);
        expect(() =>
            verifyAttestation(p7sBytes, {
                trustRoots: [],
                signingTimeMaxAgeSec: 0,
                expectedDigest: tooShort,
            }),
        ).toThrow(expect.objectContaining({ code: "PayloadMismatch" }));
        const tooLong = new Uint8Array(33);
        expect(() =>
            verifyAttestation(p7sBytes, {
                trustRoots: [],
                signingTimeMaxAgeSec: 0,
                expectedDigest: tooLong,
            }),
        ).toThrow(expect.objectContaining({ code: "PayloadMismatch" }));
    });

    it("skips the binding check when expectedDigest is null (back-compat)", () => {
        const p7sBytes = loadFixture();
        const v = verifyAttestation(p7sBytes, {
            trustRoots: [],
            signingTimeMaxAgeSec: 0,
            expectedDigest: null,
        });
        expect(v.subjectSerialAscii.startsWith("TINUA-")).toBe(true);
    });

    it("skips the binding check when expectedDigest is omitted", () => {
        const p7sBytes = loadFixture();
        const v = verifyAttestation(p7sBytes, {
            trustRoots: [],
            signingTimeMaxAgeSec: 0,
        });
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

// Wire-format tripwire — if anyone changes the JSON key order or whitespace
// policy this constant flips and the diff is loud in code review. The web
// client's `buildChallengeBytes` MUST produce byte-identical output.
describe("canonical binding — wire-format tripwire", () => {
    it("digest for (epoch=v2-2026, blindedInput=0x00…00) matches the hand-rolled literal", () => {
        const bytes = buildEnrollmentBindingBytes(
            "v2-2026",
            `0x${"00".repeat(32)}`,
        );
        const digestHex = bytesToHex(sha256(bytes));
        const literal =
            `{"intent":"crisp-qes-enroll-v2","epoch":"v2-2026","blindedInput":"0x${"00".repeat(32)}"}`;
        const refHex = bytesToHex(
            sha256(new TextEncoder().encode(literal)),
        );
        expect(digestHex).toBe(refHex);
    });
});
