// Unit tests for the v2.1 attestation gate:
//   A — leaf cert ECDSA verify over signedAttrs (task #28)
//   B — chain of trust against the Diia LOTL root (task #27)
//   C — signingTime freshness window (task #30)
//
// All three exercise the real user fixture at fixtures/diia/petition-1-binding.bin.p7s.
// The bundled trust material comes from @crisp-qes/lotl-flattener
// (diia_ecdsa.p7b). When either fixture is missing the suite skips, so CI
// without local fixtures stays green.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
    AttestationError,
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

maybe("verifyAttestation — task A: ECDSA over signedAttrs", () => {
    it("accepts the real fixture with trust + freshness checks disabled", () => {
        const v = verifyAttestation(loadFixture(), {
            trustRoots: [],
            signingTimeMaxAgeSec: 0,
        });
        expect(v.subjectSerialAscii.startsWith("TINUA-")).toBe(true);
    });

    it("rejects a fixture whose leaf signature value was tampered with", () => {
        // Flip a byte deep inside the SignerInfo signature OCTET STRING.
        // The .p7s file ends with the ECDSA-Sig-Value DER — mutating the
        // last byte (low-order byte of `s`) gives a valid DER blob that
        // fails verification.
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

maybe("verifyAttestation — task B: chain-of-trust", () => {
    it("accepts the fixture when its issuer is in the Diia trust set", () => {
        const v = verifyAttestation(loadFixture(), {
            trustRoots: loadDiiaTrustRoots(),
            signingTimeMaxAgeSec: 0,
        });
        // Some CA in the trust set anchored the chain.
        expect(v.chainAnchor).not.toBeNull();
    });

    it("rejects when the trust set is non-empty but doesn't cover the issuer", () => {
        // Drop the two QTSP intermediates and keep only the TSA/OCSP service
        // certs. The leaf's issuer is the QTSP CA, so it won't chain.
        const all = loadDiiaTrustRoots();
        const filtered = all.filter(
            (t) =>
                !t.commonName.includes("Qualified Trust Services Provider") ||
                t.commonName.startsWith("TSA-") ||
                t.commonName.startsWith("OCSP-"),
        );
        // Sanity: we removed something but kept the rest.
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

    it("rejects with ChainInvalid when the empty trust set is replaced by the wrong CA", () => {
        // Build a fake trust set out of a single mutated CA — same DN, but
        // the SPKI bytes differ from what the leaf was actually signed under.
        // The leaf's issuer DN won't match anything either, so we expect
        // ChainInvalid.
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

maybe("verifyAttestation — task C: signingTime freshness", () => {
    it("accepts when signingTime is within the freshness window", () => {
        const v = verifyAttestation(loadFixture(), {
            trustRoots: [],
            signingTimeMaxAgeSec: 600,
            now: fixtureNow(),
        });
        expect(v.signingTime).not.toBeNull();
    });

    it("rejects when signingTime is older than the threshold", () => {
        // Wall-clock now is well past any plausible fixture signingTime.
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
        // Pretend the server clock is far behind the fixture's signingTime.
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
        // Wrap to 64-char lines for PEM canonical form (parser tolerates
        // either, but let's exercise the canonical path).
        const wrapped = b64.match(/.{1,64}/g)!.join("\n");
        const pem = `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
        const round = parseTrustRootPemBundle(pem);
        expect(round.length).toBe(1);
        expect(round[0]!.commonName).toBe(trustRoots[0]!.commonName);
    });
});
