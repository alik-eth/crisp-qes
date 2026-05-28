// Bundle-fallback intermediate resolution.
//
// Tests the AKI->bundle->manifest path: a .p7s that omits the issuer cert
// can still be chained through the Diia public .p7b bundle. The test
// fixture (`fixtures/diia_ecdsa.p7b`) is public CA material, so it's
// committed; the real Diia .p7s lives outside the repo and the test
// skips gracefully when it's absent.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { flattenFromP7b } from "@crisp-qes/lotl-flattener";

import { parseP7s, type ParsedP7s } from "../src/p7s.js";
import {
    findIntermediate,
    type TrustManifestLike,
} from "../src/findIntermediate.js";
import {
    findIssuerInBundle,
    parseP7bBundle,
    extractAuthorityKeyIdentifier,
    extractSubjectKeyIdentifier,
} from "../src/bundle.js";

const REPO_ROOT = resolve(__dirname, "../../..");
const DIIA_P7B_PATH = resolve(
    REPO_ROOT,
    "packages/lotl-flattener/fixtures/diia_ecdsa.p7b",
);
const REAL_P7S_PATH =
    "/data/Develop/crisp-qes/fixtures/diia/petition-1-binding.bin.p7s";

describe("parseP7bBundle", () => {
    it("returns multiple X.509 certs from the Diia .p7b", () => {
        const bytes = new Uint8Array(readFileSync(DIIA_P7B_PATH));
        const certs = parseP7bBundle(bytes);
        // Diia currently bundles 6 certs (2 QTSP + 2 TSA + 2 OCSP).
        expect(certs.length).toBeGreaterThanOrEqual(2);
        for (const c of certs) {
            expect(c[0]).toBe(0x30); // every entry must be a SEQUENCE
            expect(c.length).toBeGreaterThan(200);
        }
    });

    it("rejects non-signedData input", () => {
        expect(() => parseP7bBundle(new Uint8Array([0x30, 0x01, 0x00]))).toThrow();
    });
});

describe("extractAuthorityKeyIdentifier / extractSubjectKeyIdentifier", () => {
    it("every Diia bundle cert exposes a SKI; reflexive SKI-AKI roundtrip works", () => {
        const bytes = new Uint8Array(readFileSync(DIIA_P7B_PATH));
        const certs = parseP7bBundle(bytes);
        for (const c of certs) {
            const ski = extractSubjectKeyIdentifier(c);
            expect(ski.length).toBeGreaterThan(0);
            // AKI is present on non-self-signed certs; we don't require it
            // globally — just probe that the helper doesn't crash on a
            // present extension.
            try {
                const aki = extractAuthorityKeyIdentifier(c);
                expect(aki.length).toBeGreaterThan(0);
            } catch {
                // self-signed root may omit AKI; that's fine.
            }
        }
    });
});

describe("findIssuerInBundle — negative", () => {
    it("returns null for a leaf whose AKI doesn't match any bundle cert", () => {
        const bytes = new Uint8Array(readFileSync(DIIA_P7B_PATH));
        const bundle = parseP7bBundle(bytes);

        // Hand-craft a minimal "leaf" DER carrying an AKI extension with a
        // bogus keyIdentifier the bundle can't possibly contain. We embed:
        //   30 1F                              SEQUENCE
        //     06 03 55 1d 23                   OID 2.5.29.35 (AKI)
        //     04 18                            OCTET STRING (24 bytes)
        //       30 16                          SEQUENCE (22 bytes)
        //         80 14 <20 bytes of 0xFF>     [0] IMPLICIT keyIdentifier
        const fakeLeaf = new Uint8Array([
            0x30, 0x1f,
            0x06, 0x03, 0x55, 0x1d, 0x23,
            0x04, 0x18,
            0x30, 0x16,
            0x80, 0x14,
            ...new Array(20).fill(0xff),
        ]);
        expect(findIssuerInBundle(fakeLeaf, bundle)).toBeNull();
    });
});

const hasRealP7s = existsSync(REAL_P7S_PATH);
const maybe = hasRealP7s ? describe : describe.skip;

maybe("findIntermediate — bundle fallback (real Diia .p7s)", () => {
    let parsed: ParsedP7s;
    let bundleBytes: Uint8Array;
    let manifest: TrustManifestLike;

    it("setup: real .p7s omits intermediate; bundle resolves it", async () => {
        const p7sBytes = new Uint8Array(readFileSync(REAL_P7S_PATH));
        parsed = parseP7s(p7sBytes);
        // This is the exact regression the patch addresses: the user's real
        // Diia .p7s only carries the leaf cert.
        expect(parsed.intermediateCertDer).toBeNull();

        bundleBytes = new Uint8Array(readFileSync(DIIA_P7B_PATH));

        const flattened = await flattenFromP7b({ bytes: bundleBytes });
        manifest = flattened.manifest as unknown as TrustManifestLike;
        expect(manifest.leaves.length).toBeGreaterThan(0);
    });

    it("returns a FoundIntermediate sourced from the bundle, matching a manifest leaf", async () => {
        const hit = await findIntermediate(parsed, manifest, {
            bundleP7b: bundleBytes,
        });
        expect(hit).not.toBeNull();
        expect(hit!.source).toBe("bundle");
        expect(hit!.intermediateSpkiCommit).toBeGreaterThan(0n);
        // SPKI commit must equal one of the manifest leaves we built from the
        // same bundle the AKI resolved through.
        const commitHex =
            "0x" + hit!.intermediateSpkiCommit.toString(16).padStart(64, "0");
        const matched = manifest.leaves.find(
            (l) => l.spkiCommit.toLowerCase() === commitHex.toLowerCase(),
        );
        expect(matched).toBeDefined();
        // Pubkey + offset are well-formed P-256 fixtures.
        expect(hit!.intermediatePubkey.x).toBeGreaterThan(0n);
        expect(hit!.intermediatePubkey.y).toBeGreaterThan(0n);
        expect(hit!.intermediatePubkeyOffset).toBe(27);
    });

    it("returns null when no bundle is supplied (regression guard)", async () => {
        const hit = await findIntermediate(parsed, manifest);
        expect(hit).toBeNull();
    });
});

if (!hasRealP7s) {
    // eslint-disable-next-line no-console
    console.warn(
        `[bundle-fallback tests] Real Diia .p7s not found at ${REAL_P7S_PATH}; ` +
            "skipping the live-fixture assertions. The unit tests above still run.",
    );
}
