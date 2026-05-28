// Smoke test for `findIntermediate`.
//
// We construct a synthetic SPKI DER, compute its commit via the same
// chunking the circuit + flattener pin, then feed it into a 2-leaf
// manifest. `findIntermediate` should return the matching leaf with its
// Merkle path; flipping a byte of the SPKI should cause it to miss.

import { describe, expect, it } from "vitest";

import type { ParsedP7s } from "../src/p7s.js";
import {
    findIntermediate,
    spkiCommit,
    type TrustManifestLike,
} from "../src/findIntermediate.js";

function synthParsed(intermediateSpki: Uint8Array): ParsedP7s {
    return {
        signedAttrs: new Uint8Array(64),
        signedAttrsSha256: new Uint8Array(32),
        messageDigest: new Uint8Array(32),
        messageDigestOffset: 0,
        subjectSerial: new TextEncoder().encode("TINUA-XXXXXXXX"),
        leafCertDer: new Uint8Array(0),
        leafTbsBytes: new Uint8Array(0),
        leafTbsSha256: new Uint8Array(32),
        subjectSerialOffset: 0,
        leafPubkeyOffset: 27,
        leafSpkiDer: new Uint8Array(0),
        intermediateCertDer: new Uint8Array([0x30, 0x01, 0x00]),
        intermediateSpkiDer: intermediateSpki,
        intermediatePubkey: { x: 1n, y: 2n },
        intermediatePubkeyOffset: 27,
        pubkey: { x: 3n, y: 4n },
        signature: { r: 5n, s: 6n },
        leafCertSignature: { r: 7n, s: 8n },
    };
}

describe("findIntermediate", () => {
    it("matches a synthetic SPKI against a manifest leaf and returns the Merkle path", async () => {
        const spki = new Uint8Array(120);
        for (let i = 0; i < spki.length; i++) spki[i] = (i * 13 + 7) & 0xff;
        const commit = await spkiCommit(spki);
        const commitHex = "0x" + commit.toString(16).padStart(64, "0");

        const manifest: TrustManifestLike = {
            version: "1",
            hash: "pedersen-bn254",
            treeDepth: 16,
            root: "0x" + "00".repeat(32),
            leaves: [
                {
                    merkleIndex: 0,
                    subjectDn: "CN=Decoy",
                    spkiCommit: "0x" + "ff".repeat(32),
                    merklePath: new Array(16).fill("0x" + "11".repeat(32)),
                    merklePathIndices: new Array(16).fill(0),
                },
                {
                    merkleIndex: 1,
                    subjectDn: "CN=Diia QES Test CA",
                    spkiCommit: commitHex,
                    merklePath: new Array(16).fill("0x" + "22".repeat(32)),
                    merklePathIndices: new Array(16).fill(1),
                    tspName: "Diia QES Test TSP",
                    issuerDn: "CN=Diia Root",
                },
            ],
        };

        const hit = await findIntermediate(synthParsed(spki), manifest);
        expect(hit).not.toBeNull();
        expect(hit!.leaf.subjectDn).toBe("CN=Diia QES Test CA");
        expect(hit!.merklePath.length).toBe(16);
        expect(hit!.merklePathIndices.length).toBe(16);
        expect(hit!.intermediateSpkiCommit).toBe(commit);
        // Path entries decoded into bigints (each entry == 0x22... = same value).
        const want = BigInt("0x" + "22".repeat(32));
        for (const p of hit!.merklePath) expect(p).toBe(want);
    });

    it("returns null when the intermediate SPKI doesn't match any leaf", async () => {
        const a = new Uint8Array(120).fill(0x01);
        const b = new Uint8Array(120).fill(0x02);
        const commitA = await spkiCommit(a);
        const manifest: TrustManifestLike = {
            version: "1",
            hash: "pedersen-bn254",
            treeDepth: 16,
            root: "0x" + "00".repeat(32),
            leaves: [
                {
                    merkleIndex: 0,
                    subjectDn: "CN=Only Leaf",
                    spkiCommit: "0x" + commitA.toString(16).padStart(64, "0"),
                    merklePath: new Array(16).fill("0x" + "00".repeat(32)),
                    merklePathIndices: new Array(16).fill(0),
                },
            ],
        };
        const hit = await findIntermediate(synthParsed(b), manifest);
        expect(hit).toBeNull();
    });

    it("returns null when the .p7s has no intermediate cert", async () => {
        const parsed = synthParsed(new Uint8Array(80));
        parsed.intermediateCertDer = null;
        parsed.intermediateSpkiDer = null;
        parsed.intermediatePubkey = null;
        parsed.intermediatePubkeyOffset = null;

        const manifest: TrustManifestLike = {
            version: "1",
            hash: "pedersen-bn254",
            treeDepth: 16,
            root: "0x00",
            leaves: [],
        };
        expect(await findIntermediate(parsed, manifest)).toBeNull();
    });
});
