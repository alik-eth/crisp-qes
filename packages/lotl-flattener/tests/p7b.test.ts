import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { diiaP7bFilter, flattenFromP7b, parseP7b } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, "../fixtures");
const p7bPath = resolve(fixturesDir, "diia_ecdsa.p7b");

// Pinned inputs — any drift in the bundle, the filter, the chunking, or
// the Merkle domain separators changes this root. The orchestrator pins
// this same value into the on-chain `trustRoot` at PetitionRegistry deploy
// time, so this test acts as a deploy-input regression gate.
const PIN = {
  lotlVersion: "diia-p7b-2026-05-28",
  builtAt: "2026-05-28T00:00:00Z",
  treeDepth: 16,
} as const;

describe("parseP7b — DER walker", () => {
  test("extracts every Certificate carried in the Diia .p7b bundle", async () => {
    const der = new Uint8Array(await readFile(p7bPath));
    const certs = parseP7b(der);
    // Diia's diia_ecdsa.p7b ships 6 certs: 2 qualified issuers + 2 TSA
    // service certs + 2 OCSP service certs. The parser returns all of them
    // in DER order, leaving filtering to the caller.
    expect(certs.length).toBe(6);
    for (const c of certs) {
      // Every entry must be a SEQUENCE (X.509 Certificate).
      expect(c[0]).toBe(0x30);
      // ~1KB-ish per Diia ECDSA cert; reject obvious truncations.
      expect(c.length).toBeGreaterThan(500);
    }
  });

  test("rejects a non-SignedData blob", () => {
    expect(() => parseP7b(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]))).toThrow(
      /signedData/i,
    );
  });

  test("rejects garbage", () => {
    expect(() => parseP7b(new Uint8Array([0xff, 0xff, 0xff, 0xff]))).toThrow();
    expect(() => parseP7b(new Uint8Array(0))).toThrow();
  });
});

describe("diiaP7bFilter", () => {
  test("drops TSA-server and OCSP-server certs by CN prefix", () => {
    const subjects = [
      'O=DIIA\nCN="DIIA". Qualified Trust Services Provider\nC=UA',
      "O=DIIA\nCN=TSA-server QTSP DIIA\nC=UA",
      "O=DIIA\nCN=OCSP-server DIIA. Qualified Trust Services Provider\nC=UA",
    ];
    const kept = subjects.filter((s) =>
      diiaP7bFilter({
        certDer: new Uint8Array(0),
        subjectDn: s,
        issuerDn: "",
      }),
    );
    expect(kept).toEqual([subjects[0]]);
  });
});

describe("flattenFromP7b — Pedersen-Merkle trust root", () => {
  test("produces a stable root and the right leaf count from the Diia bundle", async () => {
    const result = await flattenFromP7b({
      in: p7bPath,
      ...PIN,
    });

    // After the default filter (drop TSA-server + OCSP-server CNs), the
    // Diia bundle has 2 qualified-issuer certs that actually sign citizen
    // QES leaves (a current + previous generation).
    expect(result.caCount).toBe(2);
    expect(result.manifest.treeDepth).toBe(16);
    expect(result.manifest.hash).toBe("pedersen-bn254");
    expect(result.manifest.lotlVersion).toBe(PIN.lotlVersion);
    expect(result.manifest.builtAt).toBe(PIN.builtAt);

    // Root must be a 0x-prefixed bytes32 (66 chars total).
    expect(result.manifest.root).toMatch(/^0x[0-9a-f]{64}$/);
    // Golden root for the Diia bundle under the filter + circuit-pinned
    // SPKI chunking. The orchestrator pins this value on Base Sepolia.
    expect(result.manifest.root).toBe(P7B_GOLDEN_ROOT);

    expect(result.manifest.leaves).toHaveLength(2);
    for (const leaf of result.manifest.leaves) {
      expect(leaf.merklePath).toHaveLength(16);
      expect(leaf.merklePathIndices).toHaveLength(16);
      expect(leaf.spkiCommit).toMatch(/^0x[0-9a-f]{64}$/);
      expect(leaf.territory).toBe("UA");
      // Both kept certs are the QTSP intermediates — no TSA/OCSP in subject.
      expect(leaf.subjectDn).not.toMatch(/^CN=TSA-/m);
      expect(leaf.subjectDn).not.toMatch(/^CN=OCSP-/m);
      expect(leaf.subjectDn).toMatch(/Qualified Trust Services Provider/);
    }
  });

  test("custom keep-all filter exposes every cert in the bundle", async () => {
    const result = await flattenFromP7b({
      in: p7bPath,
      filter: () => true,
      ...PIN,
    });
    expect(result.caCount).toBe(6);
    expect(result.manifest.leaves).toHaveLength(6);
  });

  test("two runs produce byte-identical manifests", async () => {
    const a = await flattenFromP7b({ in: p7bPath, ...PIN });
    const b = await flattenFromP7b({ in: p7bPath, ...PIN });
    expect(JSON.stringify(b.manifest)).toBe(JSON.stringify(a.manifest));
    expect(b.root).toBe(a.root);
  });
});

// Pinned bytes32 root for the filtered Diia bundle. Captured on first
// passing local run; the orchestrator pins this same value on Base Sepolia
// (PetitionRegistry.trustRoot). Any drift here means one of:
//   (a) the .p7b fixture changed — Diia rotated certs (re-pin),
//   (b) the cert filter changed — coordinate with circuit/contracts,
//   (c) the SPKI chunking or Merkle domain separators changed — must be
//       paired with the matching circuit update.
const P7B_GOLDEN_ROOT =
  "0x0dc4f2d069e7daddf6891d00dd2bb77880ad5dc65b3d39bd1d2781afb85e6f53";
