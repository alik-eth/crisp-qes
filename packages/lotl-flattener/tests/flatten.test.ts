import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { flatten, flattenToFile, type Manifest } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, "../fixtures");
const lotlPath = join(fixturesDir, "lotl-mini.xml");

// Pinned inputs — if any of these change the golden root below must change
// deliberately.
const PIN = {
  lotlVersion: "lotl-mini-2026-04-17",
  builtAt: "2026-04-17T00:00:00Z",
  treeDepth: 16,
} as const;

// Golden root for the lotl-mini fixture under PIN. Generated on first
// successful local run of `node dist/cli.js --in fixtures/lotl-mini.xml ...`.
// Any drift here means either:
//   (a) the @aztec/bb.js Pedersen impl changed under our feet — escalate,
//   (b) the SPKI-commit / Merkle node domain separators were touched — must
//       be paired with the Noir circuit + Solidity registry update,
//   (c) the fixture XML changed — re-pin deliberately.
const GOLDEN_ROOT = "0x1314962800e8b604128af20cc101b73f454f797cc23495e0dab6c3a0a9058ed0";

let outDir: string;
beforeEach(async () => {
  outDir = await mkdtemp(join(tmpdir(), "crisp-qes-flatten-"));
});
afterEach(async () => {
  await rm(outDir, { recursive: true, force: true });
});

describe("flatten — Pedersen-Merkle trust root", () => {
  test("produces stable root, leaf count, and manifest shape against lotl-mini", async () => {
    const result = await flatten({ in: lotlPath, ...PIN });

    expect(result.caCount).toBe(2);
    expect(result.manifest.version).toBe("1");
    expect(result.manifest.hash).toBe("pedersen-bn254");
    expect(result.manifest.treeDepth).toBe(16);
    expect(result.manifest.lotlVersion).toBe(PIN.lotlVersion);
    expect(result.manifest.builtAt).toBe(PIN.builtAt);

    // Root must be a 0x-prefixed bytes32 (66 chars).
    expect(result.manifest.root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.manifest.root).toBe(GOLDEN_ROOT);

    // Both leaves carry a full Merkle path of length treeDepth.
    expect(result.manifest.leaves).toHaveLength(2);
    for (const leaf of result.manifest.leaves) {
      expect(leaf.merklePath).toHaveLength(16);
      expect(leaf.merklePathIndices).toHaveLength(16);
      expect(leaf.spkiCommit).toMatch(/^0x[0-9a-f]{64}$/);
      expect(leaf.subjectDn).toBeTruthy();
    }

    // Territories preserved end-to-end from the fixture (EE first, PL second).
    expect(result.manifest.leaves.map((l) => l.territory)).toEqual(["EE", "PL"]);
  });

  test("two runs against the synthetic LOTL produce byte-identical manifests", async () => {
    const a = await flatten({ in: lotlPath, ...PIN });
    const b = await flatten({ in: lotlPath, ...PIN });
    expect(JSON.stringify(b.manifest)).toBe(JSON.stringify(a.manifest));
    expect(b.root).toBe(a.root);
  });

  test("flattenToFile writes manifest and round-trips", async () => {
    const outPath = join(outDir, "manifest.json");
    const result = await flattenToFile({ in: lotlPath, out: outPath, ...PIN });
    const onDisk = JSON.parse(await readFile(outPath, "utf8")) as Manifest;
    expect(onDisk.root).toBe(result.manifest.root);
    expect(onDisk.leaves).toHaveLength(2);
  });
});
