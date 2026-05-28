// Manifest writer.
//
// Emits a single `manifest.json` (Manifest schema in ../types.ts). One file
// keeps the producer/consumer contract small: the registry deploy script
// reads `root`, the SDK witness builder reads `leaves[]` and indexes by
// subject DN to recover the Merkle path for a citizen's leaf.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { FlattenedCA, Manifest, ManifestLeaf } from "../types.js";
import { proveInclusion } from "../tree/merkle.js";

export interface WriterInput {
  root: bigint;
  treeDepth: number;
  layers: bigint[][];
  cas: FlattenedCA[];
  lotlVersion: string;
  builtAt: string;
}

export const toHex32 = (v: bigint): string => {
  if (v < 0n) throw new Error("bigint must be non-negative for hex serialization");
  let h = v.toString(16);
  // bytes32 — always pad to 64 hex chars so downstream Solidity consumers
  // can decode without manual padding.
  if (h.length > 64) {
    throw new Error(`bigint ${h} exceeds 32 bytes`);
  }
  h = h.padStart(64, "0");
  return `0x${h}`;
};

const toB64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");

export async function buildManifest(input: WriterInput): Promise<Manifest> {
  const leaves: ManifestLeaf[] = [];
  for (const [idx, ca] of input.cas.entries()) {
    const { path, indices } = await proveInclusion(input.layers, idx);
    leaves.push({
      merkleIndex: idx,
      subjectDn: ca.subjectDN,
      spkiCommit: toHex32(ca.spkiCommit),
      merklePath: path.map(toHex32),
      merklePathIndices: indices,
      issuerDn: ca.issuerDN,
      territory: ca.territory,
      ...(ca.tspName ? { tspName: ca.tspName } : {}),
      ...(ca.serviceName ? { serviceName: ca.serviceName } : {}),
      serviceStatus: ca.serviceStatus,
      serviceValidFrom: ca.serviceValidFrom,
      ...(ca.serviceValidTo ? { serviceValidTo: ca.serviceValidTo } : {}),
      validFrom: ca.validFrom,
      validTo: ca.validTo,
      qualifiers: ca.qualifiers,
      certDerB64: toB64(ca.certDer),
    });
  }
  return {
    version: "1",
    hash: "pedersen-bn254",
    treeDepth: input.treeDepth,
    root: toHex32(input.root),
    builtAt: input.builtAt,
    lotlVersion: input.lotlVersion,
    leaves,
  };
}

export async function writeManifest(input: WriterInput, outPath: string): Promise<Manifest> {
  const manifest = await buildManifest(input);
  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}
