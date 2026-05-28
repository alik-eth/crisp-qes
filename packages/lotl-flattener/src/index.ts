// @crisp-qes/lotl-flattener — public entry.
//
// Produces the Pedersen-Merkle trust root that PetitionRegistry pins at
// deploy time, plus a per-leaf manifest the SDK uses to build Noir witnesses
// (CRISP-QES spec §2.1, §3).

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

import { extractCAs } from "./ca/extract.js";
import { extractSpki } from "./ca/extractSpki.js";
import { spkiCommit } from "./ca/spkiCommit.js";
import { parseLotl, type LotlPointer } from "./fetch/lotl.js";
import { parseMsTl } from "./fetch/msTl.js";
import { filterServicesByCountry } from "./filter/countryFilter.js";
import { filterQes } from "./filter/qesServices.js";
import { buildTree } from "./tree/merkle.js";
import { buildManifest } from "./output/writer.js";
import type { FlattenedCA, Manifest } from "./types.js";

export * from "./types.js";
export { spkiCommit, SPKI_COMMIT_DOMAIN, MAX_SPKI_BYTES } from "./ca/spkiCommit.js";
export { MERKLE_NODE_DOMAIN, buildTree, proveInclusion, zeroHashes } from "./tree/merkle.js";
export { pedersenHashFields, pedersenHashBuffer } from "./ca/pedersen.js";

/** Tree depth used by PetitionRegistry. 16 = 65536 trusted CAs of headroom. */
export const TREE_DEPTH = 16;

export type MsTlLoader = (location: string, pointer: LotlPointer) => Promise<string>;

export interface FlattenOpts {
  /** Path to LOTL XML on disk. */
  in: string;
  /** Optional explicit MS-TL loader; defaults to local-file relative to LOTL. */
  msTlLoader?: MsTlLoader;
  /** Optional ISO-3166 alpha-2 filter (e.g. "UA" for Diia-only). */
  filterCountry?: string;
  /** Pinned tree depth. */
  treeDepth?: number;
  /** Manifest provenance string. */
  lotlVersion?: string;
  /** Manifest provenance string. */
  builtAt?: string;
}

export interface FlattenResult {
  root: bigint;
  caCount: number;
  manifest: Manifest;
}

const defaultLocalLoader = (lotlPath: string): MsTlLoader => {
  const baseDir = dirname(resolve(lotlPath));
  return async (location: string): Promise<string> => {
    const target = isAbsolute(location) ? location : resolve(baseDir, location);
    return readFile(target, "utf8");
  };
};

/**
 * Flatten a LOTL bundle into a Pedersen-Merkle trust root + manifest.
 *
 * The implementation is deliberately offline: no HTTP fetches, no XMLDSig
 * verification. Treat the inputs as trusted-by-construction. Live LOTL and
 * signature verification are out of scope for the CRISP-QES MVP — pin a
 * snapshot, verify it out-of-band, then feed it here.
 */
export async function flatten(opts: FlattenOpts): Promise<FlattenResult> {
  const lotlXml = await readFile(opts.in, "utf8");
  const pointers = parseLotl(lotlXml);
  const loader = opts.msTlLoader ?? defaultLocalLoader(opts.in);
  const treeDepth = opts.treeDepth ?? TREE_DEPTH;

  const services = [];
  for (const p of pointers) {
    let rawXml: string;
    try {
      rawXml = await loader(p.location, p);
    } catch (cause) {
      throw new Error(`MS TL ${p.territory} load failed for ${p.location}`, { cause });
    }
    services.push(...parseMsTl(rawXml));
  }
  const qes = filterQes(services);
  const sliced = opts.filterCountry ? filterServicesByCountry(qes, opts.filterCountry) : qes;
  const extracted = extractCAs(sliced);

  const cas: FlattenedCA[] = [];
  const leaves: bigint[] = [];
  for (const e of extracted) {
    const spki = extractSpki(e.certDer);
    const commit = await spkiCommit(spki);
    leaves.push(commit);
    cas.push({ ...e, spkiCommit: commit });
  }

  const { root, layers } = await buildTree(leaves, treeDepth);
  const manifest = await buildManifest({
    root,
    treeDepth,
    layers,
    cas,
    lotlVersion: opts.lotlVersion ?? "unknown",
    builtAt: opts.builtAt ?? new Date().toISOString(),
  });

  return { root, caCount: cas.length, manifest };
}

export interface FlattenToFileOpts extends FlattenOpts {
  /** Path to manifest.json to write. */
  out: string;
}

export async function flattenToFile(opts: FlattenToFileOpts): Promise<FlattenResult> {
  const result = await flatten(opts);
  await mkdir(dirname(resolve(opts.out)), { recursive: true });
  await writeFile(opts.out, `${JSON.stringify(result.manifest, null, 2)}\n`);
  return result;
}
