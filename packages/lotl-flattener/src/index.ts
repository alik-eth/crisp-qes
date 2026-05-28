// @crisp-qes/lotl-flattener — public entry.
//
// Produces the Pedersen-Merkle trust root that PetitionRegistry pins at
// deploy time, plus a per-leaf manifest the SDK uses to build Noir witnesses
// (CRISP-QES spec §2.1, §3).

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

import { X509Certificate } from "node:crypto";

import { extractCAs } from "./ca/extract.js";
import { extractSpki } from "./ca/extractSpki.js";
import { spkiCommit } from "./ca/spkiCommit.js";
import { parseLotl, type LotlPointer } from "./fetch/lotl.js";
import { parseMsTl } from "./fetch/msTl.js";
import { parseP7b } from "./fetch/p7b.js";
import { filterServicesByCountry } from "./filter/countryFilter.js";
import { filterQes } from "./filter/qesServices.js";
import { buildTree } from "./tree/merkle.js";
import { buildManifest } from "./output/writer.js";
import type { FlattenedCA, Manifest } from "./types.js";

export * from "./types.js";
export { spkiCommit, SPKI_COMMIT_DOMAIN, MAX_SPKI_BYTES } from "./ca/spkiCommit.js";
export { MERKLE_NODE_DOMAIN, buildTree, proveInclusion, zeroHashes } from "./tree/merkle.js";
export { pedersenHashFields, pedersenHashBuffer } from "./ca/pedersen.js";
export { parseP7b } from "./fetch/p7b.js";

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

// ---------------------------------------------------------------------------
// `.p7b` bundle ingestion path
// ---------------------------------------------------------------------------
//
// Diia publishes its trusted-CA bundle as a CMS-SignedData `.p7b` blob
// (ca.diia.gov.ua/uploads/certificates/diia_ecdsa.p7b). For the MVP we ingest
// it directly — no LOTL XML in the loop — and emit the same Pedersen-Merkle
// manifest shape so PetitionRegistry and the SDK can consume it unchanged.

/**
 * Predicate over a parsed cert. Return `true` to keep a cert as a Merkle
 * leaf, `false` to drop it.
 *
 * `subjectDn` is the multi-line DN string `node:crypto.X509Certificate.subject`
 * returns (`"O=...\nOU=...\nCN=..."`), so DN-component matching can use
 * line-anchored regexes like `/^CN=TSA-/m`.
 */
export type P7bCertFilter = (info: {
  certDer: Uint8Array;
  subjectDn: string;
  issuerDn: string;
}) => boolean;

/**
 * Default filter for the Diia `.p7b` bundle: keep the qualified-issuer
 * certs (whose CN matches `"DIIA". Qualified Trust Services Provider`) and
 * drop the TSA timestamping and OCSP-responder service certs. Those service
 * certs sign their own protocol responses and never sign citizen QES certs,
 * so committing them would expand the trust set without any benefit.
 */
export const diiaP7bFilter: P7bCertFilter = ({ subjectDn }) => {
  if (/^CN=TSA-/m.test(subjectDn)) return false;
  if (/^CN=OCSP-/m.test(subjectDn)) return false;
  return true;
};

export interface FlattenFromP7bOpts {
  /**
   * Either a binary DER `.p7b` buffer, or a filesystem path read via
   * `node:fs`. Exactly one must be set.
   */
  in?: string;
  bytes?: Uint8Array;
  /** Cert filter; defaults to `diiaP7bFilter`. */
  filter?: P7bCertFilter;
  /** Pinned tree depth. Defaults to {@link TREE_DEPTH}. */
  treeDepth?: number;
  /** Provenance label written into the manifest (`Manifest.lotlVersion`). */
  lotlVersion?: string;
  /** Provenance timestamp; defaults to `new Date().toISOString()`. */
  builtAt?: string;
  /**
   * Territory string stamped onto every leaf. Diia is UA-only; the field
   * is kept for manifest-schema parity with the LOTL path.
   */
  territory?: string;
  /** Optional TSP / service-name labels stamped onto every leaf. */
  tspName?: string;
  serviceName?: string;
}

/**
 * Flatten a Diia (or any single-issuer) `.p7b` bundle into the same
 * Pedersen-Merkle manifest the LOTL path emits. The leaves array preserves
 * the bundle's DER order so the Merkle root is stable across runs over the
 * same input.
 */
export async function flattenFromP7b(opts: FlattenFromP7bOpts): Promise<FlattenResult> {
  if ((opts.in === undefined) === (opts.bytes === undefined)) {
    throw new Error("flattenFromP7b: provide exactly one of { in, bytes }");
  }
  const der = opts.bytes ?? new Uint8Array(await readFile(opts.in!));
  const treeDepth = opts.treeDepth ?? TREE_DEPTH;
  const filter = opts.filter ?? diiaP7bFilter;
  const territory = opts.territory ?? "UA";

  const certs = parseP7b(der);
  const cas: FlattenedCA[] = [];
  const leaves: bigint[] = [];

  for (const certDer of certs) {
    const parsed = new X509Certificate(Buffer.from(certDer));
    const subjectDn = parsed.subject;
    const issuerDn = parsed.issuer;
    if (!filter({ certDer, subjectDn, issuerDn })) continue;

    const spki = extractSpki(certDer);
    const commit = await spkiCommit(spki);
    leaves.push(commit);
    cas.push({
      certDer,
      subjectDN: subjectDn,
      issuerDN: issuerDn,
      validFrom: Math.floor(Date.parse(parsed.validFrom) / 1000),
      validTo: Math.floor(Date.parse(parsed.validTo) / 1000),
      territory,
      ...(opts.tspName ? { tspName: opts.tspName } : {}),
      ...(opts.serviceName ? { serviceName: opts.serviceName } : {}),
      // The `.p7b` bundle has no ETSI service-status semantics; pin a
      // "granted" placeholder so the manifest schema is consistent with the
      // LOTL path. Auditors should cross-check against the published bundle.
      serviceStatus: "p7b-bundle",
      serviceValidFrom: 0,
      qualifiers: [],
      qualificationElements: [],
      spkiCommit: commit,
    });
  }

  const { root, layers } = await buildTree(leaves, treeDepth);
  const manifest = await buildManifest({
    root,
    treeDepth,
    layers,
    cas,
    lotlVersion: opts.lotlVersion ?? "diia-p7b",
    builtAt: opts.builtAt ?? new Date().toISOString(),
  });
  return { root, caCount: cas.length, manifest };
}

export interface FlattenFromP7bToFileOpts extends FlattenFromP7bOpts {
  /** Path to manifest.json to write. */
  out: string;
}

export async function flattenFromP7bToFile(
  opts: FlattenFromP7bToFileOpts,
): Promise<FlattenResult> {
  const result = await flattenFromP7b(opts);
  await mkdir(dirname(resolve(opts.out)), { recursive: true });
  await writeFile(opts.out, `${JSON.stringify(result.manifest, null, 2)}\n`);
  return result;
}
