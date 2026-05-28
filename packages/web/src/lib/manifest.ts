// Load the lotl-flattener manifest and find the leaf matching a given SPKI
// commit. The manifest schema mirrors
// packages/lotl-flattener/src/types.ts (Manifest).

import { config } from "../config";

export interface ManifestLeaf {
    merkleIndex: number;
    subjectDn: string;
    spkiCommit: string;
    merklePath: string[];
    merklePathIndices: number[];
    issuerDn: string;
    territory: string;
    tspName?: string;
    serviceName?: string;
    serviceStatus: string;
    serviceValidFrom: number;
    serviceValidTo?: number;
    validFrom: number;
    validTo: number;
    qualifiers: string[];
    certDerB64: string;
}

export interface TrustManifest {
    version: "1";
    hash: "pedersen-bn254";
    treeDepth: number;
    root: string;
    builtAt: string;
    lotlVersion: string;
    leaves: ManifestLeaf[];
}

let cache: Promise<TrustManifest> | null = null;

export function loadTrustManifest(): Promise<TrustManifest> {
    if (cache) return cache;
    cache = fetch(config.trustManifestUrl, { credentials: "omit" })
        .then(async (r) => {
            if (!r.ok) {
                throw new Error(`trust manifest fetch: HTTP ${r.status}`);
            }
            const m = (await r.json()) as TrustManifest;
            if (m.hash !== "pedersen-bn254" || m.version !== "1") {
                throw new Error(`trust manifest: unsupported version/hash`);
            }
            return m;
        })
        .catch((err) => {
            cache = null;
            throw err;
        });
    return cache;
}

export function findLeafByCommit(
    manifest: TrustManifest,
    commit: bigint,
): ManifestLeaf | null {
    const target = "0x" + commit.toString(16).padStart(64, "0");
    for (const leaf of manifest.leaves) {
        if (normaliseHex(leaf.spkiCommit) === target) return leaf;
    }
    return null;
}

function normaliseHex(h: string): string {
    if (!h.startsWith("0x")) return ("0x" + h).toLowerCase();
    return h.toLowerCase();
}
