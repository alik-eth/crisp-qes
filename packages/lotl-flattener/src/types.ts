// CRISP-QES trust-root flattener types.
//
// The trust root pinned on PetitionRegistry is a Pedersen-Merkle commitment
// over the Diia trusted CA list (see docs/specs §2.1, §3). Per-leaf data is
// the canonical SPKI bytes of each trusted CA; the leaf commitment is
// pedersenHashBuffer(spkiDer). Internal Merkle nodes are pedersenHash([l,r]).

export interface ExtractedCA {
  certDer: Uint8Array;
  subjectDN: string;
  issuerDN: string;
  validFrom: number;
  validTo: number;
  territory: string;
  tspName?: string;
  serviceName?: string;
  serviceStatus: string;
  serviceValidFrom: number;
  serviceValidTo?: number;
  qualifiers: string[];
  qualificationElements: Array<{
    qualifiers: string[];
    criteria: {
      assert?: string;
      keyUsageBits: string[];
      policyIdentifiers: string[];
    };
  }>;
}

export interface FlattenedCA extends ExtractedCA {
  spkiCommit: bigint;
}

/**
 * Manifest schema emitted by the flattener.
 *
 * - `root` is the on-chain bytes32 that PetitionRegistry pins at deploy time.
 * - `leaves[i].merklePath` is the bottom-up sibling path that the SDK feeds
 *   into the Noir circuit alongside the leaf SPKI commitment.
 * - `hash` documents the hash family so consumers refuse to mix manifests
 *   from different protocol revisions.
 */
export interface Manifest {
  version: "1";
  hash: "pedersen-bn254";
  treeDepth: number;
  root: string; // 0x-prefixed bytes32
  builtAt: string;
  lotlVersion: string;
  leaves: ManifestLeaf[];
}

export interface ManifestLeaf {
  merkleIndex: number;
  subjectDn: string;
  spkiCommit: string; // 0x-prefixed bytes32
  merklePath: string[]; // bottom-up sibling path, each entry 0x-prefixed bytes32
  merklePathIndices: number[]; // 0 = sibling is right, 1 = sibling is left
  // Provenance / audit fields — not consumed by the circuit, kept so an
  // off-chain reviewer can re-derive each leaf from public ETSI TL data.
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
