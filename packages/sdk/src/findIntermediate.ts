// Match the .p7s's intermediate CA cert against the LOTL trust manifest.
//
// In D-v2 the on-chain `trustRoot` commits to Diia *intermediate* CA SPKIs.
// The flattener's manifest exposes one Pedersen Merkle leaf per intermediate,
// keyed by its `spkiCommit` (the 31-byte BE chunked Pedersen hash of the
// zero-padded 1024-byte SPKI DER). We recompute that commit for the
// intermediate cert pulled out of a .p7s and look it up in the manifest.
//
// If the .p7s doesn't carry an intermediate (`parsed.intermediateCertDer ===
// null`), or the intermediate isn't under any trusted CA in the current
// root, we return `null` — callers should surface a clear "not under any
// trusted Diia CA" to the user.
//
// The Pedersen primitive must match circuit + flattener byte-for-byte:
//   - chunk size 31 bytes (BE-packed into a BN254 Field)
//   - 33 full chunks + 1 trailing single-byte chunk
//   - pedersen_hash_with_separator(fields, hashIndex = SPKI_COMMIT_DOMAIN = 1)
// See `packages/circuit/src/spki.nr` and
// `packages/lotl-flattener/src/ca/spkiCommit.ts`.

import { BarretenbergSync, Fr } from "@aztec/bb.js";
import type { ParsedP7s } from "./p7s.js";

const SPKI_COMMIT_DOMAIN = 1;
const SPKI_MAX_BYTES = 1024;
const SPKI_CHUNK_BYTES = 31;
const SPKI_FULL_CHUNKS = 33;
const SPKI_NUM_CHUNKS = 34;

/** Manifest shape we depend on. Source-of-truth: lotl-flattener types.ts. */
export interface TrustManifestLeafLike {
    merkleIndex: number;
    subjectDn: string;
    spkiCommit: string; // 0x-prefixed bytes32
    merklePath: string[]; // 0x-prefixed bytes32, length = treeDepth
    merklePathIndices: number[]; // 0/1, length = treeDepth
    issuerDn?: string;
    tspName?: string;
    serviceName?: string;
    certDerB64?: string;
}

export interface TrustManifestLike {
    version: "1";
    hash: "pedersen-bn254";
    treeDepth: number;
    root: string;
    leaves: TrustManifestLeafLike[];
}

export interface FoundIntermediate {
    /** The manifest leaf matched to the .p7s's intermediate cert. */
    leaf: TrustManifestLeafLike;
    /** The intermediate cert DER (echo of `parsed.intermediateCertDer`). */
    intermediateCertDer: Uint8Array;
    /** The intermediate SPKI DER (echo of `parsed.intermediateSpkiDer`). */
    intermediateSpkiDer: Uint8Array;
    /** Pedersen commit of the intermediate SPKI (bigint). */
    intermediateSpkiCommit: bigint;
    /** Bottom-up sibling path, BN254 field-valued — ready for `buildWitness`. */
    merklePath: bigint[];
    /** Bottom-up index bits (0/1), ready for `buildWitness`. */
    merklePathIndices: number[];
}

/**
 * Compute the canonical SPKI Pedersen commit for an intermediate cert and
 * look it up in the trust manifest. Returns the matching leaf with its
 * Merkle inclusion proof if found, otherwise `null`.
 */
export async function findIntermediate(
    parsed: ParsedP7s,
    manifest: TrustManifestLike,
): Promise<FoundIntermediate | null> {
    if (
        parsed.intermediateCertDer === null ||
        parsed.intermediateSpkiDer === null
    ) {
        return null;
    }
    if (manifest.hash !== "pedersen-bn254" || manifest.version !== "1") {
        throw new Error(
            `findIntermediate: unsupported manifest version/hash (${manifest.version}/${manifest.hash})`,
        );
    }

    const commit = await spkiCommit(parsed.intermediateSpkiDer);
    const target = toHex32(commit);
    for (const leaf of manifest.leaves) {
        if (normaliseHex(leaf.spkiCommit) !== target) continue;
        if (leaf.merklePath.length !== manifest.treeDepth) {
            throw new Error(
                `findIntermediate: manifest leaf ${leaf.merkleIndex} merklePath length ${leaf.merklePath.length} != treeDepth ${manifest.treeDepth}`,
            );
        }
        if (leaf.merklePathIndices.length !== manifest.treeDepth) {
            throw new Error(
                `findIntermediate: manifest leaf ${leaf.merkleIndex} indices length ${leaf.merklePathIndices.length} != treeDepth ${manifest.treeDepth}`,
            );
        }
        return {
            leaf,
            intermediateCertDer: parsed.intermediateCertDer,
            intermediateSpkiDer: parsed.intermediateSpkiDer,
            intermediateSpkiCommit: commit,
            merklePath: leaf.merklePath.map((h) => BigInt(h)),
            merklePathIndices: leaf.merklePathIndices.slice(),
        };
    }
    return null;
}

/** Canonical SPKI commit — must mirror circuit + flattener byte-for-byte. */
export async function spkiCommit(spkiDer: Uint8Array): Promise<bigint> {
    if (spkiDer.length === 0) throw new Error("spkiCommit: empty SPKI");
    if (spkiDer.length > SPKI_MAX_BYTES) {
        throw new Error(
            `spkiCommit: SPKI length ${spkiDer.length} exceeds ${SPKI_MAX_BYTES}`,
        );
    }
    const padded = new Uint8Array(SPKI_MAX_BYTES);
    padded.set(spkiDer, 0);

    const fields = new Array<Fr>(SPKI_NUM_CHUNKS);
    for (let c = 0; c < SPKI_FULL_CHUNKS; c++) {
        const start = c * SPKI_CHUNK_BYTES;
        fields[c] = new Fr(packBE(padded.subarray(start, start + SPKI_CHUNK_BYTES)));
    }
    fields[SPKI_FULL_CHUNKS] = new Fr(BigInt(padded[SPKI_MAX_BYTES - 1]!));

    const api = await BarretenbergSync.initSingleton();
    const out = api.pedersenHash(fields, SPKI_COMMIT_DOMAIN);
    return BigInt(out.toString());
}

function packBE(chunk: Uint8Array): bigint {
    let acc = 0n;
    for (let i = 0; i < chunk.length; i++) acc = (acc << 8n) | BigInt(chunk[i]!);
    return acc;
}

function toHex32(v: bigint): string {
    return "0x" + v.toString(16).padStart(64, "0");
}

function normaliseHex(h: string): string {
    if (!h.startsWith("0x")) return ("0x" + h).toLowerCase();
    return h.toLowerCase();
}
