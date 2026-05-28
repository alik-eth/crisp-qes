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

import { BarretenbergSync } from "@aztec/bb.js";
import type { ParsedP7s } from "./p7s.js";
import { findIssuerInBundle, parseP7bBundle } from "./bundle.js";

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
    /** The manifest leaf matched to the intermediate cert. */
    leaf: TrustManifestLeafLike;
    /** The intermediate cert DER — either from the .p7s or the fallback bundle. */
    intermediateCertDer: Uint8Array;
    /** The intermediate SPKI DER (91 bytes for P-256). */
    intermediateSpkiDer: Uint8Array;
    /** Intermediate's P-256 pubkey (x, y). */
    intermediatePubkey: { x: bigint; y: bigint };
    /** Byte offset within `intermediateSpkiDer` where X[0] sits (27 by construction). */
    intermediatePubkeyOffset: number;
    /** Pedersen commit of the intermediate SPKI (bigint). */
    intermediateSpkiCommit: bigint;
    /** Bottom-up sibling path, BN254 field-valued — ready for `buildWitness`. */
    merklePath: bigint[];
    /** Bottom-up index bits (0/1), ready for `buildWitness`. */
    merklePathIndices: number[];
    /** Where the intermediate cert came from. */
    source: "p7s" | "bundle";
}

export interface FindIntermediateOpts {
    /**
     * Public Diia `.p7b` bundle bytes. When the .p7s carries only the leaf
     * (`parsed.intermediateCertDer === null`), the lookup falls back to
     * matching `leafCertDer.AKI` against bundle certs' SKIs.
     */
    bundleP7b?: Uint8Array;
}

/**
 * Compute the canonical SPKI Pedersen commit for an intermediate cert and
 * look it up in the trust manifest. Returns the matching leaf with its
 * Merkle inclusion proof if found, otherwise `null`.
 */
export async function findIntermediate(
    parsed: ParsedP7s,
    manifest: TrustManifestLike,
    opts: FindIntermediateOpts = {},
): Promise<FoundIntermediate | null> {
    if (manifest.hash !== "pedersen-bn254" || manifest.version !== "1") {
        throw new Error(
            `findIntermediate: unsupported manifest version/hash (${manifest.version}/${manifest.hash})`,
        );
    }

    let certDer: Uint8Array;
    let spkiDer: Uint8Array;
    let pubkey: { x: bigint; y: bigint };
    let pubkeyOffset: number;
    let source: "p7s" | "bundle";

    if (
        parsed.intermediateCertDer !== null &&
        parsed.intermediateSpkiDer !== null &&
        parsed.intermediatePubkey !== null &&
        parsed.intermediatePubkeyOffset !== null
    ) {
        certDer = parsed.intermediateCertDer;
        spkiDer = parsed.intermediateSpkiDer;
        pubkey = parsed.intermediatePubkey;
        pubkeyOffset = parsed.intermediatePubkeyOffset;
        source = "p7s";
    } else {
        // Fall back to the Diia `.p7b` bundle: resolve the leaf's AKI to a
        // bundle cert's SKI. Caller must supply the bundle bytes; without
        // them the chain-verify witness cannot be assembled.
        if (!opts.bundleP7b) {
            return null;
        }
        const bundle = parseP7bBundle(opts.bundleP7b);
        const issuer = findIssuerInBundle(parsed.leafCertDer, bundle);
        if (!issuer) return null;
        certDer = issuer.certDer;
        spkiDer = issuer.spkiDer;
        pubkey = issuer.pubkey;
        pubkeyOffset = issuer.pubkeyOffset;
        source = "bundle";
    }

    const commit = await spkiCommit(spkiDer);
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
            intermediateCertDer: certDer,
            intermediateSpkiDer: spkiDer,
            intermediatePubkey: pubkey,
            intermediatePubkeyOffset: pubkeyOffset,
            intermediateSpkiCommit: commit,
            merklePath: leaf.merklePath.map((h) => BigInt(h)),
            merklePathIndices: leaf.merklePathIndices.slice(),
            source,
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

    // bb.js 4.x: each Field input is a 32-byte big-endian Uint8Array.
    // Chunk inputs are <= 31 bytes wide so the leading byte stays zero —
    // each chunk value is strictly < 2^248, safely inside the BN254 prime.
    const inputs = new Array<Uint8Array>(SPKI_NUM_CHUNKS);
    for (let c = 0; c < SPKI_FULL_CHUNKS; c++) {
        const start = c * SPKI_CHUNK_BYTES;
        const buf = new Uint8Array(32);
        buf.set(padded.subarray(start, start + SPKI_CHUNK_BYTES), 1);
        inputs[c] = buf;
    }
    const tail = new Uint8Array(32);
    tail[31] = padded[SPKI_MAX_BYTES - 1]!;
    inputs[SPKI_FULL_CHUNKS] = tail;

    const api = await BarretenbergSync.initSingleton();
    const { hash } = api.pedersenHash({ inputs, hashIndex: SPKI_COMMIT_DOMAIN });
    return bytesBEToBigInt(hash);
}

function bytesBEToBigInt(b: Uint8Array): bigint {
    let acc = 0n;
    for (let i = 0; i < b.length; i++) acc = (acc << 8n) | BigInt(b[i]!);
    return acc;
}

function toHex32(v: bigint): string {
    return "0x" + v.toString(16).padStart(64, "0");
}

function normaliseHex(h: string): string {
    if (!h.startsWith("0x")) return ("0x" + h).toLowerCase();
    return h.toLowerCase();
}
