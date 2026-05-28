// Noir witness assembly for the CRISP-QES eligibility circuit (D-v2).
//
// Mirrors the `fn main(...)` parameter declaration in
// `packages/circuit/src/main.nr`:
//
//   public:
//     petition_id, nullifier, trust_root,
//     leaf_pubkey_x, leaf_pubkey_y,
//     intermediate_pubkey_x, intermediate_pubkey_y,
//     leaf_tbs_sha256_hi, leaf_tbs_sha256_lo,
//     signed_attrs_sha256_hi, signed_attrs_sha256_lo
//
//   private:
//     subject_serial: [u8; 32]
//     subject_serial_offset: u32
//     leaf_tbs_bytes: [u8; 2048]
//     leaf_tbs_len: u32
//     leaf_pubkey_offset: u32
//     intermediate_spki_bytes: [u8; 1024]
//     intermediate_pubkey_offset: u32
//     merkle_path: [Field; 16]
//     merkle_path_indices: [bool; 16]
//     signed_attrs_bytes: [u8; 2048]
//     signed_attrs_len: u32
//     message_digest_offset: u32
//     petition_text_hash: [u8; 32]
//
// All BN254 field values are emitted as `0x`-prefixed 32-byte hex (no
// implicit reduction; values must be < field modulus). Byte arrays are
// emitted as `number[]` with `0 <= x <= 255`.

import type { ParsedP7s } from "./p7s.js";
import { computeNullifier } from "./prove.js";

const MERKLE_DEPTH = 16;
const SUBJECT_SERIAL_LEN = 32;
const LEAF_TBS_MAX_BYTES = 2048;
const INTERMEDIATE_SPKI_MAX_BYTES = 1024;
const SIGNED_ATTRS_MAX_BYTES = 2048;
const PETITION_TEXT_HASH_LEN = 32;

/** Hex form (`0x` + 64 hex chars) of a BN254 field element. */
export type FieldHex = string;

export interface WitnessInputs {
    // ---- public ----
    petition_id: FieldHex;
    nullifier: FieldHex;
    trust_root: FieldHex;
    leaf_pubkey_x: FieldHex;
    leaf_pubkey_y: FieldHex;
    intermediate_pubkey_x: FieldHex;
    intermediate_pubkey_y: FieldHex;
    leaf_tbs_sha256_hi: FieldHex;
    leaf_tbs_sha256_lo: FieldHex;
    signed_attrs_sha256_hi: FieldHex;
    signed_attrs_sha256_lo: FieldHex;
    // ---- private ----
    subject_serial: number[];
    subject_serial_offset: string;
    leaf_tbs_bytes: number[];
    leaf_tbs_len: string;
    leaf_pubkey_offset: string;
    intermediate_spki_bytes: number[];
    intermediate_pubkey_offset: string;
    merkle_path: FieldHex[];
    merkle_path_indices: boolean[];
    signed_attrs_bytes: number[];
    signed_attrs_len: string;
    message_digest_offset: string;
    petition_text_hash: number[];
}

export interface BuildWitnessArgs {
    parsed: ParsedP7s;
    petitionId: bigint;
    /** 32-byte SHA-256 of the petition's `fullText` (mirrors `Petition.textHash`). */
    petitionTextHash: Uint8Array;
    /** BN254 field element (`< 2^254`) — value of `PetitionRegistry.trustRoot`. */
    trustRoot: bigint;
    /**
     * Bottom-up sibling path from the LOTL manifest's `ManifestLeaf`, exactly
     * `MERKLE_DEPTH` entries, BN254 field-valued.
     */
    merklePath: bigint[];
    /**
     * Bottom-up `merklePathIndices` from the manifest leaf, exactly
     * `MERKLE_DEPTH` bits. The flattener exposes them as `number[]` of 0/1;
     * we accept that and coerce to booleans for the Noir circuit.
     */
    merklePathIndices: number[];
}

/** Precomputed public-input values exposed alongside the witness map. */
export interface WitnessPublicInputs {
    petitionId: bigint;
    nullifier: bigint;
    trustRoot: bigint;
    leafPubkeyX: bigint;
    leafPubkeyY: bigint;
    intermediatePubkeyX: bigint;
    intermediatePubkeyY: bigint;
    leafTbsSha256Hi: bigint;
    leafTbsSha256Lo: bigint;
    signedAttrsSha256Hi: bigint;
    signedAttrsSha256Lo: bigint;
}

export interface BuildWitnessResult {
    inputs: WitnessInputs;
    publics: WitnessPublicInputs;
}

/**
 * Assemble the Noir witness for the v2 eligibility proof. Throws synchronously
 * on shape violations (wrong array lengths, out-of-range field values,
 * missing intermediate cert) so a buggy caller fails before the WASM prover
 * is spun up.
 */
export async function buildWitness(args: BuildWitnessArgs): Promise<BuildWitnessResult> {
    const {
        parsed,
        petitionId,
        petitionTextHash,
        trustRoot,
        merklePath,
        merklePathIndices,
    } = args;

    if (
        parsed.intermediateSpkiDer === null ||
        parsed.intermediatePubkey === null ||
        parsed.intermediatePubkeyOffset === null
    ) {
        throw new Error(
            "buildWitness: D-v2 requires the intermediate CA cert in the .p7s SignedData (none found)",
        );
    }

    requireFitsBn254("petitionId", petitionId);
    requireFitsBn254("trustRoot", trustRoot);
    requireFitsBn254("pubkey.x", parsed.pubkey.x);
    requireFitsBn254("pubkey.y", parsed.pubkey.y);
    requireFitsBn254("intermediate.x", parsed.intermediatePubkey.x);
    requireFitsBn254("intermediate.y", parsed.intermediatePubkey.y);
    requireByteLen("petitionTextHash", petitionTextHash, PETITION_TEXT_HASH_LEN);
    requireLen("merklePath", merklePath, MERKLE_DEPTH);
    requireLen("merklePathIndices", merklePathIndices, MERKLE_DEPTH);

    if (parsed.signedAttrs.length > SIGNED_ATTRS_MAX_BYTES) {
        throw new Error(
            `buildWitness: signedAttrs is ${parsed.signedAttrs.length} bytes; circuit cap is ${SIGNED_ATTRS_MAX_BYTES}`,
        );
    }
    if (parsed.leafTbsBytes.length > LEAF_TBS_MAX_BYTES) {
        throw new Error(
            `buildWitness: leafTbsBytes is ${parsed.leafTbsBytes.length} bytes; circuit cap is ${LEAF_TBS_MAX_BYTES}`,
        );
    }
    if (parsed.intermediateSpkiDer.length > INTERMEDIATE_SPKI_MAX_BYTES) {
        throw new Error(
            `buildWitness: intermediateSpkiDer is ${parsed.intermediateSpkiDer.length} bytes; circuit cap is ${INTERMEDIATE_SPKI_MAX_BYTES}`,
        );
    }
    if (parsed.messageDigestOffset + 32 > parsed.signedAttrs.length) {
        throw new Error(
            `buildWitness: messageDigestOffset (${parsed.messageDigestOffset}) + 32 exceeds signedAttrs length (${parsed.signedAttrs.length})`,
        );
    }
    if (parsed.subjectSerialOffset + SUBJECT_SERIAL_LEN > parsed.leafTbsBytes.length) {
        throw new Error(
            `buildWitness: subjectSerialOffset (${parsed.subjectSerialOffset}) + 32 exceeds leafTbsBytes length (${parsed.leafTbsBytes.length})`,
        );
    }
    if (
        parsed.leafPubkeyOffset < 27 ||
        parsed.leafPubkeyOffset + 64 > parsed.leafTbsBytes.length
    ) {
        throw new Error(
            `buildWitness: leafPubkeyOffset out of range (offset=${parsed.leafPubkeyOffset}, len=${parsed.leafTbsBytes.length})`,
        );
    }
    if (
        parsed.intermediatePubkeyOffset < 27 ||
        parsed.intermediatePubkeyOffset + 64 > parsed.intermediateSpkiDer.length
    ) {
        throw new Error(
            `buildWitness: intermediatePubkeyOffset out of range (offset=${parsed.intermediatePubkeyOffset}, len=${parsed.intermediateSpkiDer.length})`,
        );
    }

    const nullifier = await computeNullifier({
        pubkey: parsed.pubkey,
        petitionId,
    });
    const nullifierBig = BigInt(nullifier);

    const { hi: tbsHi, lo: tbsLo } = splitSha256(parsed.leafTbsSha256);
    const { hi: saHi, lo: saLo } = splitSha256(parsed.signedAttrsSha256);

    const subjectSerial = padBytesRight(parsed.subjectSerial, SUBJECT_SERIAL_LEN);
    const leafTbsBytes = padBytesRight(parsed.leafTbsBytes, LEAF_TBS_MAX_BYTES);
    const intermediateSpkiBytes = padBytesRight(
        parsed.intermediateSpkiDer,
        INTERMEDIATE_SPKI_MAX_BYTES,
    );
    const signedAttrsBytes = padBytesRight(parsed.signedAttrs, SIGNED_ATTRS_MAX_BYTES);

    const inputs: WitnessInputs = {
        petition_id: toFieldHex(petitionId),
        nullifier,
        trust_root: toFieldHex(trustRoot),
        leaf_pubkey_x: toFieldHex(parsed.pubkey.x),
        leaf_pubkey_y: toFieldHex(parsed.pubkey.y),
        intermediate_pubkey_x: toFieldHex(parsed.intermediatePubkey.x),
        intermediate_pubkey_y: toFieldHex(parsed.intermediatePubkey.y),
        leaf_tbs_sha256_hi: toFieldHex(tbsHi),
        leaf_tbs_sha256_lo: toFieldHex(tbsLo),
        signed_attrs_sha256_hi: toFieldHex(saHi),
        signed_attrs_sha256_lo: toFieldHex(saLo),
        subject_serial: Array.from(subjectSerial),
        subject_serial_offset: parsed.subjectSerialOffset.toString(10),
        leaf_tbs_bytes: Array.from(leafTbsBytes),
        leaf_tbs_len: parsed.leafTbsBytes.length.toString(10),
        leaf_pubkey_offset: parsed.leafPubkeyOffset.toString(10),
        intermediate_spki_bytes: Array.from(intermediateSpkiBytes),
        intermediate_pubkey_offset: parsed.intermediatePubkeyOffset.toString(10),
        merkle_path: merklePath.map(toFieldHex),
        merkle_path_indices: merklePathIndices.map(coerceBit),
        signed_attrs_bytes: Array.from(signedAttrsBytes),
        signed_attrs_len: parsed.signedAttrs.length.toString(10),
        message_digest_offset: parsed.messageDigestOffset.toString(10),
        petition_text_hash: Array.from(petitionTextHash),
    };

    return {
        inputs,
        publics: {
            petitionId,
            nullifier: nullifierBig,
            trustRoot,
            leafPubkeyX: parsed.pubkey.x,
            leafPubkeyY: parsed.pubkey.y,
            intermediatePubkeyX: parsed.intermediatePubkey.x,
            intermediatePubkeyY: parsed.intermediatePubkey.y,
            leafTbsSha256Hi: tbsHi,
            leafTbsSha256Lo: tbsLo,
            signedAttrsSha256Hi: saHi,
            signedAttrsSha256Lo: saLo,
        },
    };
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/**
 * Split a 32-byte SHA-256 output into the (hi, lo) 128-bit limbs the circuit
 * declares for each SHA-256 public input. Each limb is the big-endian
 * unsigned integer encoding of the corresponding 16-byte half, strictly
 * less than 2^128 and therefore safely inside the BN254 field range.
 */
export function splitSha256(digest: Uint8Array): { hi: bigint; lo: bigint } {
    if (digest.length !== 32) {
        throw new Error(`splitSha256: expected 32 bytes, got ${digest.length}`);
    }
    let hi = 0n;
    let lo = 0n;
    for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(digest[i]!);
    for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(digest[i]!);
    return { hi, lo };
}

// BN254 scalar field modulus (the Grumpkin / BN254 base used by std::hash::pedersen_hash).
const BN254_R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

function requireFitsBn254(label: string, v: bigint): void {
    if (v < 0n || v >= BN254_R) {
        throw new Error(`buildWitness: ${label} = ${v} not in [0, BN254_R)`);
    }
}

function requireByteLen(label: string, b: Uint8Array, n: number): void {
    if (b.length !== n) {
        throw new Error(`buildWitness: ${label} must be ${n} bytes (got ${b.length})`);
    }
}

function requireLen<T>(label: string, a: readonly T[], n: number): void {
    if (a.length !== n) {
        throw new Error(`buildWitness: ${label} must have ${n} entries (got ${a.length})`);
    }
}

function padBytesRight(src: Uint8Array, totalLen: number): Uint8Array {
    if (src.length > totalLen) {
        throw new Error(
            `padBytesRight: source is ${src.length} bytes; target ${totalLen}`,
        );
    }
    const out = new Uint8Array(totalLen);
    out.set(src, 0);
    return out;
}

function coerceBit(v: number): boolean {
    if (v === 0) return false;
    if (v === 1) return true;
    throw new Error(`buildWitness: merklePathIndices entries must be 0 or 1 (got ${v})`);
}

/** Render a BN254 field element as a 0x-prefixed 64-char hex string. */
export function toFieldHex(v: bigint): FieldHex {
    requireFitsBn254("Field", v);
    return `0x${v.toString(16).padStart(64, "0")}`;
}
