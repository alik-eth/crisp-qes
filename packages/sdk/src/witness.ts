// Noir witness assembly for the CRISP-QES eligibility circuit (D-v2-fix).
//
// Mirrors the `fn main(...)` parameter declaration in
// `packages/circuit/src/main.nr`:
//
//   public:
//     petition_id, nullifier, trust_root,
//     leaf_pubkey_x_hi, leaf_pubkey_x_lo,
//     leaf_pubkey_y_hi, leaf_pubkey_y_lo,
//     intermediate_pubkey_x_hi, intermediate_pubkey_x_lo,
//     intermediate_pubkey_y_hi, intermediate_pubkey_y_lo,
//     leaf_tbs_sha256_hi, leaf_tbs_sha256_lo,
//     signed_attrs_sha256_hi, signed_attrs_sha256_lo
//
// The pubkey limb split (D-v2-fix) protects against P-256 coordinates
// that exceed the BN254 prime: a single Field public input would
// silently mod-reduce ~25% of pubkeys, breaking the contract-side
// ECDSA call. Each 128-bit limb is well inside the field range.
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
    leaf_pubkey_x_hi: FieldHex;
    leaf_pubkey_x_lo: FieldHex;
    leaf_pubkey_y_hi: FieldHex;
    leaf_pubkey_y_lo: FieldHex;
    intermediate_pubkey_x_hi: FieldHex;
    intermediate_pubkey_x_lo: FieldHex;
    intermediate_pubkey_y_hi: FieldHex;
    intermediate_pubkey_y_lo: FieldHex;
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

export interface IntermediateOverride {
    spkiDer: Uint8Array;
    pubkey: { x: bigint; y: bigint };
    pubkeyOffset: number;
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
    /**
     * Intermediate-cert source override. When the `.p7s` doesn't carry the
     * intermediate (`parsed.intermediateCertDer === null`), the caller
     * resolves the issuer via the public Diia `.p7b` bundle
     * (see `findIntermediate`) and passes the resulting SPKI / pubkey /
     * offset triple here. When omitted, the values come from `parsed.*`.
     */
    intermediate?: IntermediateOverride;
}

/** Precomputed public-input values exposed alongside the witness map. */
export interface WitnessPublicInputs {
    petitionId: bigint;
    nullifier: bigint;
    trustRoot: bigint;
    leafPubkeyXHi: bigint;
    leafPubkeyXLo: bigint;
    leafPubkeyYHi: bigint;
    leafPubkeyYLo: bigint;
    intermediatePubkeyXHi: bigint;
    intermediatePubkeyXLo: bigint;
    intermediatePubkeyYHi: bigint;
    intermediatePubkeyYLo: bigint;
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

    // The intermediate SPKI / pubkey / offset can come either from the
    // parsed .p7s (Diia normally bundles the issuer) or from the optional
    // `intermediate` override (when the .p7s only carried the leaf and the
    // caller resolved the issuer via the public .p7b bundle).
    const intermediateSpkiDer =
        args.intermediate?.spkiDer ?? parsed.intermediateSpkiDer;
    const intermediatePubkey =
        args.intermediate?.pubkey ?? parsed.intermediatePubkey;
    const intermediatePubkeyOffset =
        args.intermediate?.pubkeyOffset ?? parsed.intermediatePubkeyOffset;

    if (
        intermediateSpkiDer === null ||
        intermediatePubkey === null ||
        intermediatePubkeyOffset === null
    ) {
        throw new Error(
            "buildWitness: D-v2 requires an intermediate CA cert (none in .p7s and no `intermediate` override supplied)",
        );
    }

    requireFitsBn254("petitionId", petitionId);
    requireFitsBn254("trustRoot", trustRoot);
    // P-256 coordinates are 256-bit; the BN254 prime sits just below 2^254,
    // so we split each coordinate into 128-bit hi/lo limbs and range-check
    // both. `requireFitsU256` catches obviously bogus inputs early; the
    // limb split itself happens inside `splitU256`.
    requireFitsU256("pubkey.x", parsed.pubkey.x);
    requireFitsU256("pubkey.y", parsed.pubkey.y);
    requireFitsU256("intermediate.x", intermediatePubkey.x);
    requireFitsU256("intermediate.y", intermediatePubkey.y);
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
    if (intermediateSpkiDer.length > INTERMEDIATE_SPKI_MAX_BYTES) {
        throw new Error(
            `buildWitness: intermediateSpkiDer is ${intermediateSpkiDer.length} bytes; circuit cap is ${INTERMEDIATE_SPKI_MAX_BYTES}`,
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
        intermediatePubkeyOffset < 27 ||
        intermediatePubkeyOffset + 64 > intermediateSpkiDer.length
    ) {
        throw new Error(
            `buildWitness: intermediatePubkeyOffset out of range (offset=${intermediatePubkeyOffset}, len=${intermediateSpkiDer.length})`,
        );
    }

    const leafLimbs = splitPubkey(parsed.pubkey);
    const intermediateLimbs = splitPubkey(intermediatePubkey);

    const nullifier = await computeNullifier({
        pubkey: parsed.pubkey,
        petitionId,
    });
    const nullifierBig = BigInt(nullifier);

    const { hi: tbsHi, lo: tbsLo } = splitSha256(parsed.leafTbsSha256);
    const { hi: saHi, lo: saLo } = splitSha256(parsed.signedAttrsSha256);

    // Slice the 32-byte window directly out of the TBS rather than zero-padding
    // the ASN.1-decoded subject-serial value. The circuit binds
    // `subject_serial[i] == leaf_tbs_bytes[subject_serial_offset + i]` for ALL
    // 32 bytes; the actual serial is shorter (e.g. "TINUA-3627506575" is 16),
    // so zero-padding past the real bytes would break the binding because the
    // bytes that actually follow inside the TBS are the next ASN.1 element,
    // not zeros. The TINUA- prefix lives in bytes [0..6] regardless.
    const subjectSerial = parsed.leafTbsBytes.slice(
        parsed.subjectSerialOffset,
        parsed.subjectSerialOffset + SUBJECT_SERIAL_LEN,
    );
    const leafTbsBytes = padBytesRight(parsed.leafTbsBytes, LEAF_TBS_MAX_BYTES);
    const intermediateSpkiBytes = padBytesRight(
        intermediateSpkiDer,
        INTERMEDIATE_SPKI_MAX_BYTES,
    );
    const signedAttrsBytes = padBytesRight(parsed.signedAttrs, SIGNED_ATTRS_MAX_BYTES);

    const inputs: WitnessInputs = {
        petition_id: toFieldHex(petitionId),
        nullifier,
        trust_root: toFieldHex(trustRoot),
        leaf_pubkey_x_hi: toFieldHex(leafLimbs.xHi),
        leaf_pubkey_x_lo: toFieldHex(leafLimbs.xLo),
        leaf_pubkey_y_hi: toFieldHex(leafLimbs.yHi),
        leaf_pubkey_y_lo: toFieldHex(leafLimbs.yLo),
        intermediate_pubkey_x_hi: toFieldHex(intermediateLimbs.xHi),
        intermediate_pubkey_x_lo: toFieldHex(intermediateLimbs.xLo),
        intermediate_pubkey_y_hi: toFieldHex(intermediateLimbs.yHi),
        intermediate_pubkey_y_lo: toFieldHex(intermediateLimbs.yLo),
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
        intermediate_pubkey_offset: intermediatePubkeyOffset.toString(10),
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
            leafPubkeyXHi: leafLimbs.xHi,
            leafPubkeyXLo: leafLimbs.xLo,
            leafPubkeyYHi: leafLimbs.yHi,
            leafPubkeyYLo: leafLimbs.yLo,
            intermediatePubkeyXHi: intermediateLimbs.xHi,
            intermediatePubkeyXLo: intermediateLimbs.xLo,
            intermediatePubkeyYHi: intermediateLimbs.yHi,
            intermediatePubkeyYLo: intermediateLimbs.yLo,
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

const U128_LIMIT = 1n << 128n;
const U256_LIMIT = 1n << 256n;

/**
 * Split an unsigned 256-bit integer into 128-bit (hi, lo) limbs. The
 * pubkey coordinate split mirrors what the circuit does on the SPKI
 * byte buffer (BE-pack the high 16 bytes -> hi, low 16 bytes -> lo).
 */
export function splitU256(v: bigint): { hi: bigint; lo: bigint } {
    if (v < 0n || v >= U256_LIMIT) {
        throw new Error(`splitU256: ${v} not in [0, 2^256)`);
    }
    return { hi: v >> 128n, lo: v & (U128_LIMIT - 1n) };
}

/**
 * Split a P-256 affine pubkey into the four 128-bit limbs the circuit
 * publishes as slots [hi(x), lo(x), hi(y), lo(y)]. Used by both the
 * witness assembler (for the InputMap) and `computeNullifier` (for the
 * 6-element pedersen input tuple).
 */
export function splitPubkey(pubkey: { x: bigint; y: bigint }): {
    xHi: bigint;
    xLo: bigint;
    yHi: bigint;
    yLo: bigint;
} {
    const x = splitU256(pubkey.x);
    const y = splitU256(pubkey.y);
    return { xHi: x.hi, xLo: x.lo, yHi: y.hi, yLo: y.lo };
}

// BN254 scalar field modulus (the Grumpkin / BN254 base used by std::hash::pedersen_hash).
const BN254_R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

function requireFitsBn254(label: string, v: bigint): void {
    if (v < 0n || v >= BN254_R) {
        throw new Error(`buildWitness: ${label} = ${v} not in [0, BN254_R)`);
    }
}

function requireFitsU256(label: string, v: bigint): void {
    if (v < 0n || v >= U256_LIMIT) {
        throw new Error(`buildWitness: ${label} = ${v} not in [0, 2^256)`);
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
