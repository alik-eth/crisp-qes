// CAdES (.p7s) parser for CRISP-QES.
//
// Ported from identityescroworg's `packages/circuits/src/parse-p7s.ts` and
// reshaped for our Noir + RIP-7212 architecture:
//
//   * Signed attributes are still re-tagged from `[0] IMPLICIT` (0xA0) to
//     `SET` (0x31) — the hash-input form — but we now also return the raw
//     `sha256(signedAttrs)` so the contract can feed it straight to the
//     P-256 precompile (`0x0000…0100`) as `msg_hash`.
//   * Leaf-cert pubkey is extracted as P-256 affine (x, y) bigints, because
//     ECDSA verification happens on chain, not in the circuit.
//   * The signerInfo.signature OCTET STRING is parsed as a DER
//     ECDSA-Sig-Value (`SEQUENCE { r INTEGER, s INTEGER }`) and returned
//     as (r, s) bigints for calldata.
//   * Leaf-vs-intermediate disambiguation now uses the SignerInfo's SID
//     (issuerAndSerialNumber or subjectKeyIdentifier) instead of a "first
//     ETSI-prefixed cert wins" heuristic, which matches the precompile-
//     contract's notion of "the cert that actually signed this CMS".

import { createHash } from "node:crypto";
import { fromBER, Integer, OctetString, Sequence } from "asn1js";
import {
    Certificate,
    ContentInfo,
    IssuerAndSerialNumber,
    SignedData,
    SignerInfo,
} from "pkijs";
import { readDerLength, indexOf, bytesEqAt } from "./asn1.js";
import { extractP256Pubkey, extractSki, extractSubjectSerial } from "./leaf-cert.js";

/**
 * Canonical 27-byte prefix that opens every well-formed ECDSA-P-256
 * SubjectPublicKeyInfo. The circuit asserts these bytes immediately before
 * the X[0] byte of the (X,Y) point — so the SDK must locate the same offset.
 *
 *   30 59                       SEQUENCE 89
 *     30 13                     SEQUENCE 19 (AlgorithmIdentifier)
 *       06 07 2a 86 48 ce 3d 02 01      OID id-ecPublicKey
 *       06 08 2a 86 48 ce 3d 03 01 07   OID secp256r1
 *     03 42 00 04               BIT STRING 66, 0 unused bits, uncompressed point
 *   -- then X[32] || Y[32]
 */
const P256_SPKI_PREFIX = new Uint8Array([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
]);
const P256_SPKI_PREFIX_LEN = P256_SPKI_PREFIX.length;

const MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
const SIGNING_TIME_OID = "1.2.840.113549.1.9.5";

export interface ParsedP7s {
    /** Raw signedAttrs bytes — fed to the P-256 precompile via sha256. */
    signedAttrs: Uint8Array;
    /** sha256(signedAttrs) — what the precompile takes as msg_hash. */
    signedAttrsSha256: Uint8Array;
    /**
     * RFC 5652 §11.3 `signingTime` authenticated attribute (OID
     * 1.2.840.113549.1.9.5), if present in signedAttrs. Used by the OPRF
     * attestation gate to enforce a freshness window.
     */
    signingTime: Date | null;
    /** Inner messageDigest attribute extracted from signedAttrs. */
    messageDigest: Uint8Array;
    /**
     * Byte offset within `signedAttrs` where the 32-byte `messageDigest`
     * OCTET STRING **value** begins. The Noir circuit copies
     * `signedAttrs[messageDigestOffset .. messageDigestOffset + 32]` and
     * binds it to `sha256(petition_id || "::" || petition_text_hash)`.
     */
    messageDigestOffset: number;
    /** Signer cert subject serial bytes. Must start with "TINUA-" for Diia. */
    subjectSerial: Uint8Array;
    /** Leaf cert DER bytes. */
    leafCertDer: Uint8Array;
    /**
     * TBSCertificate bytes of the leaf cert — i.e. the inner SEQUENCE inside
     * `leafCertDer` that the intermediate's ECDSA signature is computed over.
     * The Noir circuit consumes this directly (zero-padded to
     * `LEAF_TBS_MAX_BYTES`) and the contract feeds `sha256(leafTbsBytes)` to
     * the RIP-7212 precompile as `msgHash` for the intermediate->leaf check.
     */
    leafTbsBytes: Uint8Array;
    /** sha256(leafTbsBytes) — the precompile-side `msgHash`. */
    leafTbsSha256: Uint8Array;
    /**
     * Byte offset within `leafTbsBytes` where the 32-byte `subjectSerial`
     * value begins. The circuit asserts
     * `leafTbsBytes[subjectSerialOffset .. +32] == subjectSerial`.
     */
    subjectSerialOffset: number;
    /**
     * Byte offset within `leafTbsBytes` where the 32-byte X coordinate of
     * the leaf's P-256 pubkey begins (i.e. immediately after the canonical
     * 27-byte P-256 SPKI prefix). The circuit asserts the prefix at
     * `[offset-27 .. offset]` and extracts `(X, Y)` from `[offset .. offset+64]`.
     */
    leafPubkeyOffset: number;
    /**
     * Canonical SubjectPublicKeyInfo DER bytes of the leaf cert. The legacy
     * D-v1 trust-root committed to leaf SPKIs; D-v2 commits to intermediate
     * SPKIs instead, so this is now kept only for back-compat and parity
     * checks — the witness builder no longer consumes it.
     */
    leafSpkiDer: Uint8Array;
    /** Intermediate cert DER (if present in SignedData certificates set). */
    intermediateCertDer: Uint8Array | null;
    /** Canonical SPKI DER of the intermediate cert (null if intermediate absent). */
    intermediateSpkiDer: Uint8Array | null;
    /** P-256 pubkey of the intermediate (null if intermediate absent). */
    intermediatePubkey: { x: bigint; y: bigint } | null;
    /**
     * Byte offset within `intermediateSpkiDer` where X[0] of the
     * intermediate's P-256 pubkey begins. The circuit asserts the canonical
     * prefix at `[offset-27 .. offset]` and extracts `(X, Y)` from there.
     */
    intermediatePubkeyOffset: number | null;
    /** P-256 pubkey affine coords from the leaf cert SPKI. */
    pubkey: { x: bigint; y: bigint };
    /** ECDSA signature (r, s) on signedAttrs — the citizen's leaf signature. */
    signature: { r: bigint; s: bigint };
    /**
     * ECDSA signature (r, s) extracted from the leaf cert's `signatureValue`.
     * Computed by the intermediate CA over `leafTbsBytes`, this is the
     * second input to RIP-7212 in `PetitionRegistry.signPetition` (the
     * chain-link from intermediate to leaf).
     */
    leafCertSignature: { r: bigint; s: bigint };
}

/**
 * Parse a CAdES-BES detached signature (`.p7s`) into the inputs both the
 * `PetitionRegistry` contract and the eligibility Noir circuit consume.
 */
export function parseP7s(bytes: Uint8Array): ParsedP7s {
    const ab = toArrayBuffer(bytes);
    const asn = fromBER(ab);
    if (asn.offset === -1) {
        throw new Error("parseP7s: invalid BER at top level");
    }
    const contentInfo = new ContentInfo({ schema: asn.result });
    if (contentInfo.contentType !== "1.2.840.113549.1.7.2") {
        throw new Error(
            `parseP7s: ContentInfo is not SignedData (got ${contentInfo.contentType})`,
        );
    }
    const signed = new SignedData({ schema: contentInfo.content });

    if (signed.signerInfos.length !== 1) {
        throw new Error(
            `parseP7s: expected exactly 1 SignerInfo, got ${signed.signerInfos.length}`,
        );
    }
    const signer = signed.signerInfos[0]!;
    if (!signer.signedAttrs) {
        throw new Error(
            "parseP7s: SignerInfo missing signedAttrs (CAdES-BES requires it)",
        );
    }

    // (1) signedAttrs in its hash-input form (SET tag, not [0] IMPLICIT).
    const signedAttrs = reTagSignedAttrs(
        new Uint8Array(signer.signedAttrs.toSchema().toBER(false)),
    );

    // (2) sha256(signedAttrs) — passed to the P-256 precompile as msg_hash.
    const signedAttrsSha256 = sha256(signedAttrs);

    // (3) Inner messageDigest attribute value (32 bytes — SHA-256 of the
    //     detached payload, e.g. SHA-256(petition_id || "::" || textHash)).
    const messageDigest = extractMessageDigest(signer);
    const messageDigestOffset = locateMessageDigestOffset(signedAttrs, messageDigest);

    // (3b) Optional signingTime authenticated attribute — the OPRF gate
    //      enforces a freshness window over this.
    const signingTime = extractSigningTime(signer);

    // (4, 5, 6) Cert chain. Identify the leaf via SID, fall back to first
    //           cert if SID matching is ambiguous (shouldn't happen for
    //           well-formed Diia .p7s).
    const certs = collectCertificates(signed);
    const leafCert = pickLeafBySid(certs, signer);
    const leafCertDer = new Uint8Array(leafCert.toSchema().toBER(false));
    const subjectSerial = extractSubjectSerial(leafCertDer);
    const pubkey = extractP256Pubkey(leafCert);
    const leafSpkiDer = new Uint8Array(
        leafCert.subjectPublicKeyInfo.toSchema().toBER(false),
    );

    // (4a) Leaf TBSCertificate slice + sha256 + the offsets the v2 circuit
    //      consumes (subject serial, leaf pubkey).
    const { tbsBytes: leafTbsBytes, tbsStart } = extractTbsBytes(leafCertDer);
    const leafTbsSha256 = sha256(leafTbsBytes);
    const subjectSerialOffset = locateSubjectSerialInTbs(
        leafTbsBytes,
        subjectSerial,
        leafCertDer,
        tbsStart,
    );
    const leafPubkeyOffset = locateP256PubkeyOffset(leafTbsBytes, "leaf TBSCertificate");

    // (4b) intermediate-CA chain link: SPKI bytes, pubkey, pubkey offset.
    const intermediate = pickIntermediate(certs, leafCert);
    const intermediateCertDer = intermediate
        ? new Uint8Array(intermediate.toSchema().toBER(false))
        : null;
    let intermediateSpkiDer: Uint8Array | null = null;
    let intermediatePubkey: { x: bigint; y: bigint } | null = null;
    let intermediatePubkeyOffset: number | null = null;
    if (intermediate) {
        intermediateSpkiDer = new Uint8Array(
            intermediate.subjectPublicKeyInfo.toSchema().toBER(false),
        );
        intermediatePubkey = extractP256Pubkey(intermediate);
        intermediatePubkeyOffset = locateP256PubkeyOffset(
            intermediateSpkiDer,
            "intermediate SubjectPublicKeyInfo",
        );
    }

    // (7) Signatures.
    //  - `signature`        = leaf -> signedAttrs (citizen signing the petition).
    //  - `leafCertSignature`= intermediate -> leafTbs (CA signing the cert).
    const signature = parseEcdsaSigValue(
        new Uint8Array(signer.signature.valueBlock.valueHexView),
    );
    const leafCertSignature = parseEcdsaSigValue(
        new Uint8Array(leafCert.signatureValue.valueBlock.valueHexView),
    );

    return {
        signedAttrs,
        signedAttrsSha256,
        signingTime,
        messageDigest,
        messageDigestOffset,
        subjectSerial,
        leafCertDer,
        leafTbsBytes,
        leafTbsSha256,
        subjectSerialOffset,
        leafPubkeyOffset,
        leafSpkiDer,
        intermediateCertDer,
        intermediateSpkiDer,
        intermediatePubkey,
        intermediatePubkeyOffset,
        pubkey,
        signature,
        leafCertSignature,
    };
}

/**
 * Extract the inner TBSCertificate SEQUENCE from an X.509 cert DER. The
 * cert is `SEQUENCE { TBSCertificate, signatureAlgorithm, signatureValue }`;
 * the first inner SEQUENCE is exactly TBSCertificate.
 */
function extractTbsBytes(certDer: Uint8Array): {
    tbsBytes: Uint8Array;
    tbsStart: number;
} {
    if (certDer.length === 0 || certDer[0] !== 0x30) {
        throw new Error("parseP7s: leaf cert is not a SEQUENCE");
    }
    const outer = readDerLength(certDer, 1);
    const innerStart = 1 + outer.headerLen;
    if (certDer[innerStart] !== 0x30) {
        throw new Error("parseP7s: leaf cert inner element is not TBSCertificate SEQUENCE");
    }
    const tbs = readDerLength(certDer, innerStart + 1);
    const tbsLen = 1 + tbs.headerLen + tbs.contentLen;
    const tbsBytes = certDer.slice(innerStart, innerStart + tbsLen);
    return { tbsBytes, tbsStart: innerStart };
}

/**
 * Find the offset within `tbsBytes` where the ETSI subject serial value
 * begins. The DN walker in `extractSubjectSerial` works on the full leaf
 * cert DER, so we re-run it against the same DER to recover an absolute
 * offset and translate it to TBS-local coordinates.
 */
function locateSubjectSerialInTbs(
    tbsBytes: Uint8Array,
    subjectSerial: Uint8Array,
    leafCertDer: Uint8Array,
    tbsStart: number,
): number {
    // We re-search for the exact serial value bytes inside the TBS; the
    // serialNumber RDN value is unique enough (TINUA- prefix + tax-ID) that
    // a byte-scan won't false-match. We start the search after issuer DN by
    // walking from the absolute hit in leafCertDer.
    const absHit = indexOf(leafCertDer, subjectSerial);
    if (absHit < 0) {
        throw new Error("parseP7s: subjectSerial bytes not found in leaf cert DER");
    }
    const tbsRel = absHit - tbsStart;
    if (tbsRel < 0 || tbsRel + subjectSerial.length > tbsBytes.length) {
        throw new Error("parseP7s: subjectSerial lies outside TBSCertificate range");
    }
    // Sanity: the same bytes are actually there.
    if (!bytesEqAt(tbsBytes, tbsRel, subjectSerial)) {
        throw new Error("parseP7s: subjectSerial bytes mismatch in TBS slice");
    }
    return tbsRel;
}

/**
 * Find the offset in `buf` immediately after the canonical 27-byte P-256
 * SPKI prefix — i.e. where the first byte of X[0] sits. Throws if the
 * prefix isn't present (we only support P-256 leafs and intermediates).
 */
function locateP256PubkeyOffset(buf: Uint8Array, label: string): number {
    const at = indexOf(buf, P256_SPKI_PREFIX);
    if (at < 0) {
        throw new Error(
            `parseP7s: canonical P-256 SPKI prefix not found in ${label}`,
        );
    }
    const off = at + P256_SPKI_PREFIX_LEN;
    if (off + 64 > buf.length) {
        throw new Error(
            `parseP7s: P-256 pubkey would run off the end of ${label} (off=${off}, len=${buf.length})`,
        );
    }
    return off;
}

/**
 * Find the byte offset of the 32-byte `messageDigest` OCTET STRING **value**
 * within `signedAttrs`. The encoding is always `04 20 <32 bytes>` (OCTET
 * STRING tag, length 32, then payload) nested inside the messageDigest
 * Attribute's SET-OF-AttributeValue wrapper. We scan for `04 20` followed
 * by the exact `messageDigest` payload to pin the value position without
 * re-walking the full ASN.1 tree.
 */
function locateMessageDigestOffset(
    signedAttrs: Uint8Array,
    messageDigest: Uint8Array,
): number {
    if (messageDigest.length !== 32) {
        throw new Error(
            `parseP7s: messageDigest must be 32 bytes (got ${messageDigest.length})`,
        );
    }
    for (let i = 0; i + 2 + 32 <= signedAttrs.length; i++) {
        if (signedAttrs[i] !== 0x04 || signedAttrs[i + 1] !== 0x20) continue;
        let match = true;
        for (let j = 0; j < 32; j++) {
            if (signedAttrs[i + 2 + j] !== messageDigest[j]) {
                match = false;
                break;
            }
        }
        if (match) return i + 2;
    }
    throw new Error(
        "parseP7s: could not locate messageDigest OCTET STRING value inside signedAttrs",
    );
}

// ----- helpers ---------------------------------------------------------------

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
    // Make a copy: pkijs / asn1js mutate the underlying buffer in some
    // code paths. We do not want to surprise the caller.
    const ab = new ArrayBuffer(u8.byteLength);
    new Uint8Array(ab).set(u8);
    return ab;
}

/**
 * Re-encode pkijs's SignedAttributes block from `[0] IMPLICIT` (on-the-wire
 * tag 0xA0) into the `SET` form (tag 0x31) the leaf signature was computed
 * over. One-byte tag swap; RFC 5652 §5.4 ToBeSigned signedAttrs recipe.
 */
function reTagSignedAttrs(implicit: Uint8Array): Uint8Array {
    if (implicit.length === 0) {
        throw new Error("parseP7s: empty signedAttrs");
    }
    if (implicit[0] !== 0xa0) {
        throw new Error(
            `parseP7s: expected [0] IMPLICIT tag 0xA0 on signedAttrs; got 0x${implicit[0]!.toString(16)}`,
        );
    }
    const out = new Uint8Array(implicit.length);
    out.set(implicit);
    out[0] = 0x31; // SET
    return out;
}

function sha256(data: Uint8Array): Uint8Array {
    return new Uint8Array(createHash("sha256").update(data).digest());
}

function extractMessageDigest(signer: SignerInfo): Uint8Array {
    const attrs = signer.signedAttrs?.attributes ?? [];
    const md = attrs.find((a) => a.type === MESSAGE_DIGEST_OID);
    if (!md) {
        throw new Error(
            "parseP7s: messageDigest attribute (OID 1.2.840.113549.1.9.4) missing from signedAttrs",
        );
    }
    if (md.values.length !== 1) {
        throw new Error(
            `parseP7s: messageDigest attribute has ${md.values.length} values; expected 1`,
        );
    }
    const v = md.values[0] as unknown;
    if (!(v instanceof OctetString)) {
        throw new Error(
            "parseP7s: messageDigest attribute value is not an OCTET STRING",
        );
    }
    const bytes = new Uint8Array(v.valueBlock.valueHexView);
    if (bytes.length !== 32) {
        throw new Error(
            `parseP7s: messageDigest is ${bytes.length} bytes; expected 32 (sha-256)`,
        );
    }
    return bytes;
}

/**
 * Pull the optional `signingTime` authenticated attribute (RFC 5652 §11.3,
 * OID 1.2.840.113549.1.9.5) from `signedAttrs`. Returns `null` if absent —
 * callers (the OPRF attestation gate) decide whether absence is fatal.
 *
 * The attribute value is `Time ::= CHOICE { utcTime UTCTime, generalTime
 * GeneralizedTime }`. pkijs surfaces it as an asn1js UTCTime or
 * GeneralizedTime node carrying a JS `Date` on `valueBlock.value`.
 */
function extractSigningTime(signer: SignerInfo): Date | null {
    const attrs = signer.signedAttrs?.attributes ?? [];
    const st = attrs.find((a) => a.type === SIGNING_TIME_OID);
    if (!st || st.values.length === 0) return null;
    // asn1js wraps Time as either a UTCTime or GeneralizedTime node. Both
    // carry a `.toDate(): Date` method (preferred), or a Date in
    // `valueBlock.value` for older asn1js versions.
    const v = st.values[0] as {
        toDate?: () => Date;
        valueBlock?: { value?: unknown };
    } | undefined;
    if (v && typeof v.toDate === "function") {
        const d = v.toDate();
        if (!Number.isNaN(d.getTime())) return new Date(d.getTime());
    }
    const raw = v?.valueBlock?.value;
    if (raw instanceof Date) {
        if (!Number.isNaN(raw.getTime())) return new Date(raw.getTime());
    }
    if (typeof raw === "string" && raw.length > 0) {
        const d = new Date(raw);
        if (!Number.isNaN(d.getTime())) return d;
    }
    return null;
}

function collectCertificates(signed: SignedData): Certificate[] {
    if (!signed.certificates || signed.certificates.length === 0) {
        throw new Error("parseP7s: SignedData carries no certificates");
    }
    const certs = signed.certificates.filter(
        (c): c is Certificate => c instanceof Certificate,
    );
    if (certs.length === 0) {
        throw new Error("parseP7s: SignedData carries no Certificate-typed entries");
    }
    return certs;
}

/**
 * Pick the leaf cert that actually signed this CMS. SID is one of:
 *   - IssuerAndSerialNumber: match cert.issuer DN bytes + serialNumber Integer.
 *   - SubjectKeyIdentifier ([0] IMPLICIT OCTET STRING in SID context): match
 *     against cert SKI extension contents.
 */
function pickLeafBySid(certs: Certificate[], signer: SignerInfo): Certificate {
    const sid = signer.sid as unknown;

    if (sid instanceof IssuerAndSerialNumber) {
        const wantSerial = bigIntFromInteger(sid.serialNumber);
        const wantIssuerDer = new Uint8Array(
            sid.issuer.toSchema().toBER(false),
        );
        for (const c of certs) {
            const certSerial = bigIntFromInteger(c.serialNumber);
            if (certSerial !== wantSerial) continue;
            const issuerDer = new Uint8Array(c.issuer.toSchema().toBER(false));
            if (bytesEqual(issuerDer, wantIssuerDer)) return c;
        }
        throw new Error(
            "parseP7s: no certificate matched SignerInfo's issuerAndSerialNumber",
        );
    }

    // SubjectKeyIdentifier path: SID is an OCTET STRING wrapped in a
    // [0] IMPLICIT context tag — asn1js exposes a Primitive whose
    // valueBlock.valueHexView is the SKI bytes.
    const sidWithHex = sid as { valueBlock?: { valueHexView?: ArrayBuffer | Uint8Array } };
    const sidView = sidWithHex.valueBlock?.valueHexView;
    if (sidView !== undefined) {
        const wantSki = new Uint8Array(sidView);
        for (const c of certs) {
            const der = new Uint8Array(c.toSchema().toBER(false));
            const ski = extractSki(der);
            if (ski && bytesEqual(ski, wantSki)) return c;
        }
    }

    // Fallback — surface a clear error rather than guessing.
    throw new Error(
        "parseP7s: could not resolve SignerInfo.sid to a certificate in the SignedData",
    );
}

function pickIntermediate(
    certs: Certificate[],
    leaf: Certificate,
): Certificate | null {
    if (certs.length < 2) return null;
    const leafIssuerDer = new Uint8Array(leaf.issuer.toSchema().toBER(false));
    for (const c of certs) {
        if (c === leaf) continue;
        const subjectDer = new Uint8Array(c.subject.toSchema().toBER(false));
        if (bytesEqual(subjectDer, leafIssuerDer)) return c;
    }
    // No DN match — return the first non-leaf cert so callers still have
    // something to anchor a chain against. Diia bundles a single
    // intermediate, so this branch is unreachable in practice.
    for (const c of certs) if (c !== leaf) return c;
    return null;
}

/**
 * Parse the DER ECDSA-Sig-Value `SEQUENCE { r INTEGER, s INTEGER }` carried
 * inside the OCTET STRING of `signerInfo.signature`. Returns positive (r,s)
 * bigints; INTEGER leading-zero padding (used to keep r/s positive when
 * the high bit would otherwise set) is naturally absorbed by big-endian
 * decode.
 */
function parseEcdsaSigValue(der: Uint8Array): { r: bigint; s: bigint } {
    const asn = fromBER(toArrayBuffer(der));
    if (asn.offset === -1) {
        throw new Error("parseP7s: signerInfo.signature is not valid DER");
    }
    const seq = asn.result;
    if (!(seq instanceof Sequence) || seq.valueBlock.value.length !== 2) {
        throw new Error(
            "parseP7s: signerInfo.signature is not an ECDSA-Sig-Value SEQUENCE { r, s }",
        );
    }
    const [rNode, sNode] = seq.valueBlock.value as unknown[];
    if (!(rNode instanceof Integer) || !(sNode instanceof Integer)) {
        throw new Error(
            "parseP7s: ECDSA-Sig-Value components are not INTEGERs",
        );
    }
    const r = bigIntFromInteger(rNode);
    const s = bigIntFromInteger(sNode);
    if (r === 0n || s === 0n) {
        throw new Error("parseP7s: ECDSA signature has zero r or s");
    }
    return { r, s };
}

function bigIntFromInteger(n: Integer): bigint {
    const bytes = new Uint8Array(n.valueBlock.valueHexView);
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return v;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}
