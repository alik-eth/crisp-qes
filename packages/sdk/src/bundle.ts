// Diia `.p7b` bundle helpers.
//
// Some Diia citizen `.p7s` files carry only the leaf certificate — the
// intermediate that issued it is omitted from the SignedData certificates
// set. To still run the D-v2 chain-verify path, the SDK accepts the public
// Diia `.p7b` bundle as a fallback "where to find issuers" source: we
// extract the leaf's AuthorityKeyIdentifier (which is the issuer's SHA-1
// SKI), then scan the bundle for the cert whose SubjectKeyIdentifier
// matches.
//
// This module is browser-safe (no `node:fs`, no flattener dependency).
// `parseP7b` is a hand-rolled DER walker over the same shape that
// `packages/lotl-flattener/src/fetch/p7b.ts` walks; we port it inline to
// keep the SDK's footprint independent of the build-time flattener.

import { readDerLength, bytesEqAt, indexOf } from "./asn1.js";

// OID 1.2.840.113549.1.7.2 — signedData
const OID_SIGNED_DATA = new Uint8Array([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
]);
// OID 2.5.29.14 — subjectKeyIdentifier
const OID_SKI = new Uint8Array([0x06, 0x03, 0x55, 0x1d, 0x0e]);
// OID 2.5.29.35 — authorityKeyIdentifier
const OID_AKI = new Uint8Array([0x06, 0x03, 0x55, 0x1d, 0x23]);

// Canonical 27-byte ECDSA-P-256 SPKI prefix — mirror of p7s.ts.
const P256_SPKI_PREFIX = new Uint8Array([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
]);
const P256_SPKI_PREFIX_LEN = P256_SPKI_PREFIX.length;
// Full canonical P-256 SPKI is `30 59 <89 bytes>` = 91 bytes total.
const P256_SPKI_DER_LEN = 2 + 89;

interface TLV {
    tag: number;
    contentStart: number;
    contentEnd: number;
}

function readTlv(der: Uint8Array, off: number): TLV {
    if (off >= der.length) {
        throw new Error(`p7b: read past EOF at offset ${off}`);
    }
    const tag = der[off]!;
    const { headerLen, contentLen } = readDerLength(der, off + 1);
    const contentStart = off + 1 + headerLen;
    const contentEnd = contentStart + contentLen;
    if (contentEnd > der.length) {
        throw new Error(`p7b: TLV at offset ${off} extends past EOF`);
    }
    return { tag, contentStart, contentEnd };
}

/**
 * Parse a binary CMS-SignedData `.p7b` blob and return the DER bytes of
 * every X.509 Certificate (`SEQUENCE`-tagged entry) carried in the
 * `certificates [0] IMPLICIT` field. Order is preserved.
 */
export function parseP7bBundle(der: Uint8Array): Uint8Array[] {
    // ContentInfo SEQUENCE
    const ci = readTlv(der, 0);
    if (ci.tag !== 0x30) {
        throw new Error(`p7b: outer is not SEQUENCE (got tag 0x${ci.tag.toString(16)})`);
    }
    if (!bytesEqAt(der, ci.contentStart, OID_SIGNED_DATA)) {
        throw new Error("p7b: contentType is not signedData");
    }
    let cur = ci.contentStart + OID_SIGNED_DATA.length;

    // content [0] EXPLICIT
    const exp = readTlv(der, cur);
    if (exp.tag !== 0xa0) {
        throw new Error("p7b: expected [0] EXPLICIT after contentType");
    }
    cur = exp.contentStart;

    // SignedData SEQUENCE
    const sd = readTlv(der, cur);
    if (sd.tag !== 0x30) throw new Error("p7b: SignedData payload is not SEQUENCE");
    cur = sd.contentStart;

    // version INTEGER
    const ver = readTlv(der, cur);
    if (ver.tag !== 0x02) throw new Error("p7b: version is not INTEGER");
    cur = ver.contentEnd;

    // digestAlgorithms SET
    const da = readTlv(der, cur);
    if (da.tag !== 0x31) throw new Error("p7b: digestAlgorithms is not SET");
    cur = da.contentEnd;

    // encapContentInfo SEQUENCE
    const eci = readTlv(der, cur);
    if (eci.tag !== 0x30) throw new Error("p7b: encapContentInfo is not SEQUENCE");
    cur = eci.contentEnd;

    // certificates [0] IMPLICIT (optional)
    if (cur >= sd.contentEnd) return [];
    const next = readTlv(der, cur);
    if (next.tag !== 0xa0) return [];

    const certs: Uint8Array[] = [];
    let ptr = next.contentStart;
    while (ptr < next.contentEnd) {
        const cert = readTlv(der, ptr);
        if (cert.tag === 0x30) {
            certs.push(der.slice(ptr, cert.contentEnd));
        }
        ptr = cert.contentEnd;
    }
    return certs;
}

/**
 * Extract the `subjectKeyIdentifier` (OID 2.5.29.14) value from an X.509
 * cert DER. The extension wraps an OCTET STRING that itself wraps the
 * 20-byte SHA-1 SKI bytes. Throws if absent.
 */
export function extractSubjectKeyIdentifier(certDer: Uint8Array): Uint8Array {
    const ski = walkOctetWrappedOctet(certDer, OID_SKI);
    if (ski === null) {
        throw new Error("bundle: cert has no subjectKeyIdentifier extension");
    }
    return ski;
}

/**
 * Extract the `authorityKeyIdentifier.keyIdentifier` field (OID 2.5.29.35)
 * from an X.509 cert DER. The extension value is an OCTET STRING wrapping a
 * SEQUENCE; the keyIdentifier is the [0] IMPLICIT OCTET STRING element of
 * that SEQUENCE. Returns the 20-byte issuer-SKI bytes, or throws.
 */
export function extractAuthorityKeyIdentifier(certDer: Uint8Array): Uint8Array {
    const at = indexOf(certDer, OID_AKI);
    if (at < 0) {
        throw new Error("bundle: cert has no authorityKeyIdentifier extension");
    }
    let cur = at + OID_AKI.length;
    // Optional critical BOOLEAN.
    if (certDer[cur] === 0x01) {
        const { headerLen, contentLen } = readDerLength(certDer, cur + 1);
        cur += 1 + headerLen + contentLen;
    }
    // Outer OCTET STRING wrapping the AKI SEQUENCE.
    if (certDer[cur] !== 0x04) {
        throw new Error("bundle: AKI extension is missing outer OCTET STRING");
    }
    const outer = readDerLength(certDer, cur + 1);
    const innerStart = cur + 1 + outer.headerLen;
    if (certDer[innerStart] !== 0x30) {
        throw new Error("bundle: AKI inner is not a SEQUENCE");
    }
    const seq = readDerLength(certDer, innerStart + 1);
    let p = innerStart + 1 + seq.headerLen;
    const end = innerStart + 1 + seq.headerLen + seq.contentLen;
    while (p < end) {
        // [0] IMPLICIT OCTET STRING — context-specific primitive, tag 0x80
        if (certDer[p] === 0x80) {
            const len = readDerLength(certDer, p + 1);
            const valStart = p + 1 + len.headerLen;
            return certDer.slice(valStart, valStart + len.contentLen);
        }
        const t = readDerLength(certDer, p + 1);
        p += 1 + t.headerLen + t.contentLen;
    }
    throw new Error("bundle: AKI keyIdentifier ([0] IMPLICIT) not found");
}

/**
 * For a cert DER known to carry a P-256 SPKI, return:
 *   - `spkiDer`     : the 91-byte canonical SPKI slice (30 59 ... X || Y).
 *   - `pubkey`      : the affine (X, Y) coords as bigints.
 *   - `pubkeyOffset`: byte offset within `spkiDer` where X[0] sits (always 27).
 *
 * Throws if the canonical 27-byte prefix is not found.
 */
export function extractP256SpkiFromCert(certDer: Uint8Array): {
    spkiDer: Uint8Array;
    pubkey: { x: bigint; y: bigint };
    pubkeyOffset: number;
} {
    const at = indexOf(certDer, P256_SPKI_PREFIX);
    if (at < 0) {
        throw new Error("bundle: canonical P-256 SPKI prefix not found in cert");
    }
    if (at + P256_SPKI_DER_LEN > certDer.length) {
        throw new Error("bundle: P-256 SPKI would run off the end of cert");
    }
    const spkiDer = certDer.slice(at, at + P256_SPKI_DER_LEN);
    const pkStart = P256_SPKI_PREFIX_LEN; // 27 — by construction
    const xBytes = spkiDer.subarray(pkStart, pkStart + 32);
    const yBytes = spkiDer.subarray(pkStart + 32, pkStart + 64);
    return {
        spkiDer,
        pubkey: { x: beBytesToBigInt(xBytes), y: beBytesToBigInt(yBytes) },
        pubkeyOffset: pkStart,
    };
}

export interface IssuerFromBundle {
    /** DER bytes of the issuer cert from the bundle. */
    certDer: Uint8Array;
    /** Canonical P-256 SPKI slice (91 bytes) of the issuer. */
    spkiDer: Uint8Array;
    /** Issuer's P-256 affine pubkey. */
    pubkey: { x: bigint; y: bigint };
    /** Byte offset within `spkiDer` where X[0] sits (27 by construction). */
    pubkeyOffset: number;
    /** Index of the matched cert in the input bundle. */
    bundleIndex: number;
}

/**
 * Resolve the issuer of a leaf certificate against a `.p7b` bundle by
 * matching the leaf's AuthorityKeyIdentifier to a bundle cert's
 * SubjectKeyIdentifier. Returns `null` if no bundle cert has a matching SKI.
 *
 * Used when the citizen's `.p7s` doesn't bundle the intermediate (some
 * Diia signatures omit it). The Diia public `.p7b` from
 * ca.diia.gov.ua is the canonical "where to find issuers" source.
 */
export function findIssuerInBundle(
    leafCertDer: Uint8Array,
    bundle: Uint8Array[],
): IssuerFromBundle | null {
    const aki = extractAuthorityKeyIdentifier(leafCertDer);
    for (let i = 0; i < bundle.length; i++) {
        const candidate = bundle[i]!;
        let ski: Uint8Array;
        try {
            ski = extractSubjectKeyIdentifier(candidate);
        } catch {
            // Cert without SKI cannot be matched — skip silently.
            continue;
        }
        if (!bytesEqual(ski, aki)) continue;
        const spki = extractP256SpkiFromCert(candidate);
        return {
            certDer: candidate,
            spkiDer: spki.spkiDer,
            pubkey: spki.pubkey,
            pubkeyOffset: spki.pubkeyOffset,
            bundleIndex: i,
        };
    }
    return null;
}

// ----------------------------------------------------------------------------

function walkOctetWrappedOctet(certDer: Uint8Array, oid: Uint8Array): Uint8Array | null {
    const at = indexOf(certDer, oid);
    if (at < 0) return null;
    let cur = at + oid.length;
    if (certDer[cur] === 0x01) {
        // BOOLEAN critical
        const { headerLen, contentLen } = readDerLength(certDer, cur + 1);
        cur += 1 + headerLen + contentLen;
    }
    if (certDer[cur] !== 0x04) return null;
    const outer = readDerLength(certDer, cur + 1);
    const innerStart = cur + 1 + outer.headerLen;
    if (certDer[innerStart] !== 0x04) return null;
    const inner = readDerLength(certDer, innerStart + 1);
    const valStart = innerStart + 1 + inner.headerLen;
    return certDer.slice(valStart, valStart + inner.contentLen);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function beBytesToBigInt(b: Uint8Array): bigint {
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v;
}
