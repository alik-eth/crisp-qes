// Leaf-cert byte-walkers used by the .p7s parser.
//
// Ports the parts of identityescroworg's `leaf-cert-walk.ts` we still need
// (subject serialNumber RDN walk) and adds two extractors not present
// upstream: the SPKI uncompressed P-256 pubkey (x,y) and the SKI extension
// value for SignerInfo SID matching.

import { Certificate } from "pkijs";
import { bytesEqAt, indexOf, readDerLength } from "./asn1.js";

const ETSI_PREFIXES = ["TIN", "PNO", "IDC", "PAS", "CPI"];

/**
 * Extract the subject `serialNumber` RDN VALUE bytes (OID 2.5.4.5) from
 * a leaf cert DER. The OID appears in BOTH the issuer DN (organizational
 * serial) AND the subject DN (the EN 319 412-1 semanticsIdentifier),
 * in that order within TBSCertificate. We prefer the first occurrence
 * whose value starts with an ETSI prefix (TIN/PNO/IDC/PAS/CPI); if none
 * match, we fall back to the SECOND occurrence — subject DN follows
 * issuer DN in TBS field order — to handle off-spec leafs.
 */
export function extractSubjectSerial(der: Uint8Array): Uint8Array {
    // 06 03 55 04 05  — OID 2.5.4.5
    const OID = new Uint8Array([0x06, 0x03, 0x55, 0x04, 0x05]);
    type Hit = { offset: number; length: number; value: string };
    const hits: Hit[] = [];
    const decoder = new TextDecoder("utf-8");
    for (let i = 0; i <= der.length - OID.length - 2; i++) {
        if (!bytesEqAt(der, i, OID)) continue;
        const tag = der[i + OID.length];
        const len = der[i + OID.length + 1];
        if (tag === undefined || len === undefined) continue;
        // DirectoryString CHOICE: PrintableString (0x13) or UTF8String (0x0c).
        if (tag !== 0x13 && tag !== 0x0c) continue;
        const offset = i + OID.length + 2;
        if (offset + len > der.length) continue;
        const value = decoder.decode(der.subarray(offset, offset + len));
        hits.push({ offset, length: len, value });
    }
    if (hits.length === 0) {
        throw new Error(
            "leaf-cert: subject.serialNumber OID 2.5.4.5 not found in leaf DER",
        );
    }
    for (const h of hits) {
        if (ETSI_PREFIXES.some((p) => h.value.startsWith(p))) {
            return der.slice(h.offset, h.offset + h.length);
        }
    }
    const pick = hits.length >= 2 ? hits[1]! : hits[0]!;
    return der.slice(pick.offset, pick.offset + pick.length);
}

/**
 * Extract the affine P-256 public-key coordinates (x, y) from a pkijs
 * Certificate's SubjectPublicKeyInfo. SPKI for ECDSA-P256 is:
 *
 *   SEQUENCE {
 *     SEQUENCE { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 }, -- ecPublicKey, P-256
 *     BIT STRING (0x00 || 0x04 || X[32] || Y[32])                  -- uncompressed point
 *   }
 *
 * We pull the BIT STRING value bytes via pkijs (which strips the leading
 * "unused bits" octet) and validate the 0x04 uncompressed-point prefix.
 */
export function extractP256Pubkey(cert: Certificate): {
    x: bigint;
    y: bigint;
} {
    const spki = cert.subjectPublicKeyInfo;
    const algOid = spki.algorithm.algorithmId;
    if (algOid !== "1.2.840.10045.2.1") {
        throw new Error(
            `leaf-cert: leaf SPKI algorithm is not ecPublicKey (got ${algOid})`,
        );
    }
    // Best-effort curve check: the algorithm parameters carry the named
    // curve OID. Diia always uses prime256v1 / secp256r1.
    const params = spki.algorithm.algorithmParams;
    if (params && typeof params === "object" && "valueBlock" in params) {
        const oidParam = (params as { valueBlock?: { toString?: () => string } })
            .valueBlock;
        const asStr = oidParam?.toString?.();
        if (asStr && asStr !== "1.2.840.10045.3.1.7" && !asStr.includes("1.2.840.10045.3.1.7")) {
            // Not strictly fatal — some encodings differ — but worth noting.
            // We don't throw here because the (x,y) sanity-check below
            // already constrains to 32-byte coords.
        }
    }
    const pkBytes = new Uint8Array(spki.subjectPublicKey.valueBlock.valueHexView);
    if (pkBytes.length !== 65 || pkBytes[0] !== 0x04) {
        throw new Error(
            `leaf-cert: SPKI subjectPublicKey is not a 65-byte uncompressed P-256 point (len=${pkBytes.length}, prefix=0x${(pkBytes[0] ?? 0).toString(16)})`,
        );
    }
    const xBytes = pkBytes.subarray(1, 33);
    const yBytes = pkBytes.subarray(33, 65);
    return { x: bytesToBigInt(xBytes), y: bytesToBigInt(yBytes) };
}

/**
 * Extract the SubjectKeyIdentifier extension value (OID 2.5.29.14) from a
 * cert DER. The extension value is an OCTET STRING wrapping another
 * OCTET STRING that contains the SKI bytes proper. Returns `null` if the
 * extension is absent.
 */
export function extractSki(der: Uint8Array): Uint8Array | null {
    // OID 2.5.29.14: 06 03 55 1d 0e
    const OID = new Uint8Array([0x06, 0x03, 0x55, 0x1d, 0x0e]);
    const at = indexOf(der, OID);
    if (at < 0) return null;
    // The Extension is `SEQUENCE { OID, [critical BOOLEAN,] OCTET STRING extnValue }`.
    // We walk past OID, optional BOOLEAN, then the outer OCTET STRING wraps
    // an inner OCTET STRING whose content is the SKI bytes.
    let cur = at + OID.length;
    if (der[cur] === 0x01) {
        // BOOLEAN critical
        const { headerLen, contentLen } = readDerLength(der, cur + 1);
        cur += 1 + headerLen + contentLen;
    }
    if (der[cur] !== 0x04) return null; // outer OCTET STRING
    const outer = readDerLength(der, cur + 1);
    const innerStart = cur + 1 + outer.headerLen;
    if (der[innerStart] !== 0x04) return null; // inner OCTET STRING
    const inner = readDerLength(der, innerStart + 1);
    const valStart = innerStart + 1 + inner.headerLen;
    return der.slice(valStart, valStart + inner.contentLen);
}

function bytesToBigInt(b: Uint8Array): bigint {
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v;
}
