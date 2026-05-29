// Date-of-birth extraction from a Diia QES leaf certificate, plus a
// strict calendar age comparator.
//
// # Background — where DOB lives in a Diia cert
//
// The standard X.509 subject DN of a Diia QES contains only CN, SN, GN,
// serialNumber=TINUA-<RNOKPP>, C=UA. DOB is NOT in the subject RDN.
//
// Diia surfaces DOB through the **X.509v3 Subject Directory Attributes**
// extension (OID `2.5.29.9`, RFC 5280 § 4.2.1.8), inside a
// Ukrainian-government-specific attribute (OID
// `1.2.804.2.1.1.1.11.1.4.11.1`). The attribute's value is a printable
// string of the form `YYYYMMDD-XXXXX` where the leading 8 digits encode
// the citizen's calendar date of birth and `XXXXX` is an unrelated
// registry trailer we ignore.
//
// Observed example (alikvovk's own cert in fixtures/diia/):
//
//     X509v3 Subject Directory Attributes:
//       1.2.804.2.1.1.1.11.1.4.11.1: "19990426-02970"
//
// # Failure handling
//
// `extractDOB` returns `null` (NOT throws) when:
//   - the extension is absent (older or foreign QTSP certs)
//   - the attribute is absent
//   - the value doesn't parse as a valid date
//
// The OPRF service treats `null` as fail-open in the v2 demo (admit the
// citizen but log a warning). v3 multi-QTSP design will revisit.
//
// # Why pkijs and not a manual ASN.1 walk
//
// SDK already parses the cert via pkijs for the SignerInfo SID checks;
// it's the canonical "I've decoded a cert" library in this monorepo, and
// the AttributeTypeAndValue walk is a single line of pkijs rather than a
// hundred lines of DER state machine.

import { Certificate, Attribute } from "pkijs";

/** OID of the Ukrainian Diia DOB attribute inside SubjectDirectoryAttributes. */
const DOB_ATTRIBUTE_OID = "1.2.804.2.1.1.1.11.1.4.11.1";

/** OID of the SubjectDirectoryAttributes X.509 extension (RFC 5280 § 4.2.1.8). */
const SUBJECT_DIRECTORY_ATTRIBUTES_OID = "2.5.29.9";

/**
 * Extract the citizen's DOB from a Diia QES leaf-cert DER.
 *
 * Returns a `Date` at UTC-midnight of the parsed DOB, or `null` if the
 * extension/attribute is absent or unparseable. Never throws.
 */
export function extractDOB(leafCertDer: Uint8Array): Date | null {
    // Copy into a fresh ArrayBuffer so pkijs's BufferSource type-check
    // accepts it regardless of the source view's underlying buffer type
    // (Node Buffers from fs.readFile come backed by SharedArrayBuffer in
    // some runtimes, which BufferSource rejects).
    const ab = new ArrayBuffer(leafCertDer.byteLength);
    new Uint8Array(ab).set(leafCertDer);
    let cert: Certificate;
    try {
        cert = Certificate.fromBER(ab);
    } catch {
        return null;
    }

    const extensions = cert.extensions ?? [];
    const sdAttrs = extensions.find(
        (e) => e.extnID === SUBJECT_DIRECTORY_ATTRIBUTES_OID,
    );
    if (!sdAttrs) return null;

    // `parsedValue` is set if pkijs recognises the OID; for the SDA
    // extension pkijs decodes it as `SEQUENCE OF Attribute`. The
    // attribute list is exposed as `parsedValue.attributes` in pkijs v3.
    const parsed = (sdAttrs.parsedValue ?? null) as
        | { attributes?: Attribute[] }
        | null;
    const attrs: Attribute[] = parsed?.attributes ?? [];

    const dobAttr = attrs.find((a) => a.type === DOB_ATTRIBUTE_OID);
    if (!dobAttr || !dobAttr.values || dobAttr.values.length === 0) return null;

    // Attribute value is a SET OF AttributeValue. For the Diia DOB
    // attribute, the lone value is a PrintableString. pkijs lifts the
    // string into `.valueBlock.value` on the asn1js side.
    const v = dobAttr.values[0] as
        | { valueBlock?: { value?: string } }
        | undefined;
    const raw = v?.valueBlock?.value;
    if (typeof raw !== "string" || raw.length < 8) return null;

    return parseDOBString(raw);
}

/**
 * Parse a Diia DOB raw string of the form `YYYYMMDD[-XXXXX]` into a UTC
 * `Date`. Returns null on any structural / range error.
 *
 * Exported so the OPRF service can log on the parsed string without
 * needing to re-walk the cert.
 */
export function parseDOBString(raw: string): Date | null {
    if (!/^\d{8}/.test(raw)) return null;
    const y = Number(raw.slice(0, 4));
    const m = Number(raw.slice(4, 6));
    const d = Number(raw.slice(6, 8));
    if (m < 1 || m > 12 || d < 1 || d > 31) return null;
    // Reject obviously out-of-range years: nobody is signing petitions
    // on Sepolia before they were born or after 2100.
    if (y < 1900 || y > 2100) return null;
    // Round-trip check catches Feb 30, Apr 31, etc. — JS Date silently
    // overflows otherwise.
    const t = Date.UTC(y, m - 1, d);
    const back = new Date(t);
    if (
        back.getUTCFullYear() !== y ||
        back.getUTCMonth() !== m - 1 ||
        back.getUTCDate() !== d
    ) {
        return null;
    }
    return back;
}

/**
 * Strict calendar age in completed years between `dob` and `now`.
 *
 * Definition: "today < (dob + N years)" → age is N-1. Matches the legal
 * intuition that someone born on 2026-05-30 turns 18 on 2044-05-30 (NOT
 * 2044-05-29), so being 17 + 364 days reads as 17.
 *
 * Both arguments are treated in UTC. `dob > now` returns 0.
 */
export function ageInYears(dob: Date, now: Date): number {
    let age = now.getUTCFullYear() - dob.getUTCFullYear();
    const m = now.getUTCMonth() - dob.getUTCMonth();
    if (m < 0 || (m === 0 && now.getUTCDate() < dob.getUTCDate())) {
        age--;
    }
    return Math.max(0, age);
}
