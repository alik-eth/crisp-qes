// Extract the RNOKPP (Ukrainian tax id) bytes from a parsed Diia QES.
//
// The Diia certificate's subject `serialNumber` attribute is of the
// form `TINUA-<RNOKPP>` (UA citizens) or `TINUA-<UID>` (legal-entity
// flavour). The RNOKPP itself is what we feed into the OPRF hash; the
// `TINUA-` prefix is locale-stable and removed first.
//
// We deliberately use *only* the raw decimal RNOKPP digits as the OPRF
// input. The OPRF output is deterministic in that input, so a re-enrolled
// citificate from Diia (same RNOKPP) produces the same commitment and
// is rejected as a duplicate. That's the Sybil guarantee.

import type { ParsedP7s } from "@crisp-qes/sdk";

const TINUA_PREFIX = "TINUA-";

export function extractRnokpp(p: ParsedP7s): string {
    const raw = new TextDecoder().decode(p.subjectSerial);
    if (!raw.startsWith(TINUA_PREFIX)) {
        throw new Error(
            `subjectSerial does not start with ${TINUA_PREFIX}: ${raw}`,
        );
    }
    return raw.slice(TINUA_PREFIX.length);
}

/** UTF-8 bytes of the RNOKPP, ready to feed into ristretto255 hash-to-curve. */
export function rnokppBytes(p: ParsedP7s): Uint8Array {
    return new TextEncoder().encode(extractRnokpp(p));
}

export function tinuaPrefixOk(p: ParsedP7s): boolean {
    return new TextDecoder().decode(p.subjectSerial).startsWith(TINUA_PREFIX);
}

// Diia DOB attribute OID (1.2.804.2.1.1.1.11.1.4.11.1), DER-encoded. The DOB
// is carried in the SubjectDirectoryAttributes extension as a PrintableString
// "YYYYMMDD-XXXXX"; we read the leading 8 YYYYMMDD digits. Mirrors the OID
// p7sWitness.findDobOffset scans for, so the digit run located here is the
// same one the circuit byte-reads.
const DOB_ATTRIBUTE_OID = new Uint8Array([
    0x06, 0x0c, 0x2a, 0x86, 0x67, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x01, 0x04,
    0x0b, 0x01,
]);

function indexOf(hay: Uint8Array, needle: Uint8Array, from = 0): number {
    const last = hay.length - needle.length;
    outer: for (let i = from; i <= last; i++) {
        for (let k = 0; k < needle.length; k++) {
            if (hay[i + k] !== needle[k]) continue outer;
        }
        return i;
    }
    return -1;
}

/**
 * Best-effort extraction of the citizen's DOB (YYYYMMDD) from the leaf cert
 * DER. Scans forward from the Diia DOB attribute OID for the first run of 8
 * ASCII digits. Throws if no such run is found. Used by the v3 enrollment
 * flow to feed p7sWitness.buildP7sEnrollWitness (the v2 flow checks age
 * server-side and never needs DOB client-side).
 */
export function extractDOB(p: ParsedP7s): string {
    const der = p.leafCertDer;
    const oidAt = indexOf(der, DOB_ATTRIBUTE_OID, 0);
    const from = oidAt >= 0 ? oidAt + DOB_ATTRIBUTE_OID.length : 0;
    for (let i = from; i + 8 <= der.length; i++) {
        let ok = true;
        for (let k = 0; k < 8; k++) {
            const b = der[i + k]!;
            if (b < 0x30 || b > 0x39) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return new TextDecoder().decode(der.subarray(i, i + 8));
        }
    }
    throw new Error(
        "extractDOB: no 8-digit YYYYMMDD run found near the Diia DOB attribute " +
            "OID in the leaf cert DER.",
    );
}
