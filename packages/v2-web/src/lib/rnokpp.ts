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
