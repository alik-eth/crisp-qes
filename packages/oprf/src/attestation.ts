// Diia QES (.p7s) attestation verification.
//
// The OPRF service is allowed to BlindEvaluate only if the citizen produces
// a fresh Diia QES over the blinded input bundle (RNOKPP -> X -> M = r*X is
// the citizen's responsibility; the server never sees X or RNOKPP). The
// .p7s is the canonical CAdES-BES envelope Diia signs, which we already
// parse via `@crisp-qes/sdk`'s `parseP7s`.
//
// Demo simplification (intentional, see § 9 of the v2.1 spec):
//
//   * We do NOT verify the X.509 chain of trust against the Diia LOTL root
//     — that work lives in the v1 lotl-flattener and isn't wired here yet.
//     For v2.1-prod, the threshold-OPRF committee verifies the cert chain
//     and the signedAttrs ECDSA per RFC 9497-VOPRF policy gate.
//
//   * We DO assert the subject serial starts with "TINUA-" — this is the
//     unique Diia-issued tag and is enough to keep dev/test traffic from
//     accidentally enrolling under non-Diia certs.
//
//   * We do NOT bind the .p7s payload to the blinded input. v2.1-prod
//     additionally requires `messageDigest == sha256(blindedInput ||
//     enrollment_intent || epoch)`. Wiring that up here means coordinating
//     with web on the exact payload schema; tracked as a follow-up.

import { parseP7s, type ParsedP7s } from "@crisp-qes/sdk";

import { extractDOB } from "./dob.js";

const TINUA_PREFIX = new TextEncoder().encode("TINUA-");

export interface VerifiedAttestation {
    /** Tag the operator can log for support / audit (not RNOKPP itself!). */
    subjectSerialAscii: string;
    /** Raw subject serial bytes — kept in memory, never persisted. */
    subjectSerial: Uint8Array;
    /**
     * Citizen DOB extracted from the leaf cert's SubjectDirectoryAttributes
     * extension. `null` when the cert doesn't carry the Diia DOB attribute
     * (older certs, foreign QTSPs); fail-open in the v2 demo, gated by
     * the OPRF service config. v3 multi-QTSP design revisits.
     */
    dob: Date | null;
}

export function verifyAttestation(p7sBytes: Uint8Array): VerifiedAttestation {
    let parsed: ParsedP7s;
    try {
        parsed = parseP7s(p7sBytes);
    } catch (e) {
        throw new AttestationError(
            "P7sParseFailed",
            `Could not parse .p7s: ${(e as Error).message}`,
        );
    }

    if (
        parsed.subjectSerial.length < TINUA_PREFIX.length ||
        !bytesEq(
            parsed.subjectSerial.subarray(0, TINUA_PREFIX.length),
            TINUA_PREFIX,
        )
    ) {
        throw new AttestationError(
            "NotDiia",
            "subject serial does not start with TINUA- prefix",
        );
    }

    // TODO(v2.1-prod): verify the cert chain against the Diia trust root,
    // and check signedAttrs binds the actual blinded input we received.
    const dob = extractDOB(parsed.leafCertDer);
    return {
        subjectSerialAscii: bytesToAscii(parsed.subjectSerial),
        subjectSerial: parsed.subjectSerial,
        dob,
    };
}

export class AttestationError extends Error {
    constructor(
        readonly code:
            | "P7sParseFailed"
            | "NotDiia"
            | "ChainInvalid"
            | "PayloadMismatch",
        message: string,
    ) {
        super(message);
        this.name = "AttestationError";
    }
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function bytesToAscii(b: Uint8Array): string {
    // The Diia subject serial is "TINUA-" + decimal RNOKPP, all printable
    // ASCII inside the first ~16 bytes; we just stop at the first NUL or
    // non-printable to keep logs sane.
    let end = b.length;
    for (let i = 0; i < b.length; i++) {
        const c = b[i]!;
        if (c < 0x20 || c > 0x7e) {
            end = i;
            break;
        }
    }
    return new TextDecoder("ascii").decode(b.subarray(0, end));
}
