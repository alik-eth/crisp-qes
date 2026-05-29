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
//   * Payload binding (v2.1-prod): when the caller passes
//     `expectedDigest`, the inner `messageDigest` attribute extracted from
//     `signedAttrs` is byte-compared against it. The caller is expected to
//     have computed `sha256(canonical_binding_bytes)` where the canonical
//     binding is the UTF-8 JSON
//       {"intent":"crisp-qes-enroll-v2","epoch":"<epoch>","blindedInput":"0x…"}
//     with that EXACT key order, no whitespace, no trailing newline. This
//     binds a captured .p7s to one specific enrollment intent + blinded
//     input; passing `null` disables the check (back-compat for tests
//     against fixtures whose binding source isn't reconstructible).

import { parseP7s, type ParsedP7s } from "@crisp-qes/sdk";

import { extractDOB } from "./dob.js";

const TINUA_PREFIX = new TextEncoder().encode("TINUA-");

/**
 * The canonical enrollment-binding artifact the citizen signs in Diia.
 *
 * Wire format — UTF-8 bytes of compact JSON, NO whitespace, NO trailing
 * newline, keys in this EXACT order: `intent`, `epoch`, `blindedInput`:
 *
 *   {"intent":"crisp-qes-enroll-v2","epoch":"<epoch>","blindedInput":"0x<64-hex>"}
 *
 * Server-side reconstruction MUST be byte-exact — anything else breaks
 * the messageDigest binding. The web client builds the same bytes from
 * the same components.
 *
 * `blindedInput` is the request field as received: a "0x"-prefixed
 * lowercase hex of exactly 64 chars (32 bytes). The function asserts
 * that shape and fail-closes on anything else.
 */
export function buildEnrollmentBindingBytes(
    epoch: string,
    blindedInputHex: string,
): Uint8Array {
    if (!/^0x[0-9a-f]{64}$/.test(blindedInputHex)) {
        throw new AttestationError(
            "PayloadMismatch",
            "buildEnrollmentBindingBytes: blindedInput must be a " +
                "lowercase 0x-prefixed 64-hex-char string",
        );
    }
    if (epoch.length === 0 || /["\\]/.test(epoch)) {
        throw new AttestationError(
            "PayloadMismatch",
            "buildEnrollmentBindingBytes: epoch must be non-empty and " +
                'must not contain `"` or `\\`',
        );
    }
    return new TextEncoder().encode(
        `{"intent":"crisp-qes-enroll-v2","epoch":"${epoch}","blindedInput":"${blindedInputHex}"}`,
    );
}

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

export interface VerifyAttestationOptions {
    /**
     * sha256 of the canonical enrollment-binding bytes — see header.
     * When non-null, the inner `messageDigest` attribute extracted from
     * `signedAttrs` must equal these bytes verbatim, otherwise the call
     * throws `AttestationError("PayloadMismatch", …)`. Passing `null`
     * skips the check (back-compat for fixture-based tests).
     */
    expectedDigest: Uint8Array | null;
}

export function verifyAttestation(
    p7sBytes: Uint8Array,
    opts: VerifyAttestationOptions = { expectedDigest: null },
): VerifiedAttestation {
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

    // Payload-binding check (v2.1-prod): bind the .p7s to this exact
    // enrollment intent + blinded input. The caller computes
    // `sha256(canonical_binding_bytes)` from the request and the SDK
    // already exposes `parsed.messageDigest` (the 32-byte value of the
    // PKCS#9 messageDigest attribute inside signedAttrs).
    if (opts.expectedDigest !== null) {
        if (opts.expectedDigest.length !== 32) {
            throw new AttestationError(
                "PayloadMismatch",
                `expectedDigest must be 32 bytes (got ${opts.expectedDigest.length})`,
            );
        }
        if (!bytesEq(parsed.messageDigest, opts.expectedDigest)) {
            throw new AttestationError(
                "PayloadMismatch",
                "signedAttrs.messageDigest does not match the expected " +
                    "sha256(enrollment binding) for this request",
            );
        }
    }

    // TODO(v2.1-prod): verify the cert chain against the Diia trust root.
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
