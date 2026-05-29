// v2 enrollment challenge file the citizen signs in Diia (task #33).
//
// Replaces the v2.1 "label || epoch_day_be8" binding (see
// `enrollmentBinding.ts`) with a session-bound JSON payload that pins
// the exact `blindedInput` the client will later send to
// `/oprf/blind-eval`. The OPRF service rebuilds these same bytes from
// the request and verifies `sha256(challengeBytes) == p7s
// signedAttrs.messageDigest`, so a citizen cannot reuse a .p7s signed
// over a different blindedInput nor a stale challenge from a previous
// session.
//
// Wire format — byte-exact, the OPRF agent reconstructs the same shape
// independently. UTF-8 bytes of compact JSON, NO whitespace anywhere,
// NO trailing newline, fixed key order:
//
//   {"intent":"crisp-qes-enroll-v2","epoch":"<epoch>","blindedInput":"0x<64hex>"}
//
//   • intent       — literal string, hardcoded
//   • epoch        — `config.oprfEnrollmentEpoch` ("v2-2026" today)
//   • blindedInput — lowercase, 0x-prefixed, exactly 64 hex chars
//                    (32 bytes of ristretto255 point encoding)
//
// We do NOT use `JSON.stringify` here — its output is allowed to vary in
// key order or escape representation depending on the JS engine. The
// contract with the OPRF service is byte-exact, so we hand-build the
// string and TextEncoder it.

const INTENT = "crisp-qes-enroll-v2";

function toHex32(b: Uint8Array): string {
    if (b.length !== 32) {
        throw new RangeError(
            `buildChallengeBytes: blindedInput must be 32 bytes, got ${b.length}`,
        );
    }
    let s = "0x";
    for (let i = 0; i < b.length; i++) {
        s += b[i]!.toString(16).padStart(2, "0");
    }
    return s;
}

/**
 * Build the exact byte sequence the citizen signs in Diia for v2
 * enrollment. Output is the UTF-8 encoding of:
 *
 *   {"intent":"crisp-qes-enroll-v2","epoch":"<epoch>","blindedInput":"0x<64hex>"}
 *
 * Both sides (web client, OPRF service) MUST emit identical bytes for
 * the same `(blindedInput, epoch)`.
 */
export function buildChallengeBytes(
    blindedInput: Uint8Array,
    epoch: string,
): Uint8Array {
    const hex = toHex32(blindedInput);
    const json =
        `{"intent":"${INTENT}","epoch":"${epoch}","blindedInput":"${hex}"}`;
    return new TextEncoder().encode(json);
}

export const CHALLENGE_INTENT = INTENT;
