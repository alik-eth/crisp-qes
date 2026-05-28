// v2.1 enrollment binding file the citizen signs in Diia.
//
// Schema (28 bytes):
//
//   "CRISP_QES_V2_ENROLL::" (20)  ||  epoch_day_be8 (8)
//
//   where epoch_day = floor(unix_seconds / 86400)
//
// Purpose: give the citizen a concrete, human-readable artifact to sign in
// Diia («Накласти КЕП»). The signed .p7s the user uploads back is parsed
// for the RNOKPP (from subjectSerial); the binding bytes themselves are
// currently NOT checked against `signedAttrs.messageDigest` by the v2
// OPRF service — see `packages/v2-oprf/src/attestation.ts` for the TODO
// flagging that as v2.1-prod follow-up work. The mirrored MVP pattern
// (commit J/L on the Sign page) lives in `packages/web/src/lib/messageDigest.ts`.
//
// We intentionally do NOT include `blindedM` here. Computing it would need
// the citizen's RNOKPP, which lives inside the .p7s subjectSerial — i.e.
// they don't have RNOKPP available before the upload step. Once the OPRF
// service moves to threshold + per-RNOKPP attestation in v3, blinding
// will happen client-side BEFORE upload and the binding shape can grow.

const LABEL = new TextEncoder().encode("CRISP_QES_V2_ENROLL::");
const SECONDS_PER_DAY = 86_400;

export function currentEnrollmentEpochDay(now: Date = new Date()): number {
    return Math.floor(now.getTime() / 1000 / SECONDS_PER_DAY);
}

function epochDayBe8(day: number): Uint8Array {
    const out = new Uint8Array(8);
    let v = BigInt(day);
    for (let i = 7; i >= 0; i--) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return out;
}

export function buildEnrollmentBindingBytes(now: Date = new Date()): Uint8Array {
    const epoch = epochDayBe8(currentEnrollmentEpochDay(now));
    const buf = new Uint8Array(LABEL.length + epoch.length);
    buf.set(LABEL, 0);
    buf.set(epoch, LABEL.length);
    return buf;
}
