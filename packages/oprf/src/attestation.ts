// Diia QES (.p7s) attestation verification.
//
// The OPRF service is allowed to BlindEvaluate only if the citizen produces
// a fresh Diia QES over the blinded input bundle (RNOKPP -> X -> M = r*X is
// the citizen's responsibility; the server never sees X or RNOKPP). The
// .p7s is the canonical CAdES-BES envelope Diia signs, which we already
// parse via `@crisp-qes/sdk`'s `parseP7s`.
//
// v2.1 gate checks performed here:
//
//   * Subject serial prefix is "TINUA-" (Diia tag).
//   * ECDSA-P256 verify of the leaf cert's signature over signedAttrs
//     (task #28 — proves the citizen's key actually signed this envelope).
//   * Chain-of-trust verify against a configured Diia LOTL trust root
//     (task #27 — proves the leaf cert was issued by a trusted Ukrainian
//     QTSP). Currently a single-level chain only (leaf -> trusted CA, or
//     leaf -> intermediate -> trusted CA when the .p7s bundles both).
//   * signingTime freshness window (task #30 — rejects replays of old
//     .p7s envelopes; window configurable via SIGNING_TIME_MAX_AGE_SEC).
//
// Still TODO (out of scope for this commit):
//
// Still TODO (out of scope for this commit):
//
//   * Multi-level chain (leaf -> intermediate -> root CA). The Diia bundle
//     in `@crisp-qes/lotl-flattener` carries the intermediates that issue
//     citizen leaves; matching those directly is sufficient for v2 demo.

import { p256 } from "@noble/curves/nist.js";
import { Certificate } from "pkijs";

import { parseP7s, type ParsedP7s } from "@crisp-qes/sdk";

import { extractDOB } from "./dob.js";

const TINUA_PREFIX = new TextEncoder().encode("TINUA-");

/** Default skew tolerance for signingTime values dated in the future. */
const DEFAULT_CLOCK_SKEW_SEC = 60;

export interface TrustedCa {
    /** DER bytes of the trusted CA certificate. */
    certDer: Uint8Array;
    /** Canonical SubjectPublicKeyInfo DER bytes (cached for verification). */
    spkiDer: Uint8Array;
    /** Subject DN DER bytes (cached for issuer-DN matching). */
    subjectDer: Uint8Array;
    /** Affine P-256 pubkey (cached). All Diia CAs are P-256. */
    pubkey: { x: bigint; y: bigint };
    /** Human-readable common name, used in logs. */
    commonName: string;
}

export interface VerifyAttestationOpts {
    /** Trusted Diia QTSP CAs. Empty list means chain verification is skipped. */
    trustRoots: TrustedCa[];
    /**
     * Reject signingTime older than this many seconds vs `now`. Set to 0 to
     * disable the freshness check entirely (dev only).
     */
    signingTimeMaxAgeSec: number;
    /** Tolerate signingTime values up to N seconds into the future. */
    signingTimeClockSkewSec?: number;
    /** Reference clock; defaults to wall clock. Injected for tests. */
    now?: Date;
    /**
     * sha256 of the canonical enrollment-binding bytes — see
     * `buildEnrollmentBindingBytes`. When non-null, the inner
     * `messageDigest` attribute extracted from `signedAttrs` must equal
     * these bytes verbatim, otherwise we throw
     * `AttestationError("PayloadMismatch", …)`. Pass `null` to disable
     * the check (back-compat for tests against fixtures whose binding
     * source isn't reconstructible).
     */
    expectedDigest?: Uint8Array | null;
}

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
    /** signingTime authenticated attribute, surfaced for audit logs. */
    signingTime: Date | null;
    /** Subject CN of the trusted CA that the leaf chained to, for logs. */
    chainAnchor: string | null;
}

export function verifyAttestation(
    p7sBytes: Uint8Array,
    opts: VerifyAttestationOpts,
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

    // Task #28 — ECDSA-P256 verify of the leaf's signature over signedAttrs.
    // The pubkey lives on the leaf cert's SPKI; the signature value lives on
    // SignerInfo.signature (parsed as DER ECDSA-Sig-Value by the SDK).
    verifyLeafSignatureOverSignedAttrs(parsed);

    // Task #27 — chain-of-trust against the configured Diia LOTL roots.
    // Skipped only when the operator deliberately ran without trust roots
    // (OPRF_TRUST_ROOT_REQUIRED=false) — config.ts logs a loud warning at
    // startup if so.
    const chainAnchor = opts.trustRoots.length > 0
        ? verifyChain(parsed, opts.trustRoots)
        : null;

    // Task #30 — signingTime freshness. Disabled when maxAge=0 (dev/tests).
    if (opts.signingTimeMaxAgeSec > 0) {
        verifySigningTimeFreshness(
            parsed.signingTime,
            opts.signingTimeMaxAgeSec,
            opts.signingTimeClockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC,
            opts.now ?? new Date(),
        );
    }

    // Task #29 — messageDigest payload-binding. Bind the .p7s to THIS
    // enrollment intent + blinded input. Caller computes
    // `sha256(buildEnrollmentBindingBytes(epoch, blindedInputHex))` from
    // the request; we compare against `parsed.messageDigest` (the 32-byte
    // value of the PKCS#9 messageDigest attribute inside signedAttrs).
    // Passing `expectedDigest: null` disables the check for back-compat
    // with fixtures whose binding source isn't reconstructible.
    if (opts.expectedDigest != null) {
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


    const dob = extractDOB(parsed.leafCertDer);
    return {
        subjectSerialAscii: bytesToAscii(parsed.subjectSerial),
        subjectSerial: parsed.subjectSerial,
        dob,
        signingTime: parsed.signingTime,
        chainAnchor,
    };
}

// ── ECDSA verify (task #28) ──────────────────────────────────────────────

function verifyLeafSignatureOverSignedAttrs(parsed: ParsedP7s): void {
    const pubkeyBytes = uncompressedP256(parsed.pubkey);
    const sig = derSig(parsed.signature);
    // We feed the pre-computed sha256(signedAttrs) directly — p256.verify's
    // `prehash:false` skips the internal sha256 step. `lowS:false` because
    // CAdES signatures from Diia are not normalized to low-S.
    const ok = p256.verify(sig, parsed.signedAttrsSha256, pubkeyBytes, {
        prehash: false,
        lowS: false,
    });
    if (!ok) {
        throw new AttestationError(
            "SignatureInvalid",
            "leaf cert ECDSA over signedAttrs did not verify",
        );
    }
}

// ── Chain-of-trust (task #27) ────────────────────────────────────────────

function verifyChain(
    parsed: ParsedP7s,
    trustRoots: TrustedCa[],
): string {
    // Two layouts we accept:
    //   (a) leaf-only .p7s — find a trust root whose subject DN matches the
    //       leaf's issuer DN, then ECDSA-verify leafCertSignature against
    //       that root's pubkey.
    //   (b) leaf + intermediate — match the intermediate's SPKI against the
    //       trust set (single-level chain), then ECDSA-verify
    //       leafCertSignature against the intermediate's pubkey. (We trust
    //       the intermediate transitively because its SPKI is in the set.)
    if (parsed.intermediateCertDer && parsed.intermediatePubkey) {
        const interSpki = parsed.intermediateSpkiDer!;
        const anchor = trustRoots.find((t) => bytesEq(t.spkiDer, interSpki));
        if (!anchor) {
            throw new AttestationError(
                "ChainInvalid",
                "intermediate cert is not in the configured Diia trust set",
            );
        }
        verifyCertSignature(
            parsed.leafTbsBytes,
            parsed.leafCertSignature,
            parsed.intermediatePubkey,
        );
        return anchor.commonName;
    }

    // Leaf-only — look up by issuer DN.
    const leafIssuerDer = extractIssuerDer(parsed.leafCertDer);
    const anchor = trustRoots.find((t) => bytesEq(t.subjectDer, leafIssuerDer));
    if (!anchor) {
        throw new AttestationError(
            "ChainInvalid",
            "leaf cert issuer is not in the configured Diia trust set",
        );
    }
    verifyCertSignature(
        parsed.leafTbsBytes,
        parsed.leafCertSignature,
        anchor.pubkey,
    );
    return anchor.commonName;
}

function verifyCertSignature(
    tbsBytes: Uint8Array,
    sig: { r: bigint; s: bigint },
    pubkey: { x: bigint; y: bigint },
): void {
    const pubkeyBytes = uncompressedP256(pubkey);
    const sigBytes = derSig(sig);
    // p256.verify with prehash:true hashes tbsBytes with sha256 internally —
    // matches the standard X.509 sha256WithECDSA OID used by Diia.
    const ok = p256.verify(sigBytes, tbsBytes, pubkeyBytes, {
        prehash: true,
        lowS: false,
    });
    if (!ok) {
        throw new AttestationError(
            "ChainInvalid",
            "leaf cert signature does not verify against the trusted CA pubkey",
        );
    }
}

/**
 * Parse the cert via pkijs and return canonical DER of the issuer Name. We
 * reuse pkijs here (already a dep) rather than hand-walking the TBS because
 * the issuer Name encoding is non-trivial (RDN set ordering, attribute
 * value DirectoryString CHOICE).
 */
function extractIssuerDer(certDer: Uint8Array): Uint8Array {
    const ab = new ArrayBuffer(certDer.byteLength);
    new Uint8Array(ab).set(certDer);
    const cert = Certificate.fromBER(ab);
    return new Uint8Array(cert.issuer.toSchema().toBER(false));
}

// ── Trust-root loading (called by config.ts at startup) ──────────────────

/**
 * Build a TrustedCa record from a CA cert DER. Throws on a non-P256 SPKI
 * since the Diia QTSP issues only ECDSA-P256 leaves today; multi-algorithm
 * trust roots are a v3 concern.
 */
export function buildTrustedCa(certDer: Uint8Array): TrustedCa {
    const ab = new ArrayBuffer(certDer.byteLength);
    new Uint8Array(ab).set(certDer);
    const cert = Certificate.fromBER(ab);
    const algOid = cert.subjectPublicKeyInfo.algorithm.algorithmId;
    if (algOid !== "1.2.840.10045.2.1") {
        throw new Error(
            `buildTrustedCa: only ECDSA SPKI is supported (got OID ${algOid})`,
        );
    }
    const pkBytes = new Uint8Array(
        cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
    );
    if (pkBytes.length !== 65 || pkBytes[0] !== 0x04) {
        throw new Error(
            "buildTrustedCa: SPKI subjectPublicKey is not a 65-byte uncompressed P-256 point",
        );
    }
    const x = bytesToBigInt(pkBytes.subarray(1, 33));
    const y = bytesToBigInt(pkBytes.subarray(33, 65));
    const spkiDer = new Uint8Array(
        cert.subjectPublicKeyInfo.toSchema().toBER(false),
    );
    const subjectDer = new Uint8Array(cert.subject.toSchema().toBER(false));
    // Try to surface a human-readable CN for logs.
    let commonName = "<unknown>";
    for (const rdn of cert.subject.typesAndValues) {
        if (rdn.type === "2.5.4.3") {
            const v = (rdn.value as { valueBlock?: { value?: unknown } }).valueBlock
                ?.value;
            if (typeof v === "string") commonName = v;
            break;
        }
    }
    return { certDer, spkiDer, subjectDer, pubkey: { x, y }, commonName };
}

/**
 * Parse a base64-encoded concatenation of PEM-encoded CA certs into a list
 * of TrustedCa records. The base64 wrapper is so operators can pass a
 * multi-cert bundle through a single env var without dealing with shell
 * newline escaping.
 */
export function parseTrustRootEnv(b64: string): TrustedCa[] {
    const decoded = Buffer.from(b64.trim(), "base64").toString("utf8");
    return parseTrustRootPemBundle(decoded);
}

/** Parse a PEM bundle (concatenated `-----BEGIN CERTIFICATE-----` blocks). */
export function parseTrustRootPemBundle(pem: string): TrustedCa[] {
    const out: TrustedCa[] = [];
    const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(pem)) !== null) {
        const body = m[1]!.replace(/\s+/g, "");
        if (body.length === 0) continue;
        const der = new Uint8Array(Buffer.from(body, "base64"));
        out.push(buildTrustedCa(der));
    }
    if (out.length === 0) {
        throw new Error(
            "parseTrustRootPemBundle: no PEM CERTIFICATE blocks found",
        );
    }
    return out;
}

// ── signingTime freshness (task #30) ─────────────────────────────────────

function verifySigningTimeFreshness(
    signingTime: Date | null,
    maxAgeSec: number,
    clockSkewSec: number,
    now: Date,
): void {
    if (signingTime === null) {
        throw new AttestationError(
            "MissingSigningTime",
            "signed attributes lack signingTime (OID 1.2.840.113549.1.9.5)",
        );
    }
    const deltaSec = (now.getTime() - signingTime.getTime()) / 1000;
    if (deltaSec > maxAgeSec) {
        throw new AttestationError(
            "Stale",
            `signingTime older than ${maxAgeSec}s (delta=${Math.floor(deltaSec)}s)`,
        );
    }
    if (deltaSec < -clockSkewSec) {
        // Future-dated by more than tolerated skew — clock-skew abuse or a
        // broken signer. Reject as stale so the operator gets a consistent
        // code to alert on.
        throw new AttestationError(
            "Stale",
            `signingTime is ${Math.floor(-deltaSec)}s in the future (exceeds ${clockSkewSec}s skew)`,
        );
    }
}

// ── Error type ───────────────────────────────────────────────────────────

export class AttestationError extends Error {
    constructor(
        readonly code:
            | "P7sParseFailed"
            | "NotDiia"
            | "SignatureInvalid"
            | "ChainInvalid"
            | "MissingSigningTime"
            | "Stale"
            | "PayloadMismatch",
        message: string,
    ) {
        super(message);
        this.name = "AttestationError";
    }
}

// ── byte helpers ─────────────────────────────────────────────────────────

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

function uncompressedP256(pubkey: { x: bigint; y: bigint }): Uint8Array {
    const out = new Uint8Array(65);
    out[0] = 0x04;
    bigIntToBytesBE(pubkey.x, out, 1, 32);
    bigIntToBytesBE(pubkey.y, out, 33, 32);
    return out;
}

function derSig(sig: { r: bigint; s: bigint }): Uint8Array {
    // Compact (r||s) form — p256.verify accepts a 64-byte concatenation by
    // default. Both halves are 32 bytes big-endian.
    const out = new Uint8Array(64);
    bigIntToBytesBE(sig.r, out, 0, 32);
    bigIntToBytesBE(sig.s, out, 32, 32);
    return out;
}

function bigIntToBytesBE(
    v: bigint,
    out: Uint8Array,
    off: number,
    len: number,
): void {
    let x = v;
    for (let i = len - 1; i >= 0; i--) {
        out[off + i] = Number(x & 0xffn);
        x >>= 8n;
    }
}

function bytesToBigInt(b: Uint8Array): bigint {
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v;
}
