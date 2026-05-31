// Build the enroll_commit_v2 circuit witness from a REAL Diia .p7s.
//
// This is the real-cert counterpart to buildEnrollWitness() in
// lib/v3enroll.ts (which builds the same InputMap from a SYNTHETIC cert). It
// reuses the SAME proven cert parser the v2 verify flow uses (parseP7s from
// @crisp-qes/sdk + the leaf-cert / RNOKPP / DOB helpers), and emits an
// InputMap whose field layout MIRRORS gen-enroll-commit-v2-witness.mjs exactly.
//
// =====================================================================
// WHAT THE RESIZED enroll_commit_v2 CIRCUIT EXPECTS (CERT_LEN = 2048)
// =====================================================================
//
//   pubkey_x[32], pubkey_y[32]  — leaf P-256 pubkey affine coords (BE bytes).
//   sig[64]                     — leaf ECDSA over signedAttrs, r||s, LOW-S.
//   signed_attrs[512]           — the CMS hash-input signedAttrs (zero-padded),
//                                 sha256'd IN-CIRCUIT (sha256_var) to derive the
//                                 ECDSA message digest + the bound messageDigest.
//   signed_attrs_len            — true byte length of signedAttrs (pre-pad).
//   msg_digest_off              — offset of the PKCS#9 messageDigest 04 20 OCTET
//                                 STRING header inside signed_attrs.
//   cert[2048]                  — the leaf-cert DER buffer (zero-padded), the
//                                 buffer the circuit byte-reads RNOKPP + DOB from.
//   rnokpp_oid_off              — offset where the RNOKPP run begins inside
//                                 cert[] (06 03 55 04 05 13 10 "TINUA-" <10d>).
//   dob_off                     — offset of 8 contiguous ASCII DOB digits.
//   today[8]                    — public YYYYMMDD ASCII (age check).
//   c1..c4, h0[6], h1[6]        — SvdW suite constants + per-map sqrt hints.
//   r_lo, r_hi                  — blinding scalar limbs (private).
//
// The circuit derives u0,u1 = hash_to_field(RNOKPP) fully in-circuit, so the
// witness carries ONLY the SvdW hints (which still need JS-computed u0,u1) +
// the cert/ECDSA material + the scalar r. signedAttrs is hashed IN-CIRCUIT
// (sha256_var); ECDSA verify binds (pubkey, sig, sha256(signedAttrs)) and the
// circuit also returns the bound messageDigest at msg_digest_off as public
// words so the OPRF service can pin it to sha256(challengeBytes).
//
// =====================================================================
// RNOKPP ENCODING — REAL DIIA (option A, landed)
// =====================================================================
//
// The enroll_commit_v2 circuit asserts the RNOKPP appears as the EXACT run
//   06 03 55 04 05      (OID 2.5.4.5, subject serialNumber)
//   13 10               (PrintableString, length 16)
//   54 49 4E 55 41 2D   ("TINUA-")
//   <10 ASCII digits>   (the RNOKPP)
// matching a REAL Diia subject serialNumber. The "TINUA-" prefix is asserted
// but NOT hashed; only the 10 trailing digits feed hash_to_field, identical to
// extractRnokpp() (which strips "TINUA-"). findRnokppOidOffset() below locates
// exactly this run and throws a labelled error if absent.
//
// Everything (leaf pubkey, signedAttrs sha256, low-s signature, RNOKPP/DOB
// digit location, SvdW hints, scalar) is real-cert-ready and exercised below
// against a synthetic Diia-shaped cert in p7sWitness.test.ts.

import type { InputMap } from "@noir-lang/noir_js";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { parseP7s, type ParsedP7s } from "@crisp-qes/sdk";
import { extractRnokpp } from "./rnokpp.js";
import {
    N,
    Point,
    SVDW_CONSTS,
    hashToField2,
    mapToCurveSvdW,
    scalarLimbs,
    type Pt,
    type SvdWHints,
} from "./grumpkin.js";

// Must equal the resized circuit's global CERT_LEN in
// circuits/enroll_commit_v2/src/main.nr.
export const CERT_LEN = 2048;

// Must equal the circuit global SA_LEN in enroll_commit_v2/src/main.nr.
export const SA_LEN = 2048;

// OID 2.5.4.5 (subject serialNumber): 06 03 55 04 05.
const RNOKPP_OID = new Uint8Array([0x06, 0x03, 0x55, 0x04, 0x05]);
// PrintableString tag + length-16 + "TINUA-" — the exact prefix the (updated,
// option-A) enroll_commit_v2 circuit asserts immediately before the 10 RNOKPP
// digit bytes. A real Diia subject serialNumber is "TINUA-<10 digits>" (16
// bytes => PrintableString tag 0x13, length 0x10). The circuit asserts the
// "TINUA-" prefix but does NOT hash it; only the 10 trailing digits feed
// hash_to_field (matching extractRnokpp(), which strips "TINUA-").
const RNOKPP_STR_PREFIX = new Uint8Array([
    0x13, 0x10, 0x54, 0x49, 0x4e, 0x55, 0x41, 0x2d, // 13 10 'T''I''N''U''A''-'
]);
// Diia DOB attribute OID (1.2.804.2.1.1.1.11.1.4.11.1), used to disambiguate
// the YYYYMMDD digits from any other 8-digit run in the cert. DER-encoded.
const DOB_ATTRIBUTE_OID = new Uint8Array([
    0x06, 0x0c, 0x2a, 0x86, 0x67, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x01, 0x04,
    0x0b, 0x01,
]);

const dec = (v: bigint): string => v.toString();
const u8arr = (u8: Uint8Array): string[] =>
    Array.from(u8).map((b) => b.toString());
const hintArr = (h: SvdWHints): string[] => [
    dec(h.inv_t),
    dec(h.e1),
    dec(h.w1),
    dec(h.e2),
    dec(h.w2),
    dec(h.sqrt_x),
];

function indexOf(hay: Uint8Array, needle: Uint8Array, from = 0): number {
    if (needle.length === 0) return from;
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
 * Locate the byte offset inside `certDer` where the circuit's RNOKPP run
 * begins: 06 03 55 04 05  13 0A  <10 digits>. Returns the offset of the 0x06,
 * i.e. the value the circuit takes as `rnokpp_oid_off`.
 *
 * Real Diia certs encode the subject serialNumber as "TINUA-<RNOKPP>"
 * (PrintableString length 16 → 13 10), so the located run is
 *   06 03 55 04 05  13 10  54 49 4E 55 41 2D  <10 digits>
 * matching the (option-A) enroll_commit_v2 circuit. Throws a clearly-labelled
 * error if no such run is present.
 */
export function findRnokppOidOffset(certDer: Uint8Array): number {
    const P = RNOKPP_STR_PREFIX; // 13 10 "TINUA-"
    let from = 0;
    for (;;) {
        const oidAt = indexOf(certDer, RNOKPP_OID, from);
        if (oidAt < 0) break;
        const strAt = oidAt + RNOKPP_OID.length;
        let prefixOk = strAt + P.length <= certDer.length;
        for (let k = 0; prefixOk && k < P.length; k++) {
            if (certDer[strAt + k] !== P[k]) prefixOk = false;
        }
        if (prefixOk) {
            const digitsAt = strAt + P.length;
            let allDigits = digitsAt + 10 <= certDer.length;
            for (let k = 0; allDigits && k < 10; k++) {
                const b = certDer[digitsAt + k]!;
                if (b < 0x30 || b > 0x39) allDigits = false;
            }
            if (allDigits) return oidAt;
        }
        from = oidAt + 1;
    }
    throw new Error(
        'p7sWitness: no RNOKPP run (06 03 55 04 05 13 10 "TINUA-" <10 digits>) ' +
            "found in cert DER. Expected a Diia subject serialNumber encoded as " +
            '"TINUA-<10 digits>" matching the enroll_commit_v2 circuit.',
    );
}

/**
 * Locate the byte offset of the 8 contiguous ASCII DOB digits (YYYYMMDD)
 * inside `certDer`, returned as the circuit's `dob_off`. The digits are the
 * leading 8 chars of the Diia DOB PrintableString "YYYYMMDD-XXXXX" carried in
 * the SubjectDirectoryAttributes extension; we scan forward from the DOB
 * attribute OID so we don't false-match an unrelated 8-digit run. `dobDigits`
 * is the expected YYYYMMDD string (from extractDOB-equivalent parsing); we
 * verify the bytes at the located offset match it exactly.
 */
export function findDobOffset(certDer: Uint8Array, dobDigits: string): number {
    if (!/^\d{8}$/.test(dobDigits)) {
        throw new Error(
            `p7sWitness: dobDigits must be 8 ASCII digits, got "${dobDigits}"`,
        );
    }
    const want = new TextEncoder().encode(dobDigits);
    // Prefer searching after the Diia DOB attribute OID to disambiguate.
    const oidAt = indexOf(certDer, DOB_ATTRIBUTE_OID, 0);
    const from = oidAt >= 0 ? oidAt + DOB_ATTRIBUTE_OID.length : 0;
    let at = indexOf(certDer, want, from);
    if (at < 0) at = indexOf(certDer, want, 0); // fall back to a full scan
    if (at < 0) {
        throw new Error(
            "p7sWitness: DOB digits not found in cert DER (expected the leading " +
                "YYYYMMDD of the SubjectDirectoryAttributes DOB string).",
        );
    }
    return at;
}

/**
 * Normalize a P-256 ECDSA (r, s) to LOW-S and serialize to the 64-byte
 * compact r||s form Noir's std::ecdsa_secp256r1::verify_signature requires.
 * Noir REJECTS high-s signatures; Diia/most signers may emit either, so this
 * is mandatory.
 */
export function lowSCompactSig(r: bigint, s: bigint): Uint8Array {
    // Reconstruct a noble Signature, force low-s, emit compact (r||s).
    const sig = new p256.Signature(r, s).normalizeS();
    return sig.toCompactRawBytes();
}

export interface P7sEnrollWitness {
    witness: InputMap; // for enroll_commit_v2 (resized, CERT_LEN=2048)
    r: bigint; // blinding scalar — needed later for unblind
    M: Pt; // public blinded element = r * H2C(RNOKPP)
    rnokpp: string; // the 10-digit RNOKPP (from the proven extractRnokpp path)
}

/**
 * Today as YYYYMMDD ASCII (UTC) — the public age-check input. Mirrors
 * v3enroll.ts's todayYYYYMMDD.
 */
export function todayYYYYMMDD(now: Date = new Date()): string {
    const y = now.getUTCFullYear().toString().padStart(4, "0");
    const m = (now.getUTCMonth() + 1).toString().padStart(2, "0");
    const d = now.getUTCDate().toString().padStart(2, "0");
    return `${y}${m}${d}`;
}

function randomScalar(): bigint {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    let v = 0n;
    for (const b of buf) v = (v << 8n) | BigInt(b);
    return (v % (N - 1n)) + 1n;
}

/**
 * Build the enroll_commit_v2 witness from a REAL Diia .p7s.
 *
 * @param p7sBytes  the raw .p7s the citizen signed in Diia.
 * @param dobDigits the citizen's DOB as YYYYMMDD (8 ASCII digits). In the v2
 *        flow this comes from the proven SubjectDirectoryAttributes parse
 *        (`@crisp-qes/sdk` / oprf `extractDOB`); the caller passes it through
 *        so this module stays parser-agnostic and unit-testable.
 * @param opts.r    fixed blinding scalar (tests pass a constant; production
 *                  leaves it undefined for a fresh random scalar).
 * @param opts.now  clock injection for the age field (tests pin it).
 *
 * REUSES parseP7s exactly as Verify.tsx does:
 *   - parsed.pubkey {x,y}          -> pubkey_x / pubkey_y
 *   - parsed.signature {r,s}       -> low-s normalized -> sig
 *   - parsed.signedAttrs           -> signed_attrs (padded) hashed in-circuit
 *   - parsed.messageDigestOffset   -> msg_digest_off (04 20 header offset)
 *   - parsed.leafCertDer           -> cert buffer (RNOKPP + DOB live here)
 *   - extractRnokpp(parsed)        -> the 10-digit RNOKPP fed to hash_to_field
 */
export function buildP7sEnrollWitness(
    p7sBytes: Uint8Array,
    dobDigits: string,
    opts: { r?: bigint; now?: Date } = {},
): P7sEnrollWitness {
    const parsed: ParsedP7s = parseP7s(p7sBytes);

    // --- RNOKPP (proven path) -------------------------------------------
    // extractRnokpp strips the "TINUA-" prefix; this is the SAME 10-digit
    // value the on-chain commitment must bind to.
    const rnokpp = extractRnokpp(parsed);
    if (!/^\d{10}$/.test(rnokpp)) {
        throw new Error(
            `p7sWitness: extractRnokpp returned non-10-digit value "${rnokpp}"`,
        );
    }

    // --- cert buffer (zero-padded to CERT_LEN) --------------------------
    // The leaf cert DER is the buffer the circuit byte-reads RNOKPP + DOB
    // from. (signedAttrs is the SIGNED blob; RNOKPP/DOB live in the cert.)
    const certDer = parsed.leafCertDer;
    if (certDer.length > CERT_LEN) {
        throw new Error(
            `p7sWitness: leaf cert DER (${certDer.length} B) exceeds CERT_LEN ` +
                `(${CERT_LEN}); bump CERT_LEN in the circuit + here.`,
        );
    }
    const cert = new Uint8Array(CERT_LEN);
    cert.set(certDer, 0);

    // Witnessed offsets (the circuit makes no fixed-offset assumption).
    const rnokppOff = findRnokppOidOffset(cert);
    const dobOff = findDobOffset(cert, dobDigits);

    // --- ECDSA material -------------------------------------------------
    const pubX = i2osp32(parsed.pubkey.x);
    const pubY = i2osp32(parsed.pubkey.y);
    const sig = lowSCompactSig(parsed.signature.r, parsed.signature.s);

    // --- bound-challenge fields (v3) ------------------------------------
    // The circuit hashes signed_attrs in-circuit (sha256_var) and extracts the
    // PKCS#9 messageDigest at msg_digest_off. parseP7s already re-tags
    // signedAttrs to the CMS hash-input SET form and locates the digest value.
    if (parsed.signedAttrs.length > SA_LEN) {
        throw new Error(
            `p7sWitness: signedAttrs (${parsed.signedAttrs.length} B) exceeds SA_LEN (${SA_LEN}); bump both.`,
        );
    }
    const signedAttrsPadded = new Uint8Array(SA_LEN);
    signedAttrsPadded.set(parsed.signedAttrs, 0);
    // messageDigestOffset points at the 32-byte value; the circuit expects the
    // 0x04 0x20 OCTET STRING header, i.e. value offset minus 2.
    const msgDigestOff = parsed.messageDigestOffset - 2;
    if (
        signedAttrsPadded[msgDigestOff] !== 0x04 ||
        signedAttrsPadded[msgDigestOff + 1] !== 0x20
    ) {
        throw new Error(
            "p7sWitness: messageDigest is not a 04 20 OCTET STRING at the expected offset",
        );
    }

    // --- hash_to_field over the RNOKPP (for SvdW hints) -----------------
    const rnokppBytes = new TextEncoder().encode(rnokpp);
    const [u0, u1] = hashToField2(rnokppBytes);
    const m0 = mapToCurveSvdW(u0);
    const m1 = mapToCurveSvdW(u1);
    const Hpt = m0.point.add(m1.point);

    const r = opts.r ?? randomScalar();
    const M = Hpt.multiply(r);

    const { c1, c2, c3, c4 } = SVDW_CONSTS;
    const { lo, hi } = scalarLimbs(r);
    const today = todayYYYYMMDD(opts.now);

    const witness: InputMap = {
        pubkey_x: u8arr(pubX),
        pubkey_y: u8arr(pubY),
        sig: u8arr(sig),
        signed_attrs: u8arr(signedAttrsPadded),
        signed_attrs_len: parsed.signedAttrs.length.toString(),
        msg_digest_off: msgDigestOff.toString(),
        cert: u8arr(cert),
        rnokpp_oid_off: rnokppOff.toString(),
        dob_off: dobOff.toString(),
        today: Array.from(today).map((c) => c.charCodeAt(0).toString()),
        c1: dec(c1),
        c2: dec(c2),
        c3: dec(c3),
        c4: dec(c4),
        h0: hintArr(m0.hints),
        h1: hintArr(m1.hints),
        r_lo: dec(lo),
        r_hi: dec(hi),
    };

    return { witness, r, M, rnokpp };
}

// bigint -> 32-byte big-endian (matches the circuit's [u8;32] pubkey coords).
function i2osp32(v: bigint): Uint8Array {
    const o = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) {
        o[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return o;
}

// Re-export for tests / parity with v3enroll.ts.
export { Point };
