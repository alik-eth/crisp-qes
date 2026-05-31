// Build the enroll_commit_v2 circuit witness from a REAL Diia .p7s.
//
// This is the browser/TS counterpart to the validated node generator
// gen-enroll-commit-v2-witness-real.mjs (real-cert validated: the proof
// verified end-to-end via bb.js). It reuses the SAME proven cert parser the v2
// verify flow uses (parseP7s from @crisp-qes/sdk + the leaf-cert / RNOKPP / DOB
// helpers) and emits an InputMap whose field layout MIRRORS that generator
// exactly.
//
// =====================================================================
// WHAT THE DIIA-TRUST-CHAIN enroll_commit_v2 CIRCUIT EXPECTS
// =====================================================================
//
// The circuit was upgraded to verify a Diia CA -> leaf certificate chain
// IN-CIRCUIT. The old free `cert[2048]` buffer is GONE: RNOKPP/DOB/leaf-SPKI
// are now read from the CA-AUTHENTICATED leaf TBS, and a pinned Diia CA key
// must have signed that TBS. main() expects:
//
//   pubkey_x[32], pubkey_y[32]  — leaf P-256 pubkey affine coords (BE bytes).
//   sig[64]                     — leaf ECDSA over signedAttrs, r||s, LOW-S.
//   signed_attrs[SA_LEN]        — the CMS hash-input signedAttrs (zero-padded),
//                                 sha256'd IN-CIRCUIT (sha256_var) to derive the
//                                 ECDSA message digest + the bound messageDigest.
//   signed_attrs_len            — true byte length of signedAttrs (pre-pad).
//   msg_digest_off              — offset of the PKCS#9 messageDigest 04 20 OCTET
//                                 STRING header inside signed_attrs.
//   leaf_tbs[LEAF_TBS_LEN]      — the leaf cert TBSCertificate bytes (zero-
//                                 padded). sha256_var digests exactly
//                                 leaf_tbs_len bytes; the CA signature must
//                                 cover that digest. RNOKPP, DOB and the leaf
//                                 SPKI key are all read FROM HERE (authenticated).
//   leaf_tbs_len                — true byte length of leaf_tbs (pre-pad).
//   ca_pubkey_x[32], ca_pubkey_y[32]
//                               — the issuing Diia CA P-256 key (BE bytes). The
//                                 circuit asserts this is one of the PINNED Diia
//                                 QTSP keys AND that it signed leaf_tbs.
//   leaf_cert_sig[64]           — the CA's ECDSA over sha256(leaf_tbs), r||s LOW-S.
//   leaf_spki_off               — offset in leaf_tbs of X[0] of the leaf SPKI
//                                 uncompressed point; the 0x04 marker sits at
//                                 leaf_spki_off-1 and the circuit binds
//                                 leaf_tbs[off..off+64] == (pubkey_x, pubkey_y).
//   rnokpp_oid_off              — offset (in leaf_tbs) where the RNOKPP run
//                                 begins (06 03 55 04 05 13 10 "TINUA-" <10d>).
//   dob_off                     — offset (in leaf_tbs) of 8 ASCII DOB digits.
//   today[8]                    — public YYYYMMDD ASCII (age check).
//   c1..c4, h0[6], h1[6]        — SvdW suite constants + per-map sqrt hints.
//   r_lo, r_hi                  — blinding scalar limbs (private).
//
// The circuit derives u0,u1 = hash_to_field(RNOKPP) fully in-circuit, so the
// witness carries ONLY the SvdW hints (which still need JS-computed u0,u1) +
// the chain/ECDSA material + the scalar r. signedAttrs is hashed IN-CIRCUIT
// (sha256_var); ECDSA verify binds (pubkey, sig, sha256(signedAttrs)) and the
// circuit also returns the bound messageDigest at msg_digest_off as public
// words so the OPRF service can pin it to sha256(challengeBytes).
//
// =====================================================================
// SOUNDNESS — CA SELECTION IS A LOCAL PRE-CHECK ONLY
// =====================================================================
//
// The builder picks ca_pubkey from a candidate CA set by verifying the leaf
// cert signature, but the CIRCUIT enforces the pin authoritatively against its
// own hard-coded DIIA_PINNED_CA. The candidate set here DEFAULTS to the real
// pinned Diia keys ONLY — no synthetic key is ever shipped in production. The
// set is an injectable parameter SOLELY so unit tests can drive a synthetic
// test CA (whose private key never appears in production). Emitting a CA the
// circuit does not trust simply fails to prove; this pre-check just gives a
// clear, early, labelled error.
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

// Must equal the circuit global LEAF_TBS_LEN in
// circuits/enroll_commit_v2/src/main.nr. Bounds the CA-authenticated leaf TBS
// (real Diia leaf TBS is ~1203 B; 1536 gives headroom).
export const LEAF_TBS_LEN = 1536;

// Must equal the circuit global SA_LEN in enroll_commit_v2/src/main.nr.
export const SA_LEN = 2048;

// Pinned Diia QTSP CA P-256 public keys (the PRODUCTION root set). These MUST
// match circuit DIIA_PINNED_CA. The candidate-CA selection in
// buildP7sEnrollWitness defaults to THIS set — no synthetic key is ever placed
// here (its private key would be a backdoor). Coords are big-endian hex.
export interface PinnedCa {
    name: string;
    x: string; // 32-byte BE hex (no 0x prefix)
    y: string;
}
export const DIIA_PINNED_CA: readonly PinnedCa[] = [
    {
        name: "UA-43395033-2311",
        x: "8500048265e919c1738e873572c1f6443895a0c03985fc71bd96a6f62a53bcc8",
        y: "69d23ca6e6a2a7dc443bbb2a0b914ee35f1c74e282ecd8e6c5287c7a3d4aee10",
    },
    {
        name: "UA-43395033-2503",
        x: "c8b3546f4a34c021a31b3578057d1de304cbf1743a391b2032cd5b7d37184148",
        y: "c2440ea2fba10872b0bc90a92371ad50f59d0e9c0216ed52fd259b8a8cc9ee54",
    },
] as const;

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
 * Locate the byte offset inside `leafTbs` where the circuit's RNOKPP run
 * begins: 06 03 55 04 05  13 10  "TINUA-"  <10 digits>. Returns the offset of
 * the 0x06, i.e. the value the circuit takes as `rnokpp_oid_off`.
 *
 * The buffer is the CA-AUTHENTICATED leaf TBS (not the full cert DER): the
 * circuit only trusts bytes inside [0, leaf_tbs_len). Real Diia certs encode
 * the subject serialNumber as "TINUA-<RNOKPP>" (PrintableString length 16 →
 * 13 10), so the located run is
 *   06 03 55 04 05  13 10  54 49 4E 55 41 2D  <10 digits>
 * matching the enroll_commit_v2 circuit. Throws a clearly-labelled error if no
 * such run is present.
 */
export function findRnokppOidOffset(leafTbs: Uint8Array): number {
    const P = RNOKPP_STR_PREFIX; // 13 10 "TINUA-"
    let from = 0;
    for (;;) {
        const oidAt = indexOf(leafTbs, RNOKPP_OID, from);
        if (oidAt < 0) break;
        const strAt = oidAt + RNOKPP_OID.length;
        let prefixOk = strAt + P.length <= leafTbs.length;
        for (let k = 0; prefixOk && k < P.length; k++) {
            if (leafTbs[strAt + k] !== P[k]) prefixOk = false;
        }
        if (prefixOk) {
            const digitsAt = strAt + P.length;
            let allDigits = digitsAt + 10 <= leafTbs.length;
            for (let k = 0; allDigits && k < 10; k++) {
                const b = leafTbs[digitsAt + k]!;
                if (b < 0x30 || b > 0x39) allDigits = false;
            }
            if (allDigits) return oidAt;
        }
        from = oidAt + 1;
    }
    throw new Error(
        'p7sWitness: no RNOKPP run (06 03 55 04 05 13 10 "TINUA-" <10 digits>) ' +
            "found in leaf TBS. Expected a Diia subject serialNumber encoded as " +
            '"TINUA-<10 digits>" matching the enroll_commit_v2 circuit.',
    );
}

/**
 * Locate the byte offset of the 8 contiguous ASCII DOB digits (YYYYMMDD)
 * inside `leafTbs`, returned as the circuit's `dob_off`. The digits are the
 * leading 8 chars of the Diia DOB PrintableString "YYYYMMDD-XXXXX" carried in
 * the SubjectDirectoryAttributes extension; we scan forward from the DOB
 * attribute OID so we don't false-match an unrelated 8-digit run. `dobDigits`
 * is the expected YYYYMMDD string (from extractDOB-equivalent parsing); we
 * verify the bytes at the located offset match it exactly. The buffer is the
 * CA-AUTHENTICATED leaf TBS (the circuit reads DOB from here).
 */
export function findDobOffset(leafTbs: Uint8Array, dobDigits: string): number {
    if (!/^\d{8}$/.test(dobDigits)) {
        throw new Error(
            `p7sWitness: dobDigits must be 8 ASCII digits, got "${dobDigits}"`,
        );
    }
    const want = new TextEncoder().encode(dobDigits);
    // Prefer searching after the Diia DOB attribute OID to disambiguate.
    const oidAt = indexOf(leafTbs, DOB_ATTRIBUTE_OID, 0);
    const from = oidAt >= 0 ? oidAt + DOB_ATTRIBUTE_OID.length : 0;
    let at = indexOf(leafTbs, want, from);
    if (at < 0) at = indexOf(leafTbs, want, 0); // fall back to a full scan
    if (at < 0) {
        throw new Error(
            "p7sWitness: DOB digits not found in leaf TBS (expected the leading " +
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
    witness: InputMap; // for enroll_commit_v2 (Diia trust-chain)
    r: bigint; // blinding scalar — needed later for unblind
    M: Pt; // public blinded element = r * H2C(RNOKPP)
    rnokpp: string; // the 10-digit RNOKPP (from the proven extractRnokpp path)
}

// 32-byte BE hex -> 65-byte uncompressed P-256 point (04 || X || Y).
function uncompressedPoint(xHex: string, yHex: string): Uint8Array {
    const unc = new Uint8Array(65);
    unc[0] = 0x04;
    unc.set(hexToBytes(xHex), 1);
    unc.set(hexToBytes(yHex), 33);
    return unc;
}

function hexToBytes(hex: string): Uint8Array {
    const h = hex.startsWith("0x") ? hex.slice(2) : hex;
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

const bytesToHex = (u8: Uint8Array): string =>
    Array.from(u8)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

/**
 * Select the issuing Diia CA for a leaf cert: the CA whose pinned P-256 key
 * verifies `leafCertSig` over `sha256(leafTbs[0..leafTbsLen])`.
 *
 * SOUNDNESS. `candidates` DEFAULTS to the real pinned Diia root set — production
 * never passes anything else. The parameter exists ONLY so unit tests can drive
 * a synthetic test CA. This is a LOCAL pre-check that gives a clear early error;
 * the circuit re-enforces the pin authoritatively against its own
 * DIIA_PINNED_CA, so emitting a non-pinned CA simply fails to prove.
 *
 * @returns the selected CA's BE-byte coords (each 32 B) plus its pin name.
 * @throws a labelled error if NO candidate verifies the leaf cert signature.
 */
export function selectIssuingCa(
    leafTbs: Uint8Array,
    leafTbsLen: number,
    leafCertSig: { r: bigint; s: bigint },
    candidates: readonly PinnedCa[] = DIIA_PINNED_CA,
): { x: Uint8Array; y: Uint8Array; name: string } {
    const eLeaf = sha256(leafTbs.subarray(0, leafTbsLen));
    const sigCompact = new p256.Signature(leafCertSig.r, leafCertSig.s)
        .normalizeS()
        .toCompactRawBytes();
    for (const ca of candidates) {
        const unc = uncompressedPoint(ca.x, ca.y);
        if (p256.verify(sigCompact, eLeaf, unc, { prehash: false })) {
            return { x: hexToBytes(ca.x), y: hexToBytes(ca.y), name: ca.name };
        }
    }
    throw new Error(
        "p7sWitness: leaf cert is not signed by any pinned Diia CA " +
            `(tried ${candidates.length} candidate(s): ` +
            `${candidates.map((c) => c.name).join(", ")}). The certificate ` +
            "chain does not trace to a trusted Diia QTSP root.",
    );
}

/**
 * Auto-detect the leaf SPKI offset in `leafTbs`: the circuit asserts
 * `leaf_tbs[off-1] == 0x04` (uncompressed-point marker) and
 * `leaf_tbs[off .. off+64] == (pubkey_x || pubkey_y)`. parseP7s's
 * `leafPubkeyOffset` points at X[0] (just past the 0x04 marker), but we probe
 * both `[guess, guess+1]` to be robust to off-by-one prefix conventions, and
 * pick whichever bytes match the leaf pubkey.
 *
 * @throws a labelled error if neither candidate binds the pubkey.
 */
export function detectLeafSpkiOff(
    leafTbs: Uint8Array,
    leafTbsLen: number,
    spkiGuess: number,
    pubX: Uint8Array,
    pubY: Uint8Array,
): number {
    for (const off of [spkiGuess, spkiGuess + 1]) {
        if (off < 1 || off + 64 > leafTbsLen) continue;
        if (leafTbs[off - 1] !== 0x04) continue;
        let ok = true;
        for (let k = 0; k < 32; k++) {
            if (leafTbs[off + k] !== pubX[k] || leafTbs[off + 32 + k] !== pubY[k]) {
                ok = false;
                break;
            }
        }
        if (ok) return off;
    }
    throw new Error(
        "p7sWitness: could not bind leaf SPKI to the leaf pubkey in leaf TBS " +
            `(probed offsets ${spkiGuess}, ${spkiGuess + 1}; expected a 0x04 ` +
            "uncompressed-point marker followed by the 64-byte pubkey).",
    );
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
 * @param opts.cas  candidate CA set for issuer selection. DEFAULTS to the real
 *                  pinned Diia root set; production must NOT override it. Tests
 *                  pass a synthetic test CA so selection succeeds against a
 *                  synthetic-signed leaf TBS (see selectIssuingCa soundness note).
 *
 * REUSES parseP7s exactly as Verify.tsx does:
 *   - parsed.pubkey {x,y}          -> pubkey_x / pubkey_y
 *   - parsed.signature {r,s}       -> low-s normalized -> sig
 *   - parsed.signedAttrs           -> signed_attrs (padded) hashed in-circuit
 *   - parsed.messageDigestOffset   -> msg_digest_off (04 20 header offset)
 *   - parsed.leafTbsBytes          -> leaf_tbs buffer (RNOKPP + DOB + leaf SPKI,
 *                                     CA-authenticated)
 *   - parsed.leafCertSignature     -> leaf_cert_sig (CA over the leaf TBS)
 *   - parsed.intermediatePubkey /  -> ca_pubkey_{x,y} (issuer selection)
 *     pinned-CA selection
 *   - parsed.leafPubkeyOffset      -> leaf_spki_off (auto-detected)
 *   - extractRnokpp(parsed)        -> the 10-digit RNOKPP fed to hash_to_field
 */
export function buildP7sEnrollWitness(
    p7sBytes: Uint8Array,
    dobDigits: string,
    opts: { r?: bigint; now?: Date; cas?: readonly PinnedCa[] } = {},
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

    // --- leaf TBS buffer (zero-padded to LEAF_TBS_LEN) ------------------
    // The leaf TBSCertificate is the CA-AUTHENTICATED buffer the circuit
    // byte-reads RNOKPP + DOB + the leaf SPKI key from. (signedAttrs is the
    // SIGNED challenge blob; identity attributes live in the leaf TBS.)
    const leafTbsBytes = parsed.leafTbsBytes;
    if (leafTbsBytes.length > LEAF_TBS_LEN) {
        throw new Error(
            `p7sWitness: leaf TBS (${leafTbsBytes.length} B) exceeds LEAF_TBS_LEN ` +
                `(${LEAF_TBS_LEN}); bump LEAF_TBS_LEN in the circuit + here.`,
        );
    }
    const leafTbs = new Uint8Array(LEAF_TBS_LEN);
    leafTbs.set(leafTbsBytes, 0);
    const leafTbsLen = leafTbsBytes.length;

    // Witnessed offsets, now indexing into the AUTHENTICATED leaf TBS.
    const rnokppOff = findRnokppOidOffset(leafTbs.subarray(0, leafTbsLen));
    const dobOff = findDobOffset(leafTbs.subarray(0, leafTbsLen), dobDigits);

    // --- ECDSA material (leaf key over signedAttrs) ---------------------
    const pubX = i2osp32(parsed.pubkey.x);
    const pubY = i2osp32(parsed.pubkey.y);
    const sig = lowSCompactSig(parsed.signature.r, parsed.signature.s);

    // --- Diia CA -> leaf chain ------------------------------------------
    // leaf_cert_sig = the CA's ECDSA over the leaf TBS (low-s, compact).
    const leafCertSig = lowSCompactSig(
        parsed.leafCertSignature.r,
        parsed.leafCertSignature.s,
    );
    // Select the issuing CA. Prefer the intermediate embedded in the .p7s if it
    // happens to be one of the pinned keys; otherwise (real Diia certs embed no
    // intermediate) pick whichever candidate CA verifies the leaf cert sig.
    const candidates = opts.cas ?? DIIA_PINNED_CA;
    let caX: Uint8Array;
    let caY: Uint8Array;
    const inter = parsed.intermediatePubkey;
    const interMatch =
        inter &&
        candidates.find(
            (c) =>
                c.x === bytesToHex(i2osp32(inter.x)) &&
                c.y === bytesToHex(i2osp32(inter.y)),
        );
    if (interMatch) {
        caX = i2osp32(inter!.x);
        caY = i2osp32(inter!.y);
    } else {
        const ca = selectIssuingCa(
            leafTbs,
            leafTbsLen,
            parsed.leafCertSignature,
            candidates,
        );
        caX = ca.x;
        caY = ca.y;
    }

    // --- leaf SPKI offset (auto-detect 0x04-marker placement) -----------
    const leafSpkiOff = detectLeafSpkiOff(
        leafTbs,
        leafTbsLen,
        parsed.leafPubkeyOffset,
        pubX,
        pubY,
    );

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
        leaf_tbs: u8arr(leafTbs),
        leaf_tbs_len: leafTbsLen.toString(),
        ca_pubkey_x: u8arr(caX),
        ca_pubkey_y: u8arr(caY),
        leaf_cert_sig: u8arr(leafCertSig),
        leaf_spki_off: leafSpkiOff.toString(),
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
