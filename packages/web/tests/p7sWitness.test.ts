// Unit tests for lib/p7sWitness.ts — the REAL Diia .p7s -> enroll_commit_v2
// (Diia trust-chain) witness builder.
//
// SCOPE. These tests exercise the pure, deterministic pieces of the module
// against a SYNTHETIC leaf-TBS buffer + a SYNTHETIC test CA (no real Diia
// material, none on disk):
//   - findRnokppOidOffset: locates the circuit's real-Diia run
//     06 03 55 04 05 13 10 "TINUA-" <10 digits> and rejects a bare 13 0A
//     legacy encoding (no "TINUA-" prefix) with a labelled error.
//   - findDobOffset: locates the 8 YYYYMMDD digits, disambiguated by the Diia
//     DOB attribute OID.
//   - lowSCompactSig: forces low-s and emits the 64-byte r||s the Noir
//     ecdsa_secp256r1 blackbox requires.
//   - selectIssuingCa: picks the issuing CA whose pinned key verifies the leaf
//     cert signature; defaults to the real Diia pinned set, throws when no
//     candidate matches. Tests pass a SYNTHETIC test CA (whose private key
//     lives only in this test) so selection succeeds against a synthetic leaf.
//   - detectLeafSpkiOff: auto-detects the 0x04-marker placement and binds the
//     leaf SPKI to the leaf pubkey.
//   - todayYYYYMMDD: the public age field.
//
// SOUNDNESS. The synthetic CA is NEVER added to DIIA_PINNED_CA; it is passed
// in as an injected candidate set, mirroring the circuit's separate synthetic
// pinned set in its #[test] functions.
//
// The end-to-end parseP7s -> witness path (buildP7sEnrollWitness) reuses the
// PROVEN @crisp-qes/sdk parser, which is covered by the SDK's own fixture test
// against a real Diia .p7s. We deliberately do NOT fabricate a CAdES envelope
// here; pkijs isn't a direct web dep and a hand-rolled p7s would test our
// fixture, not the parser. Real-cert validation of the full path must happen
// IN-BROWSER against a live Diia .p7s (see the file header in p7sWitness.ts).

import { describe, expect, it } from "vitest";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import {
    LEAF_TBS_LEN,
    DIIA_PINNED_CA,
    findRnokppOidOffset,
    findDobOffset,
    lowSCompactSig,
    selectIssuingCa,
    detectLeafSpkiOff,
    todayYYYYMMDD,
    type PinnedCa,
} from "../src/lib/p7sWitness";

const RNOKPP_OID = [0x06, 0x03, 0x55, 0x04, 0x05];
const DOB_ATTRIBUTE_OID = [
    0x06, 0x0c, 0x2a, 0x86, 0x67, 0x02, 0x01, 0x01, 0x01, 0x0b, 0x01, 0x04,
    0x0b, 0x01,
];

const toHex = (u8: Uint8Array): string =>
    Array.from(u8)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

// Build a synthetic leaf-TBS buffer with the circuit's real-Diia RNOKPP run
// (06 03 55 04 05 13 10 "TINUA-" <10 digits>) at `rnokppOff` and an 8-digit DOB
// right after the Diia DOB attribute OID at `dobOff`.
const TINUA = [0x54, 0x49, 0x4e, 0x55, 0x41, 0x2d]; // "TINUA-"
function synthCert({
    rnokpp = "1234567890",
    dob = "19900115",
    rnokppOff = 100,
    dobOidOff = 300,
}: {
    rnokpp?: string;
    dob?: string;
    rnokppOff?: number;
    dobOidOff?: number;
} = {}): Uint8Array {
    const cert = new Uint8Array(LEAF_TBS_LEN);
    for (let i = 0; i < LEAF_TBS_LEN; i++) cert[i] = (i * 31 + 7) & 0xff;

    const run = [...RNOKPP_OID, 0x13, 0x10, ...TINUA];
    for (let i = 0; i < run.length; i++) cert[rnokppOff + i] = run[i]!;
    for (let i = 0; i < 10; i++)
        cert[rnokppOff + run.length + i] = rnokpp.charCodeAt(i);

    for (let i = 0; i < DOB_ATTRIBUTE_OID.length; i++)
        cert[dobOidOff + i] = DOB_ATTRIBUTE_OID[i]!;
    // PrintableString "YYYYMMDD-XXXXX" — only the leading 8 digits matter.
    const dobStr = `${dob}-02970`;
    const dobDigitsOff = dobOidOff + DOB_ATTRIBUTE_OID.length + 2; // tag+len
    cert[dobOidOff + DOB_ATTRIBUTE_OID.length] = 0x13; // PrintableString
    cert[dobOidOff + DOB_ATTRIBUTE_OID.length + 1] = dobStr.length;
    for (let i = 0; i < dobStr.length; i++)
        cert[dobDigitsOff + i] = dobStr.charCodeAt(i);

    return cert;
}

describe("findRnokppOidOffset", () => {
    it('finds the 06 03 55 04 05 13 10 "TINUA-" <10 digits> run', () => {
        const cert = synthCert({ rnokppOff: 137 });
        expect(findRnokppOidOffset(cert)).toBe(137);
    });

    it("works for offsets past the old 768-byte synthetic boundary", () => {
        const cert = synthCert({ rnokppOff: 1100 });
        expect(findRnokppOidOffset(cert)).toBe(1100);
    });

    it("rejects a bare 13 0A (legacy, no TINUA- prefix) encoding", () => {
        // Legacy synthetic: PrintableString length 10, no "TINUA-" prefix.
        const cert = new Uint8Array(LEAF_TBS_LEN);
        const off = 200;
        const run = [...RNOKPP_OID, 0x13, 0x0a];
        for (let i = 0; i < run.length; i++) cert[off + i] = run[i]!;
        for (let i = 0; i < 10; i++)
            cert[off + run.length + i] = "1234567890".charCodeAt(i);
        expect(() => findRnokppOidOffset(cert)).toThrow(/TINUA/);
    });

    it("skips an OID hit whose TINUA- digits are not exactly 10", () => {
        // First OID hit: 13 10 "TINUA-" then non-digit bytes -> not a match;
        // second is the canonical run.
        const cert = synthCert({ rnokppOff: 500 });
        const bad = 120;
        const run = [...RNOKPP_OID, 0x13, 0x10, ...TINUA];
        for (let i = 0; i < run.length; i++) cert[bad + i] = run[i]!;
        for (let i = 0; i < 10; i++) cert[bad + run.length + i] = 0x41; // 'A'
        expect(findRnokppOidOffset(cert)).toBe(500);
    });
});

describe("findDobOffset", () => {
    it("locates the 8 YYYYMMDD digits after the DOB attribute OID", () => {
        const cert = synthCert({ dob: "19900115", dobOidOff: 333 });
        const off = findDobOffset(cert, "19900115");
        const got = new TextDecoder().decode(cert.subarray(off, off + 8));
        expect(got).toBe("19900115");
        // Must sit just past the OID + PrintableString tag/len header.
        expect(off).toBe(333 + DOB_ATTRIBUTE_OID.length + 2);
    });

    it("rejects a non-8-digit DOB argument", () => {
        const cert = synthCert();
        expect(() => findDobOffset(cert, "1990115")).toThrow(/8 ASCII digits/);
        expect(() => findDobOffset(cert, "1990011a")).toThrow(/8 ASCII digits/);
    });

    it("throws when the DOB digits are absent", () => {
        const cert = synthCert({ dob: "19900115" });
        expect(() => findDobOffset(cert, "20001231")).toThrow(/not found/);
    });
});

describe("lowSCompactSig", () => {
    const order = p256.CURVE.n;
    const halfOrder = order >> 1n;

    it("produces a 64-byte r||s compact signature", () => {
        const sk = p256.utils.randomPrivateKey();
        const msg = sha256(new Uint8Array([1, 2, 3]));
        const s = p256.sign(msg, sk, { prehash: false });
        const compact = lowSCompactSig(s.r, s.s);
        expect(compact.length).toBe(64);
    });

    it("normalizes a HIGH-s signature down to low-s", () => {
        const sk = p256.utils.randomPrivateKey();
        const msg = sha256(new Uint8Array([4, 5, 6]));
        const sig = p256.sign(msg, sk, { prehash: false }).normalizeS();
        // Flip to the high-s representative: s' = n - s (> n/2).
        const highS = order - sig.s;
        expect(highS).toBeGreaterThan(halfOrder);

        const compact = lowSCompactSig(sig.r, highS);
        const sOut = bytesToBigInt(compact.subarray(32, 64));
        expect(sOut).toBeLessThanOrEqual(halfOrder);
        expect(sOut).toBe(sig.s); // recovered the canonical low-s value
    });

    it("leaves an already-low-s signature unchanged and still verifies", () => {
        const sk = p256.utils.randomPrivateKey();
        const pub = p256.getPublicKey(sk, false);
        const msg = sha256(new Uint8Array([7, 8, 9]));
        const sig = p256.sign(msg, sk, { prehash: false }).normalizeS();
        const compact = lowSCompactSig(sig.r, sig.s);
        const rOut = bytesToBigInt(compact.subarray(0, 32));
        const sOut = bytesToBigInt(compact.subarray(32, 64));
        expect(rOut).toBe(sig.r);
        expect(sOut).toBe(sig.s);
        expect(
            p256.verify(compact, msg, pub, { prehash: false }),
        ).toBe(true);
    });
});

// --- Diia trust-chain helpers ------------------------------------------
// A SYNTHETIC test CA keypair. Its private key lives ONLY here; it is NEVER
// added to DIIA_PINNED_CA. We hand it to selectIssuingCa as an injected
// candidate set, exactly as the circuit's #[test] uses a separate synthetic
// pinned set.
const CA_SK = sha256(new Uint8Array([0xca, 0x5e, 0x77])); // deterministic 32 B
const CA_PUB = p256.getPublicKey(CA_SK, false); // 65-byte uncompressed
const SYNTH_CA: PinnedCa = {
    name: "SYNTH-TEST-CA",
    x: toHex(CA_PUB.slice(1, 33)),
    y: toHex(CA_PUB.slice(33, 65)),
};

// Build a synthetic leaf TBS that embeds a leaf SPKI uncompressed point at a
// chosen marker offset, then sign sha256(leafTbs[0..len]) with the synthetic CA.
function synthLeafWithSpki(
    leafPub: Uint8Array, // 65-byte uncompressed leaf point
    markerOff: number, // offset of the 0x04 marker
    len: number,
): { leafTbs: Uint8Array; len: number } {
    const leafTbs = new Uint8Array(LEAF_TBS_LEN);
    for (let i = 0; i < len; i++) leafTbs[i] = (i * 17 + 5) & 0xff;
    leafTbs[markerOff] = 0x04;
    for (let k = 0; k < 64; k++) leafTbs[markerOff + 1 + k] = leafPub[1 + k]!;
    return { leafTbs, len };
}

describe("selectIssuingCa", () => {
    it("selects the synthetic CA that signed the leaf TBS", () => {
        const len = 800;
        const leafTbs = new Uint8Array(LEAF_TBS_LEN);
        for (let i = 0; i < len; i++) leafTbs[i] = (i * 13 + 3) & 0xff;
        const eLeaf = sha256(leafTbs.subarray(0, len));
        const sig = p256.sign(eLeaf, CA_SK, { prehash: false }).normalizeS();

        const sel = selectIssuingCa(
            leafTbs,
            len,
            { r: sig.r, s: sig.s },
            [SYNTH_CA],
        );
        expect(sel.name).toBe("SYNTH-TEST-CA");
        expect(toHex(sel.x)).toBe(SYNTH_CA.x);
        expect(toHex(sel.y)).toBe(SYNTH_CA.y);
    });

    it("throws a labelled error when no candidate CA verifies", () => {
        const len = 800;
        const leafTbs = new Uint8Array(LEAF_TBS_LEN);
        for (let i = 0; i < len; i++) leafTbs[i] = (i * 13 + 3) & 0xff;
        const eLeaf = sha256(leafTbs.subarray(0, len));
        const sig = p256.sign(eLeaf, CA_SK, { prehash: false }).normalizeS();

        // Default candidate set is the REAL pinned Diia keys — none of which
        // signed this synthetic leaf, so selection must fail closed.
        expect(() =>
            selectIssuingCa(leafTbs, len, { r: sig.r, s: sig.s }),
        ).toThrow(/not signed by any pinned Diia CA/);
    });

    it("defaults its candidate set to the real pinned Diia roots", () => {
        // Soundness guard: the production default must be DIIA_PINNED_CA, and
        // that set must NOT contain the synthetic test CA.
        expect(DIIA_PINNED_CA.some((c) => c.x === SYNTH_CA.x)).toBe(false);
        expect(DIIA_PINNED_CA.length).toBe(2);
        expect(DIIA_PINNED_CA.map((c) => c.name)).toContain("UA-43395033-2311");
    });
});

describe("detectLeafSpkiOff", () => {
    const leafSk = sha256(new Uint8Array([0x1e, 0xaf]));
    const leafPub = p256.getPublicKey(leafSk, false);
    const pubX = leafPub.slice(1, 33);
    const pubY = leafPub.slice(33, 65);

    it("detects the SPKI X offset (0x04 marker at off-1) and binds the pubkey", () => {
        const markerOff = 200;
        const { leafTbs, len } = synthLeafWithSpki(leafPub, markerOff, 800);
        // X[0] sits right after the marker; detect should return markerOff+1.
        expect(detectLeafSpkiOff(leafTbs, len, markerOff + 1, pubX, pubY)).toBe(
            markerOff + 1,
        );
        // Robust to a guess one short (probes guess and guess+1).
        expect(detectLeafSpkiOff(leafTbs, len, markerOff, pubX, pubY)).toBe(
            markerOff + 1,
        );
    });

    it("throws when the SPKI does not bind the leaf pubkey", () => {
        const { leafTbs, len } = synthLeafWithSpki(leafPub, 200, 800);
        const wrongY = new Uint8Array(32).fill(7);
        expect(() =>
            detectLeafSpkiOff(leafTbs, len, 201, pubX, wrongY),
        ).toThrow(/could not bind leaf SPKI/);
    });
});

describe("todayYYYYMMDD", () => {
    it("formats a fixed UTC date as YYYYMMDD", () => {
        expect(todayYYYYMMDD(new Date(Date.UTC(2026, 4, 31)))).toBe("20260531");
        expect(todayYYYYMMDD(new Date(Date.UTC(2000, 0, 1)))).toBe("20000101");
    });
});

function bytesToBigInt(b: Uint8Array): bigint {
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v;
}
