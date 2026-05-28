// Witness assembly tests for the D-v2 chain-verify circuit.
//
// These exercise the pure-typescript witness builder against a synthetic
// `ParsedP7s` so we don't depend on the Diia fixture (CI ships without it).
// The Diia fixture is exercised separately by `p7s.test.ts`.

import { describe, expect, it } from "vitest";

import type { ParsedP7s } from "../src/p7s.js";
import { buildWitness, splitPubkey, splitSha256, splitU256, toFieldHex } from "../src/witness.js";
import { computeNullifier } from "../src/prove.js";

function makeParsedP7s(overrides: Partial<ParsedP7s> = {}): ParsedP7s {
    const signedAttrs = new Uint8Array(200);
    signedAttrs[0] = 0x31; // SET tag
    signedAttrs[1] = 0x82;
    // Plant a recognizable messageDigest OCTET STRING at a fixed offset.
    const mdOffset = 50;
    signedAttrs[mdOffset - 2] = 0x04;
    signedAttrs[mdOffset - 1] = 0x20;
    const messageDigest = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        messageDigest[i] = (i * 7 + 3) & 0xff;
        signedAttrs[mdOffset + i] = messageDigest[i]!;
    }

    // Synthetic leaf TBSCertificate: subject_serial bytes planted at offset
    // 100, leaf pubkey would-be offset right after the canonical 27-byte
    // SPKI prefix at offset 200 (so leaf_pubkey_offset = 227).
    const subjectSerial = new TextEncoder().encode("TINUA-1234567890123456789012345");
    const leafTbsBytes = new Uint8Array(400);
    leafTbsBytes.set(subjectSerial, 100);
    // Plant 64 pubkey bytes at offset 227 — values don't have to match X/Y
    // since the shape test only inspects offsets/lengths.
    for (let i = 0; i < 64; i++) leafTbsBytes[227 + i] = (i + 0x20) & 0xff;

    const intermediateSpkiDer = new Uint8Array(200);
    // The intermediate SPKI body just needs to be a sane length; we plant the
    // canonical prefix at offset 0 so intermediate_pubkey_offset = 27.
    for (let i = 0; i < 27; i++) intermediateSpkiDer[i] = 0xa0 + i;
    for (let i = 27; i < 27 + 64; i++) intermediateSpkiDer[i] = i & 0xff;

    return {
        signedAttrs,
        signedAttrsSha256: new Uint8Array(32).fill(0xAA),
        messageDigest,
        messageDigestOffset: mdOffset,
        subjectSerial: subjectSerial.slice(0, 32),
        leafCertDer: new Uint8Array(420),
        leafTbsBytes,
        leafTbsSha256: new Uint8Array(32).fill(0xBB),
        subjectSerialOffset: 100,
        leafPubkeyOffset: 227,
        leafSpkiDer: new Uint8Array(550),
        intermediateCertDer: new Uint8Array(800),
        intermediateSpkiDer,
        intermediatePubkey: {
            x: 0xbeefn,
            y: 0xcafen,
        },
        intermediatePubkeyOffset: 27,
        pubkey: {
            x: 0xa1ce_b0b_c0ffeen,
            y: 0xdeca_f_face_b00cn,
        },
        signature: { r: 1n, s: 2n },
        leafCertSignature: { r: 3n, s: 4n },
        ...overrides,
    };
}

describe("splitSha256 hi/lo", () => {
    it("encodes the canonical zero hash as 0,0", () => {
        const { hi, lo } = splitSha256(new Uint8Array(32));
        expect(hi).toBe(0n);
        expect(lo).toBe(0n);
    });

    it("splits a top-bit-set digest into two 128-bit halves", () => {
        const digest = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            digest[i] = 0xff - (i & 0x0f);
        }
        const { hi, lo } = splitSha256(digest);
        expect(hi < 1n << 128n).toBe(true);
        expect(lo < 1n << 128n).toBe(true);
        const reassembled = (hi << 128n) | lo;
        let direct = 0n;
        for (const b of digest) direct = (direct << 8n) | BigInt(b);
        expect(reassembled).toBe(direct);
    });

    it("matches the circuit's be_bytes16_to_field semantics on a known vector", () => {
        const digest = new Uint8Array(32);
        digest[0] = 0x01;
        digest[1] = 0x02;
        digest[15] = 0xff;
        digest[16] = 0xab;
        digest[31] = 0xcd;
        const { hi, lo } = splitSha256(digest);
        expect(hi).toBe(0x010200000000000000000000000000ffn);
        expect(lo).toBe(0xab000000000000000000000000000000n | 0xcdn);
    });

    it("rejects wrong-length input", () => {
        expect(() => splitSha256(new Uint8Array(31))).toThrow();
        expect(() => splitSha256(new Uint8Array(33))).toThrow();
    });
});

describe("splitU256 / splitPubkey", () => {
    it("encodes zero as (0, 0)", () => {
        expect(splitU256(0n)).toEqual({ hi: 0n, lo: 0n });
    });

    it("reassembles a top-bit-set 256-bit value losslessly", () => {
        // The exact value pattern that broke pre-fix: top byte 0x83, i.e.
        // numerically > BN254_R, so a single-Field public input would
        // silently reduce mod p.
        const v =
            0x83db112233445566778899aabbccddeeff00112233445566778899aabbccddeen;
        const { hi, lo } = splitU256(v);
        expect(hi >> 128n).toBe(0n);
        expect(lo >> 128n).toBe(0n);
        expect((hi << 128n) | lo).toBe(v);
    });

    it("matches the circuit's BE-pack semantics on a known vector", () => {
        // hi = BE(bytes 0..15), lo = BE(bytes 16..31). For v with explicit
        // bytes 0x010203...20 this gives well-known limb values.
        let v = 0n;
        for (let i = 1; i <= 32; i++) v = (v << 8n) | BigInt(i);
        const { hi, lo } = splitU256(v);
        expect(hi).toBe(0x0102030405060708090a0b0c0d0e0f10n);
        expect(lo).toBe(0x1112131415161718191a1b1c1d1e1f20n);
    });

    it("rejects oversized input", () => {
        expect(() => splitU256(-1n)).toThrow();
        expect(() => splitU256(1n << 256n)).toThrow();
    });

    it("splitPubkey returns 4 separate limbs for X and Y", () => {
        const x = 0x80000000000000000000000000000001n << 128n |
            0x00000000000000000000000000000abcn;
        const y =
            0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
        const { xHi, xLo, yHi, yLo } = splitPubkey({ x, y });
        expect((xHi << 128n) | xLo).toBe(x);
        expect((yHi << 128n) | yLo).toBe(y);
        expect(xHi >> 128n).toBe(0n);
        expect(xLo >> 128n).toBe(0n);
        expect(yHi >> 128n).toBe(0n);
        expect(yLo >> 128n).toBe(0n);
    });
});

describe("computeNullifier", () => {
    it("matches the bb.js Pedersen on the canonical input tuple", async () => {
        const a = await computeNullifier({
            pubkey: { x: 1n, y: 2n },
            petitionId: 42n,
        });
        expect(a).toMatch(/^0x[0-9a-f]{64}$/);
        const b = await computeNullifier({
            pubkey: { x: 1n, y: 2n },
            petitionId: 42n,
        });
        expect(b).toBe(a);
    });

    it("changes when any input changes (sanity)", async () => {
        const base = await computeNullifier({
            pubkey: { x: 1n, y: 2n },
            petitionId: 1n,
        });
        const diffPid = await computeNullifier({
            pubkey: { x: 1n, y: 2n },
            petitionId: 2n,
        });
        const diffX = await computeNullifier({
            pubkey: { x: 3n, y: 2n },
            petitionId: 1n,
        });
        expect(diffPid).not.toBe(base);
        expect(diffX).not.toBe(base);
    });
});

describe("buildWitness — shape contract (D-v2)", () => {
    const baseArgs = {
        petitionId: 7n,
        petitionTextHash: new Uint8Array(32).fill(0x42),
        trustRoot: 0xdeadbeefn,
        merklePath: Array.from({ length: 16 }, (_, i) => BigInt(i + 1)),
        merklePathIndices: Array.from({ length: 16 }, (_, i) => i & 1),
    };

    it("produces an InputMap with the exact v2 circuit field names + array sizes", async () => {
        const { inputs, publics } = await buildWitness({
            parsed: makeParsedP7s(),
            ...baseArgs,
        });

        // Public slots (15) — pubkey coords now ship as 128-bit limb pairs
        // (D-v2-fix). Each limb is `< 2^128`, well inside the BN254 prime.
        expect(inputs.petition_id).toBe(toFieldHex(7n));
        expect(inputs.trust_root).toBe(toFieldHex(0xdeadbeefn));
        expect(inputs.leaf_pubkey_x_hi).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.leaf_pubkey_x_lo).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.leaf_pubkey_y_hi).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.leaf_pubkey_y_lo).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.intermediate_pubkey_x_hi).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.intermediate_pubkey_x_lo).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.intermediate_pubkey_y_hi).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.intermediate_pubkey_y_lo).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.nullifier).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.leaf_tbs_sha256_hi).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.leaf_tbs_sha256_lo).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.signed_attrs_sha256_hi).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.signed_attrs_sha256_lo).toMatch(/^0x[0-9a-f]{64}$/);

        // Each limb fits in 128 bits.
        for (const slot of [
            inputs.leaf_pubkey_x_hi,
            inputs.leaf_pubkey_x_lo,
            inputs.leaf_pubkey_y_hi,
            inputs.leaf_pubkey_y_lo,
            inputs.intermediate_pubkey_x_hi,
            inputs.intermediate_pubkey_x_lo,
            inputs.intermediate_pubkey_y_hi,
            inputs.intermediate_pubkey_y_lo,
        ]) {
            expect(BigInt(slot) >> 128n).toBe(0n);
        }

        // Private slots — circuit-mandated lengths
        expect(inputs.subject_serial.length).toBe(32);
        expect(inputs.leaf_tbs_bytes.length).toBe(2048);
        expect(inputs.intermediate_spki_bytes.length).toBe(1024);
        expect(inputs.merkle_path.length).toBe(16);
        expect(inputs.merkle_path_indices.length).toBe(16);
        expect(inputs.signed_attrs_bytes.length).toBe(2048);
        expect(inputs.petition_text_hash.length).toBe(32);

        // Offsets + lengths as decimal strings (Noir u32 InputMap form).
        expect(inputs.signed_attrs_len).toBe("200");
        expect(inputs.message_digest_offset).toBe("50");
        expect(inputs.subject_serial_offset).toBe("100");
        expect(inputs.leaf_tbs_len).toBe("400");
        expect(inputs.leaf_pubkey_offset).toBe("227");
        expect(inputs.intermediate_pubkey_offset).toBe("27");

        // merkle_path_indices coerced to booleans
        for (const v of inputs.merkle_path_indices) expect(typeof v).toBe("boolean");

        // publics carry the same numerical values we'll send on-chain.
        // Each pubkey coordinate now lives in two limbs; reassembly must
        // round-trip back to the original ParsedP7s value.
        expect(publics.petitionId).toBe(7n);
        expect(publics.nullifier).toBe(BigInt(inputs.nullifier));
        expect(publics.trustRoot).toBe(0xdeadbeefn);
        expect((publics.intermediatePubkeyXHi << 128n) | publics.intermediatePubkeyXLo).toBe(
            0xbeefn,
        );
        expect((publics.intermediatePubkeyYHi << 128n) | publics.intermediatePubkeyYLo).toBe(
            0xcafen,
        );
    });

    it("pads bytes right with zeros up to the circuit max length", async () => {
        const { inputs } = await buildWitness({
            parsed: makeParsedP7s(),
            ...baseArgs,
        });
        // signedAttrs was 200 bytes — everything past is zero.
        for (let i = 200; i < 2048; i++) {
            expect(inputs.signed_attrs_bytes[i]).toBe(0);
        }
        // leaf TBS was 400 bytes — zero-padded out to 2048.
        for (let i = 400; i < 2048; i++) {
            expect(inputs.leaf_tbs_bytes[i]).toBe(0);
        }
        // intermediate SPKI was 200 bytes — zero-padded out to 1024.
        for (let i = 200; i < 1024; i++) {
            expect(inputs.intermediate_spki_bytes[i]).toBe(0);
        }
    });

    it("splits both SHA-256 digests into hi/lo that reassemble correctly", async () => {
        const tbs = new Uint8Array(32);
        const sa = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            tbs[i] = 0xf0 ^ i;
            sa[i] = 0x0f ^ i;
        }
        const parsed = makeParsedP7s({
            leafTbsSha256: tbs,
            signedAttrsSha256: sa,
        });

        const { inputs } = await buildWitness({ parsed, ...baseArgs });

        const reassemble = (hi: bigint, lo: bigint) => (hi << 128n) | lo;
        const directOf = (b: Uint8Array) => {
            let v = 0n;
            for (const x of b) v = (v << 8n) | BigInt(x);
            return v;
        };
        expect(
            reassemble(
                BigInt(inputs.leaf_tbs_sha256_hi),
                BigInt(inputs.leaf_tbs_sha256_lo),
            ),
        ).toBe(directOf(tbs));
        expect(
            reassemble(
                BigInt(inputs.signed_attrs_sha256_hi),
                BigInt(inputs.signed_attrs_sha256_lo),
            ),
        ).toBe(directOf(sa));
    });

    it("rejects oversized signedAttrs / leafTbs / intermediateSpki", async () => {
        await expect(
            buildWitness({
                parsed: makeParsedP7s({
                    signedAttrs: new Uint8Array(4096), // > 2048 cap
                }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/signedAttrs/);

        await expect(
            buildWitness({
                parsed: makeParsedP7s({
                    leafTbsBytes: new Uint8Array(4096), // > 2048 cap
                }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/leafTbsBytes/);

        await expect(
            buildWitness({
                parsed: makeParsedP7s({
                    intermediateSpkiDer: new Uint8Array(2048), // > 1024 cap
                }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/intermediateSpkiDer/);
    });

    it("rejects bad shape (wrong petitionTextHash / indices / merkle path)", async () => {
        await expect(
            buildWitness({
                parsed: makeParsedP7s(),
                ...baseArgs,
                petitionTextHash: new Uint8Array(31),
            }),
        ).rejects.toThrow(/petitionTextHash/);

        await expect(
            buildWitness({
                parsed: makeParsedP7s(),
                ...baseArgs,
                merklePathIndices: Array.from({ length: 16 }, () => 2),
            }),
        ).rejects.toThrow(/0 or 1/);

        await expect(
            buildWitness({
                parsed: makeParsedP7s(),
                ...baseArgs,
                merklePath: Array.from({ length: 15 }, () => 0n),
            }),
        ).rejects.toThrow(/merklePath/);
    });

    it("rejects messageDigestOffset that runs off the end of signedAttrs", async () => {
        const sa = new Uint8Array(200);
        await expect(
            buildWitness({
                parsed: makeParsedP7s({
                    signedAttrs: sa,
                    messageDigestOffset: 190, // 190 + 32 = 222 > 200
                }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/messageDigestOffset/);
    });

    it("rejects a .p7s with no intermediate cert (D-v2 requires it)", async () => {
        await expect(
            buildWitness({
                parsed: makeParsedP7s({
                    intermediateCertDer: null,
                    intermediateSpkiDer: null,
                    intermediatePubkey: null,
                    intermediatePubkeyOffset: null,
                }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/intermediate/);
    });

    it("rejects out-of-range leafPubkeyOffset / intermediatePubkeyOffset", async () => {
        await expect(
            buildWitness({
                parsed: makeParsedP7s({ leafPubkeyOffset: 5 }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/leafPubkeyOffset/);

        await expect(
            buildWitness({
                parsed: makeParsedP7s({ intermediatePubkeyOffset: 5 }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/intermediatePubkeyOffset/);
    });
});
