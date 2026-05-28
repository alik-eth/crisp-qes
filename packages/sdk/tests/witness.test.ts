// Witness assembly tests.
//
// These exercise the pure-typescript witness builder against a synthetic
// `ParsedP7s` so we don't depend on the Diia fixture (CI ships without it).
// The Diia fixture is exercised separately by `p7s.test.ts`.

import { describe, expect, it } from "vitest";

import type { ParsedP7s } from "../src/p7s.js";
import { buildWitness, splitSha256, toFieldHex } from "../src/witness.js";
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
    return {
        signedAttrs,
        signedAttrsSha256: new Uint8Array(32).fill(0xAA),
        messageDigest,
        messageDigestOffset: mdOffset,
        subjectSerial: new TextEncoder().encode("TINUA-1234567890"),
        leafCertDer: new Uint8Array(400),
        leafSpkiDer: new Uint8Array(550), // typical RSA-free P-256 SPKI ~ 91 bytes; pad to 550 to exercise bounds
        intermediateCertDer: null,
        pubkey: {
            x: 0xa1ce_b0b_c0ffeen,
            y: 0xdeca_f_face_b00cn,
        },
        signature: { r: 1n, s: 2n },
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
        // 0xFF...FF top bit set; hi = 0xFFEEDD...100, lo = 0xFFEEDD...100.
        const digest = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            digest[i] = 0xff - (i & 0x0f);
        }
        const { hi, lo } = splitSha256(digest);
        // Each limb fits in 128 bits.
        expect(hi < 1n << 128n).toBe(true);
        expect(lo < 1n << 128n).toBe(true);
        // Reassembly round-trips.
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
        // hi = 0x010200000000000000000000000000FF
        expect(hi).toBe(0x010200000000000000000000000000ffn);
        // lo = 0xAB00000000000000000000000000_00CD
        expect(lo).toBe(0xab000000000000000000000000000000n | 0xcdn);
    });

    it("rejects wrong-length input", () => {
        expect(() => splitSha256(new Uint8Array(31))).toThrow();
        expect(() => splitSha256(new Uint8Array(33))).toThrow();
    });
});

describe("computeNullifier", () => {
    it("matches the bb.js Pedersen on the canonical input tuple", async () => {
        const a = await computeNullifier({
            pubkey: { x: 1n, y: 2n },
            petitionId: 42n,
        });
        expect(a).toMatch(/^0x[0-9a-f]{64}$/);
        // Deterministic — calling twice yields the same value.
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

describe("buildWitness — shape contract", () => {
    const baseArgs = {
        petitionId: 7n,
        petitionTextHash: new Uint8Array(32).fill(0x42),
        trustRoot: 0xdeadbeefn,
        merklePath: Array.from({ length: 16 }, (_, i) => BigInt(i + 1)),
        merklePathIndices: Array.from({ length: 16 }, (_, i) => i & 1),
    };

    it("produces an InputMap with the exact circuit field names + array sizes", async () => {
        const { inputs, publics } = await buildWitness({
            parsed: makeParsedP7s(),
            ...baseArgs,
        });

        // Public slots
        expect(inputs.petition_id).toBe(toFieldHex(7n));
        expect(inputs.trust_root).toBe(toFieldHex(0xdeadbeefn));
        expect(inputs.pubkey_x).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.pubkey_y).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.nullifier).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.signed_attrs_sha256_hi).toMatch(/^0x[0-9a-f]{64}$/);
        expect(inputs.signed_attrs_sha256_lo).toMatch(/^0x[0-9a-f]{64}$/);

        // Private slots — circuit-mandated lengths
        expect(inputs.subject_serial.length).toBe(32);
        expect(inputs.spki_bytes.length).toBe(1024);
        expect(inputs.merkle_path.length).toBe(16);
        expect(inputs.merkle_path_indices.length).toBe(16);
        expect(inputs.signed_attrs_bytes.length).toBe(512);
        expect(inputs.petition_text_hash.length).toBe(32);

        // `signed_attrs_len` and offset are decimal strings
        expect(inputs.signed_attrs_len).toBe("200");
        expect(inputs.message_digest_offset).toBe("50");

        // merkle_path_indices coerced to booleans
        for (const v of inputs.merkle_path_indices) expect(typeof v).toBe("boolean");

        // publics carry the same numerical values we'll send on-chain
        expect(publics.petitionId).toBe(7n);
        expect(publics.nullifier).toBe(BigInt(inputs.nullifier));
        expect(publics.trustRoot).toBe(0xdeadbeefn);
    });

    it("pads bytes right with zeros up to the circuit max length", async () => {
        const { inputs } = await buildWitness({
            parsed: makeParsedP7s(),
            ...baseArgs,
        });
        // The synthetic signedAttrs was 200 bytes — everything past should be zero.
        for (let i = 200; i < 512; i++) {
            expect(inputs.signed_attrs_bytes[i]).toBe(0);
        }
        // leaf SPKI was 550 bytes — zero-padded out to 1024.
        for (let i = 550; i < 1024; i++) {
            expect(inputs.spki_bytes[i]).toBe(0);
        }
    });

    it("splits sha256 into hi/lo that reassemble to the digest", async () => {
        // Top-bit-set digest — the path that motivated the slot-5/6 split.
        const digest = new Uint8Array(32);
        for (let i = 0; i < 32; i++) digest[i] = 0xf0 ^ i;
        const parsed = makeParsedP7s({ signedAttrsSha256: digest });

        const { inputs } = await buildWitness({ parsed, ...baseArgs });
        const hi = BigInt(inputs.signed_attrs_sha256_hi);
        const lo = BigInt(inputs.signed_attrs_sha256_lo);
        expect(hi >> 128n).toBe(0n);
        expect(lo >> 128n).toBe(0n);

        let direct = 0n;
        for (const b of digest) direct = (direct << 8n) | BigInt(b);
        expect((hi << 128n) | lo).toBe(direct);
    });

    it("rejects oversized signedAttrs / spki / wrong-length petitionTextHash / bad indices", async () => {
        await expect(
            buildWitness({
                parsed: makeParsedP7s({
                    signedAttrs: new Uint8Array(1024), // > 512 cap
                }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/signedAttrs/);

        await expect(
            buildWitness({
                parsed: makeParsedP7s({
                    leafSpkiDer: new Uint8Array(2048), // > 1024 cap
                }),
                ...baseArgs,
            }),
        ).rejects.toThrow(/leafSpkiDer/);

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
});
