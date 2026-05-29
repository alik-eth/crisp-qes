// End-to-end Fastify route tests.
//
// We instantiate `buildApp` with an in-memory SQLite store and a real
// generated OPRF/attester key pair. The Diia .p7s fixture lives under
// `fixtures/diia/` (gitignored — see CLAUDE house rules) and is read by
// absolute path; the suite skips the attestation-gated routes when the
// fixture is absent so CI without local fixtures stays green.

import { existsSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { bytesToHex } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";

import { buildApp } from "../src/app.js";
import type { OprfConfig } from "../src/config.js";
import { EnrollmentStore } from "../src/db.js";
import { MerkleIndex } from "../src/merkle.js";
import {
    blind,
    fromHex,
    randomScalar,
    ristretto255,
    unblind,
    verifyProof,
} from "../src/oprf.js";
import {
    commitmentFromOprfOutput,
} from "../src/pedersen.js";

const FIXTURE_PATH =
    "/data/Develop/crisp-qes/fixtures/diia/petition-1-binding.bin.p7s";
const hasFixture = existsSync(FIXTURE_PATH);
const maybe = hasFixture ? describe : describe.skip;

function scalarToLE(s: bigint): Uint8Array {
    const out = new Uint8Array(32);
    let x = s;
    for (let i = 0; i < 32; i++) {
        out[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return out;
}

async function buildTestApp(overrides: Partial<OprfConfig> = {}) {
    const k = randomScalar();
    const config: OprfConfig = {
        port: 0,
        isProd: false,
        dbPath: ":memory:",
        oprfKey: scalarToLE(k),
        oprfPubkey: new Uint8Array(32),
        attesterKey: `0x${bytesToHex(randomBytes(32))}` as `0x${string}`,
        chainId: 31337,
        enrollmentRegistry:
            "0x1234567890abcdef1234567890abcdef12345678" as `0x${string}`,
        corsAllowedOrigins: ["*"],
        ageThreshold: 0, // default to disabled in tests
        ...overrides,
    };
    const store = new EnrollmentStore(":memory:");
    const merkle = await MerkleIndex.fromLeaves([]);
    const app = await buildApp({ config, store, merkle });
    await app.ready();
    return { app, config, store, merkle, k };
}

describe("oprf /healthz", () => {
    it("reports state snapshot", async () => {
        const { app } = await buildTestApp();
        const res = await app.inject({ method: "GET", url: "/healthz" });
        expect(res.statusCode).toBe(200);
        const body = res.json() as Record<string, unknown>;
        expect(body.ok).toBe(true);
        expect(body.suite).toBe("ristretto255-SHA512");
        expect(body.enrolledCount).toBe(0);
        expect(body.attesterAddr).toMatch(/^0x[0-9a-fA-F]{40}$/);
        expect(body.oprfPubkey).toMatch(/^0x[0-9a-fA-F]{64}$/);
    });
});

maybe("oprf /oprf/blind-eval", () => {
    const p7sBytes = hasFixture
        ? new Uint8Array(readFileSync(FIXTURE_PATH))
        : new Uint8Array(0);
    const p7sBase64 = Buffer.from(p7sBytes).toString("base64");

    it("returns a DLEQ-valid OPRF share for a fresh Diia attestation", async () => {
        const { app, k } = await buildTestApp();
        const input = new TextEncoder().encode("RNOKPP=3627506575");
        const { r, M } = blind(input);

        const res = await app.inject({
            method: "POST",
            url: "/oprf/blind-eval",
            payload: {
                blindedInput: `0x${bytesToHex(M)}`,
                attestation: { p7s: p7sBase64 },
            },
        });
        expect(res.statusCode).toBe(200);
        const body = res.json() as {
            Y: `0x${string}`;
            K: `0x${string}`;
            proof: { c: `0x${string}`; s: `0x${string}` };
            oprfPubkey: `0x${string}`;
        };

        // K is the duplicated public-key alias web's oprfClient expects;
        // `oprfPubkey` is the legacy field kept for backward compat.
        expect(body.K).toBe(body.oprfPubkey);
        // `proof` arrives as a {c, s} pair; reassemble for verifyProof.
        const proofBytes = new Uint8Array([
            ...fromHex(body.proof.c),
            ...fromHex(body.proof.s),
        ]);

        // Client-side DLEQ verification + unblind sanity.
        const Y = fromHex(body.Y);
        const Kpub = fromHex(body.K);
        expect(verifyProof(Kpub, M, Y, proofBytes)).toBe(true);

        const N = unblind(r, Y);
        const Nref = ristretto255.Point
            .fromBytes(M)
            .multiply(k)
            .multiply(ristretto255.Point.Fn.inv(r))
            .toBytes();
        expect(Buffer.from(N).toString("hex")).toEqual(
            Buffer.from(Nref).toString("hex"),
        );
    });

    it("rejects an invalid attestation with 401", async () => {
        const { app } = await buildTestApp();
        const M = blind(new TextEncoder().encode("x")).M;
        const res = await app.inject({
            method: "POST",
            url: "/oprf/blind-eval",
            payload: {
                blindedInput: `0x${bytesToHex(M)}`,
                // 16 random base64 bytes — definitely not a CAdES envelope.
                attestation: { p7s: Buffer.from(randomBytes(16)).toString("base64") },
            },
        });
        expect(res.statusCode).toBe(401);
    });
});

describe("oprf /oprf/register", () => {
    async function fakeEnrollmentCommitment() {
        // Synthesize an unblinded OPRF output N (any 32-byte ristretto255
        // encoding works for the commitment math) and derive the matching
        // pedersen commitment.
        const N = ristretto255.Point.BASE.multiply(randomScalar()).toBytes();
        const commitment = await commitmentFromOprfOutput(N);
        return { N, commitment };
    }

    it("inserts a fresh commitment, returns valid Merkle path, second insert is 409", async () => {
        const { app } = await buildTestApp();
        const { N, commitment } = await fakeEnrollmentCommitment();
        const commitmentHex = `0x${commitment.toString(16).padStart(64, "0")}`;
        const blindedInputUsed = `0x${"00".repeat(32)}`;
        const unblindedOutput = `0x${bytesToHex(N)}`;

        const first = await app.inject({
            method: "POST",
            url: "/oprf/register",
            payload: { commitment: commitmentHex, blindedInputUsed, unblindedOutput },
        });
        expect(first.statusCode).toBe(200);
        const body = first.json() as {
            leafIndex: number;
            merklePath: string[];
            merklePathIndices: number[];
            oldRoot: `0x${string}`;
            newRoot: `0x${string}`;
            attesterSig: `0x${string}`;
            attesterAddr: `0x${string}`;
        };
        expect(body.leafIndex).toBe(0);
        expect(body.merklePath).toHaveLength(20);
        expect(body.merklePathIndices).toHaveLength(20);
        expect(body.attesterSig).toMatch(/^0x[0-9a-fA-F]{130}$/);

        // /enrollment/:commitment/path returns the same proof.
        const path = await app.inject({
            method: "GET",
            url: `/enrollment/${commitmentHex}/path`,
        });
        expect(path.statusCode).toBe(200);
        const pathBody = path.json() as { leafIndex: number; root: string };
        expect(pathBody.leafIndex).toBe(0);
        expect(pathBody.root).toBe(body.newRoot);

        // Re-registering must collide.
        const second = await app.inject({
            method: "POST",
            url: "/oprf/register",
            payload: { commitment: commitmentHex, blindedInputUsed, unblindedOutput },
        });
        expect(second.statusCode).toBe(409);
    });

    it("rejects a commitment that doesn't match pedersen([N_hi, N_lo], 0)", async () => {
        const { app } = await buildTestApp();
        const { N } = await fakeEnrollmentCommitment();
        // Forged commitment: use a totally different value.
        const wrong = `0x${"ab".repeat(32)}`;
        const res = await app.inject({
            method: "POST",
            url: "/oprf/register",
            payload: {
                commitment: wrong,
                blindedInputUsed: `0x${"00".repeat(32)}`,
                unblindedOutput: `0x${bytesToHex(N)}`,
            },
        });
        expect(res.statusCode).toBe(400);
        expect((res.json() as { error: string }).error).toBe(
            "CommitmentMismatch",
        );
    });

    it("rejects an unknown-commitment Merkle path lookup with 404", async () => {
        const { app } = await buildTestApp();
        const res = await app.inject({
            method: "GET",
            url: `/enrollment/0x${"ff".repeat(32)}/path`,
        });
        expect(res.statusCode).toBe(404);
    });
});
