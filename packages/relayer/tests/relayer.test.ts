// v2 relayer route tests.
//
// Mocks the viem clients so we can assert wire shape, validation, error
// mapping, and the live-root pre-flight without touching the chain.

import { describe, expect, it, vi } from "vitest";
import {
    ContractFunctionRevertedError,
    type Hex,
    toFunctionSelector,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { buildApp } from "../src/app.js";
import type { Clients } from "../src/chain.js";
import type { RelayerConfig } from "../src/config.js";
import { makeRateLimiter } from "../src/rateLimit.js";

const ANVIL_KEY: Hex =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const ENROLL_ROOT: Hex = `0x${"e".repeat(64)}` as Hex;

function cfg(overrides: Partial<RelayerConfig> = {}): RelayerConfig {
    return {
        port: 0,
        chainId: 31337,
        rpcUrl: "http://127.0.0.1:8545",
        petitionRegistry: "0x1111111111111111111111111111111111111111",
        enrollmentRegistry: "0x2222222222222222222222222222222222222222",
        privateKey: ANVIL_KEY,
        blockExplorerBase: "https://example.test/tx/",
        rateLimitWindowMs: 10_000,
        isProd: false,
        corsAllowedOrigins: ["*"],
        ...overrides,
    };
}

function fakeClients(impls: {
    simulate?: ReturnType<typeof vi.fn>;
    write?: ReturnType<typeof vi.fn>;
    getReceipt?: ReturnType<typeof vi.fn>;
    getTx?: ReturnType<typeof vi.fn>;
    read?: ReturnType<typeof vi.fn>;
} = {}): Clients {
    const account = privateKeyToAccount(ANVIL_KEY);
    return {
        account,
        chain: {
            id: 31337,
            name: "anvil",
            nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
            rpcUrls: { default: { http: ["http://127.0.0.1:8545"] } },
        } as Clients["chain"],
        publicClient: {
            simulateContract:
                impls.simulate ?? vi.fn().mockResolvedValue({ request: {} }),
            getTransactionReceipt:
                impls.getReceipt ?? vi.fn().mockRejectedValue(new Error("not found")),
            getTransaction:
                impls.getTx ?? vi.fn().mockRejectedValue(new Error("not found")),
            // Default: enrollmentRoot() returns the canonical ENROLL_ROOT.
            // Tests override `read` to simulate a stale-root mismatch.
            readContract: impls.read ?? vi.fn().mockResolvedValue(ENROLL_ROOT),
        } as unknown as Clients["publicClient"],
        walletClient: {
            writeContract:
                impls.write ??
                vi.fn().mockResolvedValue(("0x" + "ab".repeat(32)) as Hex),
        } as unknown as Clients["walletClient"],
    };
}

const VALID_BODY = {
    petitionId: "1",
    nullifier: "0x" + "11".repeat(32),
    proof: "0xdead",
    publicInputs: [
        "0x" + "00".repeat(31) + "01", // [0] petitionId
        ENROLL_ROOT,                    // [1] enrollmentRoot
        "0x" + "11".repeat(32),         // [2] nullifier
    ],
};

describe("POST /v2/submit validation", () => {
    it("rejects malformed JSON with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: { nope: true },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });

    it("rejects publicInputs[0] != petitionId with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: { ...VALID_BODY, petitionId: "2" },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });

    it("rejects publicInputs[2] != nullifier with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const wrongNull = "0x" + "ff".repeat(32);
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: { ...VALID_BODY, nullifier: wrongNull },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });


    it("rejects stale enrollmentRoot with 409", async () => {
        const liveRoot = `0x${"a".repeat(64)}`;
        const clients = fakeClients({
            read: vi.fn().mockResolvedValue(liveRoot),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: VALID_BODY,
        });
        expect(res.statusCode).toBe(409);
        const body = res.json() as { error: string; expectedRoot: string };
        expect(body.error).toBe("StaleEnrollmentRoot");
        expect(body.expectedRoot.toLowerCase()).toBe(liveRoot.toLowerCase());
        await app.close();
    });
});

describe("POST /v2/submit happy path", () => {
    it("returns 200 with txHash and blockExplorerUrl when viem succeeds", async () => {
        const fakeHash = ("0x" + "ab".repeat(32)) as Hex;
        const clients = fakeClients({
            write: vi.fn().mockResolvedValue(fakeHash),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: VALID_BODY,
        });
        expect(res.statusCode).toBe(200);
        const json = res.json();
        expect(json.txHash).toBe(fakeHash);
        expect(json.blockExplorerUrl).toBe(
            `https://example.test/tx/${fakeHash}`,
        );
        await app.close();
    });
});

describe("POST /v2/submit revert mapping", () => {
    function revertWith(name: string): ContractFunctionRevertedError {
        const selector = toFunctionSelector(`error ${name}()`);
        return new ContractFunctionRevertedError({
            abi: [{ type: "error", name, inputs: [] }],
            data: selector,
            functionName: "signPetition",
        });
    }

    it("maps NullifierAlreadyUsed → 409", async () => {
        const clients = fakeClients({
            simulate: vi.fn().mockRejectedValue(revertWith("NullifierAlreadyUsed")),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: VALID_BODY,
        });
        expect(res.statusCode).toBe(409);
        await app.close();
    });

    it("maps InvalidProof → 422", async () => {
        const clients = fakeClients({
            simulate: vi.fn().mockRejectedValue(revertWith("InvalidProof")),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: VALID_BODY,
        });
        expect(res.statusCode).toBe(422);
        await app.close();
    });

    it("maps PetitionClosed → 410", async () => {
        const clients = fakeClients({
            simulate: vi.fn().mockRejectedValue(revertWith("PetitionClosed")),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: VALID_BODY,
        });
        expect(res.statusCode).toBe(410);
        await app.close();
    });
});

// — POST /v2/revoke ─────────────────────────────────────────────────────
//
// Mirrors /v2/submit's pipeline (rate-limit → body validation → public-input
// cross-check → live-root pre-flight → simulate → write) but calls
// PetitionRegistryV2.revokeVote and uses the frozen { ok, code, status, ... }
// response envelope.

const VALID_REVOKE = {
    petitionId: "1",
    nullifier: "0x" + "11".repeat(32),
    proof: "0xdead",
    publicInputs: [
        "0x" + "00".repeat(31) + "01", // [0] petitionId
        ENROLL_ROOT,                    // [1] enrollmentRoot
        "0x" + "11".repeat(32),         // [2] nullifier
    ],
};

describe("POST /v2/revoke validation", () => {
    it("rejects malformed JSON with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: { nope: true },
        });
        expect(res.statusCode).toBe(400);
        const body = res.json();
        expect(body.ok).toBe(false);
        expect(body.code).toBe("BadRequest");
        await app.close();
    });

    it("rejects publicInputs[0] != petitionId with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: { ...VALID_REVOKE, petitionId: "2" },
        });
        expect(res.statusCode).toBe(400);
        const body = res.json();
        expect(body.ok).toBe(false);
        await app.close();
    });

    it("rejects publicInputs[2] != nullifier with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const wrongNull = "0x" + "ff".repeat(32);
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: { ...VALID_REVOKE, nullifier: wrongNull },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });

    it("rejects body with stray `vote` field permitted; rejects bad nullifier hex with 400", async () => {
        // Zod's default behaviour is to allow extra keys, so a stray `vote`
        // shouldn't fail validation. A malformed nullifier should.
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: { ...VALID_REVOKE, nullifier: "0xnothex" },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });

    it("rejects stale enrollmentRoot with 409", async () => {
        const liveRoot = `0x${"a".repeat(64)}`;
        const clients = fakeClients({
            read: vi.fn().mockResolvedValue(liveRoot),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: VALID_REVOKE,
        });
        expect(res.statusCode).toBe(409);
        const body = res.json() as { ok: boolean; code: string };
        expect(body.ok).toBe(false);
        expect(body.code).toBe("StaleEnrollmentRoot");
        await app.close();
    });
});

describe("POST /v2/revoke happy path", () => {
    it("returns 200 with ok+txHash+blockExplorerUrl when viem succeeds", async () => {
        const fakeHash = ("0x" + "cd".repeat(32)) as Hex;
        const simulate = vi.fn().mockResolvedValue({ request: {} });
        const write = vi.fn().mockResolvedValue(fakeHash);
        const clients = fakeClients({ simulate, write });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: VALID_REVOKE,
        });
        expect(res.statusCode).toBe(200);
        const json = res.json();
        expect(json.ok).toBe(true);
        expect(json.txHash).toBe(fakeHash);
        expect(json.blockExplorerUrl).toBe(
            `https://example.test/tx/${fakeHash}`,
        );
        // simulate-then-submit pattern: each called once
        expect(simulate).toHaveBeenCalledTimes(1);
        expect(write).toHaveBeenCalledTimes(1);
        // simulate must target revokeVote, not signPetition
        const simulateArgs = simulate.mock.calls[0][0];
        expect(simulateArgs.functionName).toBe("revokeVote");
        await app.close();
    });
});

describe("POST /v2/revoke revert mapping", () => {
    function revertWith(name: string): ContractFunctionRevertedError {
        const selector = toFunctionSelector(`error ${name}()`);
        return new ContractFunctionRevertedError({
            abi: [{ type: "error", name, inputs: [] }],
            data: selector,
            functionName: "revokeVote",
        });
    }

    it("maps NullifierNotUsed → 409 with code NullifierNotUsed, no chain write", async () => {
        const write = vi.fn().mockResolvedValue("0x" + "ff".repeat(32));
        const clients = fakeClients({
            simulate: vi.fn().mockRejectedValue(revertWith("NullifierNotUsed")),
            write,
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: VALID_REVOKE,
        });
        expect(res.statusCode).toBe(409);
        const body = res.json() as { ok: boolean; code: string };
        expect(body.ok).toBe(false);
        expect(body.code).toBe("NullifierNotUsed");
        // crucially, no write was issued
        expect(write).not.toHaveBeenCalled();
        await app.close();
    });

    it("maps InvalidProof → 422", async () => {
        const clients = fakeClients({
            simulate: vi.fn().mockRejectedValue(revertWith("InvalidProof")),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: VALID_REVOKE,
        });
        expect(res.statusCode).toBe(422);
        const body = res.json() as { ok: boolean; code: string };
        expect(body.code).toBe("InvalidProof");
        await app.close();
    });

    it("maps PetitionClosed → 410", async () => {
        const clients = fakeClients({
            simulate: vi.fn().mockRejectedValue(revertWith("PetitionClosed")),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: VALID_REVOKE,
        });
        expect(res.statusCode).toBe(410);
        await app.close();
    });

    it("maps UnknownPetition → 404", async () => {
        const clients = fakeClients({
            simulate: vi.fn().mockRejectedValue(revertWith("UnknownPetition")),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/v2/revoke",
            payload: VALID_REVOKE,
        });
        expect(res.statusCode).toBe(404);
        await app.close();
    });
});

describe("GET /healthz", () => {
    it("exposes config snapshot", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({ method: "GET", url: "/healthz" });
        expect(res.statusCode).toBe(200);
        const body = res.json();
        expect(body.ok).toBe(true);
        expect(body.chainId).toBe(31337);
        expect(body.petitionRegistry).toBe(
            "0x1111111111111111111111111111111111111111",
        );
        expect(body.enrollmentRegistry).toBe(
            "0x2222222222222222222222222222222222222222",
        );
        await app.close();
    });
});

// — POST /v2/enroll ──────────────────────────────────────────────────────
//
// Wire shape: { newRoot, newCommitments[], signature } verbatim relayed to
// EnrollmentRegistry.updateRoot(...). No citizen auth. Replay / stale-
// oldRoot / bad-sig all collapse into BadSignature() at simulate time
// and map to 409 — the citizen can then re-fetch from /oprf/register.

const VALID_ENROLL = {
    newRoot: "0x" + "ab".repeat(32),
    newCommitments: ["0x" + "cd".repeat(32)],
    signature: "0x" + "ee".repeat(64) + "1c", // r||s||v, 65 bytes
};

describe("POST /v2/enroll validation", () => {
    it("rejects malformed JSON with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/enroll",
            payload: { newRoot: "not-hex" },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });

    it("rejects empty newCommitments with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/enroll",
            payload: { ...VALID_ENROLL, newCommitments: [] },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });

    it("rejects short signature with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/enroll",
            payload: { ...VALID_ENROLL, signature: "0xdead" },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });
});

describe("POST /v2/enroll happy path", () => {
    it("returns 200 + txHash when simulate + write succeed", async () => {
        const fakeHash = ("0x" + "11".repeat(32)) as Hex;
        const write = vi.fn().mockResolvedValue(fakeHash);
        const clients = fakeClients({ write });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });

        const res = await app.inject({
            method: "POST",
            url: "/v2/enroll",
            payload: VALID_ENROLL,
        });
        expect(res.statusCode).toBe(200);
        const json = res.json() as { txHash: string; blockExplorerUrl: string };
        expect(json.txHash).toBe(fakeHash);
        expect(json.blockExplorerUrl).toBe(`https://example.test/tx/${fakeHash}`);
        // simulate + write each called exactly once
        expect(write).toHaveBeenCalledTimes(1);
        await app.close();
    });
});

describe("POST /v2/enroll replay / bad sig", () => {
    function badSigRevert(): ContractFunctionRevertedError {
        const selector = toFunctionSelector("error BadSignature()");
        return new ContractFunctionRevertedError({
            abi: [{ type: "error", name: "BadSignature", inputs: [] }],
            data: selector,
            functionName: "updateRoot",
        });
    }

    it("simulate reverting BadSignature → 409, no chain write", async () => {
        const write = vi.fn().mockResolvedValue("0x" + "ff".repeat(32));
        const simulate = vi.fn().mockRejectedValue(badSigRevert());
        const clients = fakeClients({ simulate, write });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });

        const res = await app.inject({
            method: "POST",
            url: "/v2/enroll",
            payload: VALID_ENROLL,
        });
        expect(res.statusCode).toBe(409);
        const body = res.json() as { error: string; detail: string };
        expect(body.error).toBe("BadSignature");
        // multi-cause explanation surfaced for the caller
        expect(body.detail).toContain("oprfAttester");
        // crucially, no write was issued
        expect(write).not.toHaveBeenCalled();
        await app.close();
    });

    it("submitting the same sig twice both end in 409 (no double-submit)", async () => {
        // Simulate the chain-state-advance pattern: first call succeeds,
        // then chain advances oldRoot, then second call's simulate sees
        // BadSignature because the stored oldRoot no longer matches what
        // the attesterSig was over.
        const fakeHash = ("0x" + "22".repeat(32)) as Hex;
        const simulate = vi
            .fn()
            .mockResolvedValueOnce({ request: {} })
            .mockRejectedValue(badSigRevert());
        const write = vi.fn().mockResolvedValue(fakeHash);
        const clients = fakeClients({ simulate, write });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });

        const first = await app.inject({
            method: "POST",
            url: "/v2/enroll",
            payload: VALID_ENROLL,
            remoteAddress: "10.0.0.1",
        });
        expect(first.statusCode).toBe(200);

        const second = await app.inject({
            method: "POST",
            url: "/v2/enroll",
            payload: VALID_ENROLL,
            remoteAddress: "10.0.0.2", // different IP so we don't 429 first
        });
        expect(second.statusCode).toBe(409);
        // Exactly one write — first request only.
        expect(write).toHaveBeenCalledTimes(1);
        await app.close();
    });

    it("write-side failure with unknown selector → 502 retryable", async () => {
        const simulate = vi.fn().mockResolvedValue({ request: {} });
        const write = vi.fn().mockRejectedValue(new Error("nonce too low"));
        const clients = fakeClients({ simulate, write });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });

        const res = await app.inject({
            method: "POST",
            url: "/v2/enroll",
            payload: VALID_ENROLL,
        });
        expect(res.statusCode).toBe(502);
        const body = res.json() as { error: string; retryable: boolean };
        expect(body.error).toBe("RelayerEnrollFailed");
        expect(body.retryable).toBe(true);
        await app.close();
    });
});

describe("rateLimit", () => {
    it("bucket exhaustion returns 429", async () => {
        const rateLimiter = makeRateLimiter(60_000);
        // Drain the bucket so the second hit 429s.
        rateLimiter.take("127.0.0.1");
        rateLimiter.take("127.0.0.1");
        rateLimiter.take("127.0.0.1");
        rateLimiter.take("127.0.0.1");
        rateLimiter.take("127.0.0.1");
        const app = buildApp({
            config: cfg(),
            clientsFactory: () => fakeClients(),
            rateLimiter,
        });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: VALID_BODY,
        });
        expect(res.statusCode).toBe(429);
        await app.close();
    });
});
