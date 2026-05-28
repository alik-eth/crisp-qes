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
    vote: 0,
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

    it("rejects vote > 2 with 400", async () => {
        const app = buildApp({ config: cfg(), clientsFactory: () => fakeClients() });
        const res = await app.inject({
            method: "POST",
            url: "/v2/submit",
            payload: { ...VALID_BODY, vote: 3 },
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
