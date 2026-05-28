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

function cfg(overrides: Partial<RelayerConfig> = {}): RelayerConfig {
    return {
        port: 0,
        chainId: 31337,
        rpcUrl: "http://127.0.0.1:8545",
        registry: "0x1111111111111111111111111111111111111111",
        privateKey: ANVIL_KEY,
        blockExplorerBase: "https://example.test/tx/",
        rateLimitWindowMs: 10_000,
        isProd: false,
        ...overrides,
    };
}

function fakeClients(impls: {
    simulate?: ReturnType<typeof vi.fn>;
    write?: ReturnType<typeof vi.fn>;
    getReceipt?: ReturnType<typeof vi.fn>;
    getTx?: ReturnType<typeof vi.fn>;
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
    leafPubkeyX: "0x" + "22".repeat(32),
    leafPubkeyY: "0x" + "33".repeat(32),
    leafSigR: "0x" + "44".repeat(32),
    leafSigS: "0x" + "55".repeat(32),
    intermediatePubkeyX: "0x" + "66".repeat(32),
    intermediatePubkeyY: "0x" + "77".repeat(32),
    intermediateSigR: "0x" + "88".repeat(32),
    intermediateSigS: "0x" + "99".repeat(32),
    proof: "0xdead",
    publicInputs: [
        "0x" + "00".repeat(31) + "01", // [0]  petitionId == 1
        "0x" + "11".repeat(32),         // [1]  nullifier
        "0x" + "aa".repeat(32),         // [2]  trustRoot
        "0x" + "22".repeat(32),         // [3]  leafPubkeyX
        "0x" + "33".repeat(32),         // [4]  leafPubkeyY
        "0x" + "66".repeat(32),         // [5]  intermediatePubkeyX
        "0x" + "77".repeat(32),         // [6]  intermediatePubkeyY
        "0x" + "00".repeat(16) + "bb".repeat(16), // [7]  leafTbsSha256_hi
        "0x" + "00".repeat(16) + "cc".repeat(16), // [8]  leafTbsSha256_lo
        "0x" + "00".repeat(16) + "dd".repeat(16), // [9]  signedAttrsSha256_hi
        "0x" + "00".repeat(16) + "ee".repeat(16), // [10] signedAttrsSha256_lo
    ],
};

describe("POST /submit validation", () => {
    it("rejects malformed JSON with 400", async () => {
        const app = buildApp({
            config: cfg(),
            clientsFactory: () => fakeClients(),
        });
        const res = await app.inject({
            method: "POST",
            url: "/submit",
            payload: { nope: true },
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });

    it("rejects mismatched publicInputs[0] vs petitionId", async () => {
        const app = buildApp({
            config: cfg(),
            clientsFactory: () => fakeClients(),
        });
        const body = {
            ...VALID_BODY,
            petitionId: "2",
        };
        const res = await app.inject({
            method: "POST",
            url: "/submit",
            payload: body,
        });
        expect(res.statusCode).toBe(400);
        await app.close();
    });
});

describe("POST /submit happy path", () => {
    it("returns 200 with txHash and blockExplorerUrl when viem succeeds", async () => {
        const fakeHash = ("0x" + "ab".repeat(32)) as Hex;
        const clients = fakeClients({
            write: vi.fn().mockResolvedValue(fakeHash),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/submit",
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

describe("POST /submit revert mapping", () => {
    it("maps NullifierAlreadyUsed simulate revert to 409", async () => {
        const selector = toFunctionSelector("error NullifierAlreadyUsed()");
        const revert = new ContractFunctionRevertedError({
            abi: [
                {
                    type: "error",
                    name: "NullifierAlreadyUsed",
                    inputs: [],
                },
            ],
            data: selector,
            functionName: "signPetition",
        });
        const clients = fakeClients({
            simulate: vi.fn().mockRejectedValue(revert),
        });
        const app = buildApp({ config: cfg(), clientsFactory: () => clients });
        const res = await app.inject({
            method: "POST",
            url: "/submit",
            payload: VALID_BODY,
        });
        expect(res.statusCode).toBe(409);
        expect(res.json().error).toBe("NullifierAlreadyUsed");
        await app.close();
    });
});

describe("GET /healthz", () => {
    it("returns chainId, registry, relayerAddr", async () => {
        const app = buildApp({
            config: cfg(),
            clientsFactory: () => fakeClients(),
        });
        const res = await app.inject({ method: "GET", url: "/healthz" });
        expect(res.statusCode).toBe(200);
        const j = res.json();
        expect(j.ok).toBe(true);
        expect(j.chainId).toBe(31337);
        expect(j.registry).toBe("0x1111111111111111111111111111111111111111");
        // anvil acct #0 address
        expect(j.relayerAddr.toLowerCase()).toBe(
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        );
        await app.close();
    });
});

describe("rate limiter", () => {
    it("returns 429 on the second submit from same IP inside window", async () => {
        // Use a real rate limiter with a long window. The injected requests
        // share IP 127.0.0.1.
        const app = buildApp({
            config: cfg(),
            clientsFactory: () => fakeClients(),
            rateLimiter: makeRateLimiter(60_000),
        });
        const first = await app.inject({
            method: "POST",
            url: "/submit",
            payload: VALID_BODY,
        });
        expect(first.statusCode).toBe(200);

        const second = await app.inject({
            method: "POST",
            url: "/submit",
            payload: VALID_BODY,
        });
        expect(second.statusCode).toBe(429);
        expect(second.json().error).toBe("RateLimited");
        await app.close();
    });

    it("allows a second request after the window expires", async () => {
        const limiter = makeRateLimiter(50);
        expect(limiter.take("1.2.3.4", 1000)).toBe(true);
        expect(limiter.take("1.2.3.4", 1010)).toBe(false);
        expect(limiter.take("1.2.3.4", 1100)).toBe(true);
    });
});
