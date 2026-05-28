import type { Hex } from "viem";

export interface RelayerConfig {
    port: number;
    chainId: number;
    rpcUrl: string;
    registry: `0x${string}`;
    privateKey: Hex;
    blockExplorerBase: string;
    rateLimitWindowMs: number;
    isProd: boolean;
    /**
     * CORS allow-list for the public submit endpoint.
     *
     * The web client (https://crisp-qes-web.fly.dev) is on a different
     * origin, so without explicit CORS the browser blocks the POST to
     * /submit before it even leaves the tab.
     *
     * Parsed from `CORS_ALLOWED_ORIGINS` (comma-separated). Defaults to
     * the production web origin in prod, or `*` in dev.
     */
    corsAllowedOrigins: string[];
}

// Dev defaults: anvil chain id, localhost RPC, the well-known anvil
// account #0 private key. NEVER use this in production.
const ANVIL_DEFAULT_KEY: Hex =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const ZERO_ADDR = "0x0000000000000000000000000000000000000000" as const;

function pickExplorer(chainId: number): string {
    switch (chainId) {
        case 84532:
            return "https://sepolia.basescan.org/tx/";
        case 8453:
            return "https://basescan.org/tx/";
        case 11155111:
            return "https://sepolia.etherscan.io/tx/";
        case 31337:
            return "http://localhost:8545/tx/";
        default:
            return "";
    }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayerConfig {
    const nodeEnv = env.NODE_ENV ?? "development";
    const isProd = nodeEnv === "production";

    const chainId = Number(env.CHAIN_ID ?? (isProd ? 84532 : 31337));
    const rpcUrl =
        env.RPC_URL ?? (isProd ? "" : "http://127.0.0.1:8545");

    const registry = (env.PETITION_REGISTRY ?? (isProd ? "" : ZERO_ADDR)) as
        | `0x${string}`
        | "";
    const privateKey = (env.RELAYER_PRIVATE_KEY ?? (isProd ? "" : ANVIL_DEFAULT_KEY)) as
        | Hex
        | "";

    if (isProd) {
        if (!privateKey) {
            throw new Error(
                "[relayer] RELAYER_PRIVATE_KEY is required in production",
            );
        }
        if (!registry) {
            throw new Error(
                "[relayer] PETITION_REGISTRY is required in production",
            );
        }
        if (!rpcUrl) {
            throw new Error("[relayer] RPC_URL is required in production");
        }
    }

    if (!/^0x[0-9a-fA-F]{40}$/.test(registry)) {
        throw new Error(
            `[relayer] PETITION_REGISTRY must be a 20-byte hex address, got ${registry}`,
        );
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
        throw new Error(
            "[relayer] RELAYER_PRIVATE_KEY must be a 32-byte hex string",
        );
    }

    const corsRaw =
        env.CORS_ALLOWED_ORIGINS ??
        (isProd ? "https://crisp-qes-web.fly.dev" : "*");
    const corsAllowedOrigins = corsRaw
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);

    return {
        port: Number(env.PORT ?? 8787),
        chainId,
        rpcUrl,
        registry: registry as `0x${string}`,
        privateKey: privateKey as Hex,
        blockExplorerBase: env.BLOCK_EXPLORER_BASE ?? pickExplorer(chainId),
        rateLimitWindowMs: Number(env.RATE_LIMIT_WINDOW_MS ?? 10_000),
        isProd,
        corsAllowedOrigins,
    };
}
