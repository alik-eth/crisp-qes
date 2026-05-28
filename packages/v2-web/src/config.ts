// Runtime configuration from Vite env vars (VITE_ prefix).
//
// Many of the v2 endpoints depend on the OPRF + contracts deploy
// (tasks #30/#31/#32). Until those land, the build flow uses sentinel
// placeholders so `pnpm dev` and `vite build` still succeed; the actual
// deploy fills these in via `fly.toml [build.args]`.

import { baseSepolia, foundry } from "viem/chains";
import type { Chain } from "viem";

const env = import.meta.env;

function req(name: string, fallback: string): string {
    const v = env[name];
    if (typeof v === "string" && v.length > 0) return v;
    return fallback;
}

const CHAIN_ID = Number(req("VITE_CHAIN_ID", "84532"));

function pickChain(id: number): Chain {
    switch (id) {
        case baseSepolia.id:
            return baseSepolia;
        case foundry.id:
            return foundry;
        default:
            return {
                id,
                name: `chain-${id}`,
                nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
                rpcUrls: {
                    default: { http: [req("VITE_RPC_URL", "http://127.0.0.1:8545")] },
                },
            } satisfies Chain;
    }
}

export interface AppConfig {
    chain: Chain;
    chainId: number;
    rpcUrl: string;
    oprfUrl: string;
    enrollmentRegistry: `0x${string}`;
    petitionRegistryV2: `0x${string}`;
    relayerUrl: string;
    circuitUrl: string;
    blockExplorerUrl: string;
    walletConnectProjectId: string;
    /** Mirrors PetitionRegistryV2.CREATION_DEPOSIT (0.001 ether). */
    creationDepositWei: bigint;
    /** Mirrors PetitionRegistryV2.MAX_TEXT_BYTES (8 * 1024). */
    maxTextBytes: number;
}

const ZERO_ADDR = "0x0000000000000000000000000000000000000000" as const;

export const config: AppConfig = {
    chain: pickChain(CHAIN_ID),
    chainId: CHAIN_ID,
    rpcUrl: req("VITE_RPC_URL", "https://sepolia.base.org"),
    oprfUrl: req("VITE_OPRF_URL", "http://127.0.0.1:8788"),
    enrollmentRegistry: req("VITE_ENROLLMENT_REGISTRY", ZERO_ADDR) as `0x${string}`,
    petitionRegistryV2: req("VITE_PETITION_REGISTRY_V2", ZERO_ADDR) as `0x${string}`,
    relayerUrl: req("VITE_RELAYER_URL", "http://127.0.0.1:8787"),
    circuitUrl: req("VITE_CIRCUIT_URL", "/crisp_qes_v2_circuit.json"),
    blockExplorerUrl: req("VITE_BLOCK_EXPLORER", "https://sepolia.basescan.org"),
    walletConnectProjectId: req(
        "VITE_WALLETCONNECT_PROJECT_ID",
        "33a263ffda20d72b289cf92b369cfa47",
    ),
    creationDepositWei: 1_000_000_000_000_000n,
    maxTextBytes: 8 * 1024,
};
