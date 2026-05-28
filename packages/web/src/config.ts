// Runtime configuration sourced from Vite env vars (prefix VITE_).
//
// All values are required for the live demo; sensible localhost-ish
// defaults keep `pnpm dev` from crashing during early development.

import { base, baseSepolia, foundry } from "viem/chains";
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
        case base.id:
            return base;
        case baseSepolia.id:
            return baseSepolia;
        case foundry.id:
            return foundry;
        default:
            // Synthesise an ad-hoc chain — viem only needs id/name/rpc/nativeCurrency.
            return {
                id,
                name: `chain-${id}`,
                nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
                rpcUrls: { default: { http: [req("VITE_RPC_URL", "http://127.0.0.1:8545")] } },
            } satisfies Chain;
    }
}

export interface AppConfig {
    chain: Chain;
    chainId: number;
    rpcUrl: string;
    registry: `0x${string}`;
    relayerUrl: string;
    trustManifestUrl: string;
    circuitUrl: string;
    blockExplorerUrl: string;
}

export const config: AppConfig = {
    chain: pickChain(CHAIN_ID),
    chainId: CHAIN_ID,
    rpcUrl: req("VITE_RPC_URL", "http://127.0.0.1:8545"),
    registry: req(
        "VITE_REGISTRY_ADDRESS",
        "0x0000000000000000000000000000000000000000",
    ) as `0x${string}`,
    relayerUrl: req("VITE_RELAYER_URL", "http://127.0.0.1:8787"),
    trustManifestUrl: req("VITE_TRUST_MANIFEST_URL", "/trust-manifest.json"),
    circuitUrl: req("VITE_CIRCUIT_URL", "/crisp_qes_circuit.json"),
    blockExplorerUrl: req(
        "VITE_BLOCK_EXPLORER",
        CHAIN_ID === base.id
            ? "https://basescan.org"
            : CHAIN_ID === baseSepolia.id
              ? "https://sepolia.basescan.org"
              : "",
    ),
};
