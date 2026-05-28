// Wallet/public client factories. Isolated in its own module so the test
// suite can `vi.mock` it and swap in fake clients without booting viem
// against a real RPC.

import {
    type Chain,
    type Hex,
    type PublicClient,
    type WalletClient,
    createPublicClient,
    createWalletClient,
    defineChain,
    http,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia, sepolia } from "viem/chains";

import type { RelayerConfig } from "./config.js";

function resolveChain(cfg: RelayerConfig): Chain {
    switch (cfg.chainId) {
        case 8453:
            return base;
        case 84532:
            return baseSepolia;
        case 11155111:
            return sepolia;
        default:
            return defineChain({
                id: cfg.chainId,
                name: `chain-${cfg.chainId}`,
                nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
                rpcUrls: { default: { http: [cfg.rpcUrl] } },
            });
    }
}

export interface Clients {
    publicClient: PublicClient;
    walletClient: WalletClient;
    account: ReturnType<typeof privateKeyToAccount>;
    chain: Chain;
}

export function makeClients(cfg: RelayerConfig): Clients {
    const chain = resolveChain(cfg);
    const transport = http(cfg.rpcUrl);
    const account = privateKeyToAccount(cfg.privateKey as Hex);
    const publicClient = createPublicClient({ chain, transport });
    const walletClient = createWalletClient({ account, chain, transport });
    return { publicClient, walletClient, account, chain };
}
