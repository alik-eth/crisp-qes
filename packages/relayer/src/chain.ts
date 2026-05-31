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
    /**
     * Serialized contract write. All on-chain writes funnel through one
     * promise queue with a managed sequential nonce, so concurrent requests
     * on the single relayer key cannot collide on the same nonce. Adds
     * `account`, `chain`, and `nonce` automatically — callers pass only the
     * contract call params (address, abi, functionName, args, gas, value…).
     */
    sendTx: (params: Record<string, unknown>) => Promise<Hex>;
}

export function makeClients(cfg: RelayerConfig): Clients {
    const chain = resolveChain(cfg);
    const transport = http(cfg.rpcUrl);
    const account = privateKeyToAccount(cfg.privateKey as Hex);
    const publicClient = createPublicClient({ chain, transport });
    const walletClient = createWalletClient({ account, chain, transport });

    let queue: Promise<unknown> = Promise.resolve();
    let nextNonce: number | null = null;

    const sendTx = (params: Record<string, unknown>): Promise<Hex> => {
        const run = async (): Promise<Hex> => {
            if (nextNonce === null) {
                nextNonce = await publicClient.getTransactionCount({
                    address: account.address,
                    blockTag: "pending",
                });
            }
            const nonce = nextNonce;
            try {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                const hash = (await walletClient.writeContract({
                    ...(params as any),
                    account,
                    chain,
                    nonce,
                })) as Hex;
                nextNonce = nonce + 1;
                return hash;
            } catch (err) {
                // The nonce is now uncertain (tx may not have been accepted);
                // force a fresh read from the chain on the next send.
                nextNonce = null;
                throw err;
            }
        };
        // Chain onto the queue so runs execute strictly one-at-a-time. Keep
        // the queue alive regardless of this run's success/failure.
        const result = queue.then(run, run);
        queue = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    };

    return { publicClient, walletClient, account, chain, sendTx };
}
