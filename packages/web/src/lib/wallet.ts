// WalletConnect v2 (raw @walletconnect/ethereum-provider) wired into viem.
//
// We deliberately keep this thin: no wagmi, no reown/appkit, no tanstack-query.
// The provider package ships its own modal — `showQrModal: true` makes it open
// automatically on `connect()`. The result is wrapped in a viem
// `walletClient` so the rest of the app can call `writeContract` etc. with
// the same ergonomics as `publicClient`.

import { custom, createWalletClient, type WalletClient, type Address } from "viem";
import { config } from "../config";

// `@walletconnect/ethereum-provider` only ships ESM; we import the named
// `EthereumProvider` factory and use its `.init({ ... })` static.
import { EthereumProvider } from "@walletconnect/ethereum-provider";

export interface WalletSession {
    provider: Awaited<ReturnType<typeof EthereumProvider.init>>;
    client: WalletClient;
    address: Address;
    chainId: number;
}

let cached: Promise<Awaited<ReturnType<typeof EthereumProvider.init>>> | null = null;

async function getProvider() {
    if (cached) return cached;
    if (!config.walletConnectProjectId) {
        throw new Error("VITE_WALLETCONNECT_PROJECT_ID is not configured");
    }
    cached = EthereumProvider.init({
        projectId: config.walletConnectProjectId,
        showQrModal: true,
        // We only need a single EVM chain. `optionalChains` lets the wallet
        // upgrade the session if it already supports something else, but we
        // require Base Sepolia for our writes.
        chains: [config.chainId],
        optionalChains: [config.chainId],
        // RPC for direct dapp->wallet reads (rarely used; viem reads go via
        // publicClient). Keep it consistent with our config.
        rpcMap: { [config.chainId]: config.rpcUrl },
        methods: [
            "eth_sendTransaction",
            "eth_signTransaction",
            "eth_sign",
            "personal_sign",
            "eth_signTypedData",
            "eth_signTypedData_v4",
            "wallet_switchEthereumChain",
            "wallet_addEthereumChain",
        ],
        events: ["chainChanged", "accountsChanged", "disconnect"],
        metadata: {
            name: "CRISP-QES",
            description: "Privacy-preserving Diia QES petitions on Base",
            url:
                typeof window !== "undefined"
                    ? window.location.origin
                    : "https://crisp-qes-web.fly.dev",
            icons: [],
        },
    });
    return cached;
}

/**
 * Open the WalletConnect modal (if not already connected), then return a
 * viem walletClient wrapping the resulting EIP-1193 provider.
 *
 * Caller must `await ensureChain(...)` before submitting writes — we expose
 * that as a separate step so the UI can show a "switch chain" prompt.
 */
export async function connectWallet(): Promise<WalletSession> {
    const provider = await getProvider();
    if (!provider.session) {
        await provider.connect();
    }
    const accounts = (await provider.request({ method: "eth_accounts" })) as Address[];
    const address = accounts && accounts.length > 0 ? accounts[0] : undefined;
    if (!address) {
        throw new Error("Wallet returned no accounts");
    }
    const chainIdHex = (await provider.request({ method: "eth_chainId" })) as string;
    const chainId = Number.parseInt(chainIdHex, 16);

    const client = createWalletClient({
        account: address,
        chain: config.chain,
        transport: custom(provider as unknown as { request: (a: { method: string; params?: unknown }) => Promise<unknown> }),
    });

    return { provider, client, address, chainId };
}

/**
 * Ask the wallet to switch to our target chain. Returns the resulting
 * chainId. Throws if the user rejects.
 */
export async function ensureChain(session: WalletSession): Promise<number> {
    if (session.chainId === config.chainId) return session.chainId;
    const targetHex = "0x" + config.chainId.toString(16);
    try {
        await session.provider.request({
            method: "wallet_switchEthereumChain",
            params: [{ chainId: targetHex }],
        });
    } catch (err) {
        // 4902 = chain unknown to wallet; try adding it.
        const code = (err as { code?: number }).code;
        if (code === 4902) {
            await session.provider.request({
                method: "wallet_addEthereumChain",
                params: [
                    {
                        chainId: targetHex,
                        chainName: config.chain.name,
                        rpcUrls: [config.rpcUrl],
                        nativeCurrency: config.chain.nativeCurrency,
                        blockExplorerUrls: config.blockExplorerUrl
                            ? [config.blockExplorerUrl]
                            : [],
                    },
                ],
            });
        } else {
            throw err;
        }
    }
    const post = (await session.provider.request({ method: "eth_chainId" })) as string;
    return Number.parseInt(post, 16);
}

export async function disconnectWallet(): Promise<void> {
    if (!cached) return;
    const provider = await cached;
    try {
        await provider.disconnect();
    } catch {
        // ignore — provider may already be torn down
    }
}
