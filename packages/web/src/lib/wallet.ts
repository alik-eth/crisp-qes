// Wallet connectors for the create-petition flow.
//
// We deliberately do NOT pull in wagmi, reown/appkit, or tanstack — the brief
// asks for raw plumbing. The catch with bare `@walletconnect/ethereum-provider`
// is that its built-in modal only offers mobile QR linking: it has no
// browser-extension picker. That's confusing for desktop users who already
// have MetaMask / Rabby / Frame / etc. installed.
//
// So we expose TWO connection paths and let the page render its own picker:
//
//   1. EIP-1193 injected providers, discovered via the EIP-6963 multi-provider
//      announcement protocol — covers all modern browser extensions; falls
//      back to the legacy `window.ethereum` shim if nothing announces itself.
//   2. WalletConnect v2 — opens the WC modal for mobile wallet QR pairing.
//
// Both paths return the same `WalletSession` shape so the page doesn't care
// which one the user picked.

import { custom, createWalletClient, type WalletClient, type Address } from "viem";
import { config } from "../config";
import { EthereumProvider } from "@walletconnect/ethereum-provider";

// EIP-1193 provider surface we actually use. Keeping it structural avoids
// importing wallet-specific types.
export interface Eip1193Provider {
    request(args: { method: string; params?: unknown[] | object }): Promise<unknown>;
    on?(event: string, listener: (...args: unknown[]) => void): void;
    removeListener?(event: string, listener: (...args: unknown[]) => void): void;
}

// EIP-6963 announcement record — what a browser wallet broadcasts.
export interface InjectedDetail {
    info: {
        uuid: string;
        name: string;
        icon: string; // data: URL
        rdns: string; // reverse-dns id, e.g. io.metamask
    };
    provider: Eip1193Provider;
}

export type WalletKind = "injected" | "walletconnect";

export interface WalletSession {
    kind: WalletKind;
    provider: Eip1193Provider;
    client: WalletClient;
    address: Address;
    chainId: number;
    /** Human-readable label for the connected wallet (e.g. "MetaMask"). */
    label: string;
    /** Optional data: URL icon, set for EIP-6963 wallets. */
    icon?: string;
}

// -------------------- EIP-6963 discovery --------------------

const _injected: InjectedDetail[] = [];
let _injectedListening = false;

/**
 * Start listening for EIP-6963 announcements. Wallets respond synchronously
 * to a `requestProvider` event with a `providerDetail`. Subsequent
 * announcements are also captured (some wallets announce on every load).
 *
 * Safe to call repeatedly; it's idempotent.
 */
export function startInjectedDiscovery(): void {
    if (_injectedListening || typeof window === "undefined") return;
    _injectedListening = true;

    window.addEventListener("eip6963:announceProvider", (ev: Event) => {
        const detail = (ev as CustomEvent<InjectedDetail>).detail;
        if (!detail || !detail.info) return;
        // Dedupe by uuid — extensions sometimes announce more than once.
        if (_injected.some((d) => d.info.uuid === detail.info.uuid)) return;
        _injected.push(detail);
    });

    window.dispatchEvent(new Event("eip6963:requestProvider"));
}

/**
 * Return all injected wallets known so far. If no EIP-6963 wallet has
 * announced itself, fall back to the legacy `window.ethereum` shim
 * (covers old MetaMask versions and a few exotic mobile in-app browsers).
 */
export function listInjectedProviders(): InjectedDetail[] {
    if (_injected.length > 0) return _injected.slice();
    if (typeof window !== "undefined") {
        const legacy = (window as unknown as { ethereum?: Eip1193Provider }).ethereum;
        if (legacy) {
            return [
                {
                    info: {
                        uuid: "legacy-window-ethereum",
                        name: "Browser wallet",
                        icon: "",
                        rdns: "legacy",
                    },
                    provider: legacy,
                },
            ];
        }
    }
    return [];
}

// -------------------- injected (browser extension) --------------------

export async function connectInjected(detail: InjectedDetail): Promise<WalletSession> {
    const provider = detail.provider;
    const accounts = (await provider.request({
        method: "eth_requestAccounts",
    })) as Address[];
    const address = accounts && accounts.length > 0 ? accounts[0] : undefined;
    if (!address) throw new Error("Wallet returned no accounts");

    const chainIdHex = (await provider.request({ method: "eth_chainId" })) as string;
    const chainId = Number.parseInt(chainIdHex, 16);

    const client = createWalletClient({
        account: address,
        chain: config.chain,
        transport: custom(provider as unknown as { request: (a: { method: string; params?: unknown }) => Promise<unknown> }),
    });

    return {
        kind: "injected",
        provider,
        client,
        address,
        chainId,
        label: detail.info.name,
        icon: detail.info.icon || undefined,
    };
}

// -------------------- WalletConnect v2 --------------------

let _wcInit: Promise<Awaited<ReturnType<typeof EthereumProvider.init>>> | null = null;

async function getWcProvider() {
    if (_wcInit) return _wcInit;
    if (!config.walletConnectProjectId) {
        throw new Error("VITE_WALLETCONNECT_PROJECT_ID is not configured");
    }
    _wcInit = EthereumProvider.init({
        projectId: config.walletConnectProjectId,
        showQrModal: true,
        chains: [config.chainId],
        optionalChains: [config.chainId],
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
    return _wcInit;
}

export async function connectWalletConnect(): Promise<WalletSession> {
    const provider = await getWcProvider();
    if (!provider.session) {
        await provider.connect();
    }
    const accounts = (await provider.request({ method: "eth_accounts" })) as Address[];
    const address = accounts && accounts.length > 0 ? accounts[0] : undefined;
    if (!address) throw new Error("Wallet returned no accounts");

    const chainIdHex = (await provider.request({ method: "eth_chainId" })) as string;
    const chainId = Number.parseInt(chainIdHex, 16);

    const client = createWalletClient({
        account: address,
        chain: config.chain,
        transport: custom(provider as unknown as { request: (a: { method: string; params?: unknown }) => Promise<unknown> }),
    });

    return {
        kind: "walletconnect",
        provider: provider as unknown as Eip1193Provider,
        client,
        address,
        chainId,
        label: "WalletConnect",
    };
}

// -------------------- chain switch / disconnect --------------------

/**
 * Ask the wallet to switch to our target chain. Returns the resulting chainId.
 * Throws if the user rejects.
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

export async function disconnectWallet(session: WalletSession | null): Promise<void> {
    if (!session) return;
    if (session.kind === "walletconnect" && _wcInit) {
        try {
            const p = await _wcInit;
            await p.disconnect();
        } catch {
            // ignore
        }
    }
    // For injected wallets, EIP-1193 has no canonical disconnect — extensions
    // manage their own permission state. We just clear our local state in the
    // caller.
}
