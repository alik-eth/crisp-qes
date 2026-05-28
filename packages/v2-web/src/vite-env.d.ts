/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_CHAIN_ID?: string;
    readonly VITE_RPC_URL?: string;
    readonly VITE_OPRF_URL?: string;
    readonly VITE_ENROLLMENT_REGISTRY?: string;
    readonly VITE_PETITION_REGISTRY_V2?: string;
    readonly VITE_RELAYER_URL?: string;
    readonly VITE_CIRCUIT_URL?: string;
    readonly VITE_BLOCK_EXPLORER?: string;
    readonly VITE_WALLETCONNECT_PROJECT_ID?: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
