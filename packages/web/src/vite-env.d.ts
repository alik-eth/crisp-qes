/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_CHAIN_ID?: string;
    readonly VITE_RPC_URL?: string;
    readonly VITE_REGISTRY_ADDRESS?: string;
    readonly VITE_RELAYER_URL?: string;
    readonly VITE_TRUST_MANIFEST_URL?: string;
    readonly VITE_CIRCUIT_URL?: string;
    readonly VITE_BLOCK_EXPLORER?: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
