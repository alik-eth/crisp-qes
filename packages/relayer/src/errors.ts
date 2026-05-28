// Map a viem-thrown error from `simulateContract` / `writeContract` to an
// HTTP status and a human-readable error code.

import {
    BaseError,
    ContractFunctionRevertedError,
    type Hex,
    toFunctionSelector,
} from "viem";

import { petitionRegistryAbi } from "./abi.js";

const SIGNER_ERROR_NAMES = [
    "UnknownPetition",
    "PetitionClosed",
    "NullifierAlreadyUsed",
    "InvalidProof",
    "InvalidTrustRoot",
    "InvalidSignature",
] as const;

type SignerErrorName = (typeof SIGNER_ERROR_NAMES)[number];

// selector -> name lookup. Built once at module load.
const SELECTOR_TO_NAME: Map<Hex, SignerErrorName> = new Map(
    SIGNER_ERROR_NAMES.map((name) => [
        toFunctionSelector(`error ${name}()`),
        name,
    ]),
);

export interface RelayerErrorResponse {
    status: number;
    body: {
        error: string;
        selector?: Hex;
        detail?: string;
    };
}

const STATUS_BY_NAME: Record<SignerErrorName, number> = {
    NullifierAlreadyUsed: 409,
    PetitionClosed: 410,
    UnknownPetition: 404,
    InvalidSignature: 422,
    InvalidProof: 422,
    InvalidTrustRoot: 422,
};

function findRevertSelector(err: unknown): Hex | undefined {
    if (!(err instanceof Error)) return undefined;
    // viem nests the contract revert under .cause; walk the chain.
    let cursor: unknown = err;
    while (cursor) {
        if (cursor instanceof ContractFunctionRevertedError) {
            const data = cursor.data;
            if (data && typeof data === "object" && "errorName" in data) {
                const name = (data as { errorName?: string }).errorName;
                if (name && SIGNER_ERROR_NAMES.includes(name as SignerErrorName)) {
                    return toFunctionSelector(`error ${name}()`);
                }
            }
            const raw = (cursor as ContractFunctionRevertedError & { raw?: Hex }).raw;
            if (raw && raw.length >= 10) return raw.slice(0, 10) as Hex;
        }
        if (cursor instanceof BaseError) {
            // some viem builds attach raw revert data on the outer error
            const meta = cursor as BaseError & {
                data?: Hex | { errorName?: string };
            };
            if (typeof meta.data === "string" && meta.data.startsWith("0x")) {
                return (meta.data as string).slice(0, 10) as Hex;
            }
        }
        cursor = (cursor as { cause?: unknown }).cause;
    }
    // last resort: scrape the message for "0x........"
    const m = err.message.match(/0x[0-9a-fA-F]{8}/);
    return m ? (m[0] as Hex) : undefined;
}

export function mapContractError(err: unknown): RelayerErrorResponse {
    const selector = findRevertSelector(err);
    const name = selector ? SELECTOR_TO_NAME.get(selector) : undefined;
    const detail = err instanceof Error ? err.message.split("\n")[0] : undefined;

    if (name) {
        return {
            status: STATUS_BY_NAME[name],
            body: { error: name, selector, detail },
        };
    }

    return {
        status: 500,
        body: {
            error: "RelayerSubmitFailed",
            selector,
            detail,
        },
    };
}

export { SIGNER_ERROR_NAMES, SELECTOR_TO_NAME };
// Re-export the ABI so `app.ts` can wire it without a second import path.
export { petitionRegistryAbi };
