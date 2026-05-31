// Map a viem-thrown error from `simulateContract` / `writeContract` to an
// HTTP status and a human-readable error code.

import {
    BaseError,
    ContractFunctionRevertedError,
    type Hex,
    toFunctionSelector,
} from "viem";

import { petitionRegistryV2Abi } from "./abi.js";

const SIGNER_ERROR_NAMES = [
    "UnknownPetition",
    "PetitionClosed",
    "NullifierAlreadyUsed",
    "NullifierNotUsed",
    "InvalidProof",
    "InvalidEnrollmentRoot",
] as const;

type SignerErrorName = (typeof SIGNER_ERROR_NAMES)[number];

// selector -> name lookup. Built once at module load.
const SELECTOR_TO_NAME: Map<Hex, SignerErrorName> = new Map(
    SIGNER_ERROR_NAMES.map((name) => [
        toFunctionSelector(`error ${name}()`),
        name,
    ]),
);

// — EnrollmentRegistry custom errors ───────────────────────────────────────
//
// Surface on `POST /v2/enroll`. `BadSignature` is the multi-cause bucket:
// replay (citizen retried after a previous successful submit), stale oldRoot
// (OPRF DB drifted from chain by another concurrent enroll), or genuinely
// malformed sig. All three look the same to the contract — ecrecover yields
// the wrong address. From the relayer's POV they collapse into "the same
// attesterSig won't land this update", which is a 409 Conflict semantically:
// the citizen can resolve by re-fetching a fresh sig from `/oprf/register`.
const ENROLL_ERROR_NAMES = [
    "BadSignature",
    "EmptyBatch",
] as const;

type EnrollErrorName = (typeof ENROLL_ERROR_NAMES)[number];

const ENROLL_SELECTOR_TO_NAME: Map<Hex, EnrollErrorName> = new Map(
    ENROLL_ERROR_NAMES.map((name) => [
        toFunctionSelector(`error ${name}()`),
        name,
    ]),
);

const ENROLL_STATUS_BY_NAME: Record<EnrollErrorName, number> = {
    BadSignature: 409,
    EmptyBatch: 400,
};

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
    NullifierNotUsed: 409,
    PetitionClosed: 410,
    UnknownPetition: 404,
    InvalidProof: 422,
    InvalidEnrollmentRoot: 422,
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

// Classify a TRANSACTION-level failure that is NOT a contract revert — these
// surface from writeContract (gas estimation / broadcast), not the contract's
// own `revert`, so they have no selector. Previously they fell through to the
// generic "RelayerSubmitFailed / signPetition reverted", which is misleading:
// the proof may be perfectly valid and the real cause is the relayer account
// being out of gas money (simulate is a free eth_call and passes; the write
// can't be paid for) or a nonce conflict. Walk the viem cause chain by both
// error name and message text (node RPC errors only carry a message).
function classifyTxError(
    err: unknown,
): { error: string; status: number; detail: string } | undefined {
    const msgs: string[] = [];
    let cursor: unknown = err;
    while (cursor) {
        if (cursor instanceof Error) {
            const name = cursor.name ?? "";
            if (name === "InsufficientFundsError") {
                return {
                    error: "InsufficientRelayerFunds",
                    status: 503,
                    detail:
                        "relayer account has insufficient ETH to pay gas — fund the relayer key",
                };
            }
            if (/^Nonce(TooLow|TooHigh|MaxValue)Error$/.test(name)) {
                return {
                    error: "RelayerNonceError",
                    status: 503,
                    detail: "relayer nonce conflict — transient, retry",
                };
            }
            if (cursor.message) msgs.push(cursor.message);
        }
        cursor = (cursor as { cause?: unknown }).cause;
    }
    const blob = msgs.join(" | ").toLowerCase();
    if (/insufficient funds/.test(blob)) {
        return {
            error: "InsufficientRelayerFunds",
            status: 503,
            detail:
                "relayer account has insufficient ETH to pay gas — fund the relayer key",
        };
    }
    if (/nonce too (low|high)|replacement transaction underpriced/.test(blob)) {
        return {
            error: "RelayerNonceError",
            status: 503,
            detail: "relayer nonce conflict — transient, retry",
        };
    }
    return undefined;
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

    // Not a known contract revert — is it a tx-level failure (funds / nonce)?
    const tx = classifyTxError(err);
    if (tx) {
        return { status: tx.status, body: { error: tx.error, detail: tx.detail } };
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

// Same shape as `mapContractError`, but bound to the EnrollmentRegistry
// error set. Lives in this module so the chain-walk + selector-fallback
// behaviour stays consistent across endpoints.
export function mapEnrollmentError(err: unknown): RelayerErrorResponse {
    const selector = findRevertSelector(err);
    const name = selector
        ? ENROLL_SELECTOR_TO_NAME.get(selector)
        : undefined;
    const detail = err instanceof Error ? err.message.split("\n")[0] : undefined;

    if (name) {
        const baseBody: RelayerErrorResponse["body"] = {
            error: name,
            selector,
            detail,
        };
        if (name === "BadSignature") {
            // Expand the multi-cause bucket for the caller.
            baseBody.detail =
                (detail ? detail + " — " : "") +
                "the attester signature does not recover to the registered oprfAttester. " +
                "Most common cause: the OPRF service's view of currentRoot has drifted from " +
                "the on-chain enrollmentRoot (concurrent enrollment landed in between), " +
                "or the same attesterSig was already used. Re-fetch a fresh sig from " +
                "/oprf/register and retry.";
        }
        return { status: ENROLL_STATUS_BY_NAME[name], body: baseBody };
    }

    // Not a known contract revert — funds / nonce tx-level failure?
    const tx = classifyTxError(err);
    if (tx) {
        return { status: tx.status, body: { error: tx.error, detail: tx.detail } };
    }

    return {
        status: 500,
        body: {
            error: "RelayerEnrollFailed",
            selector,
            detail,
        },
    };
}

export {
    SIGNER_ERROR_NAMES,
    SELECTOR_TO_NAME,
    ENROLL_ERROR_NAMES,
    ENROLL_SELECTOR_TO_NAME,
};
// Re-export the ABI so `app.ts` can wire it without a second import path.
export { petitionRegistryV2Abi };
