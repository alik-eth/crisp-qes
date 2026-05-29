// v2 relayer client. Endpoint shape coordinates with task #34 (N5).
//
// A petition is support-only: the relayer accepts the 3-input public
// array `[petition_id, enrollment_root, nullifier]` and posts
// `PetitionRegistryV2.signPetition` on behalf of the citizen. No vote,
// no per-citizen fee — the relayer absorbs gas.

import { config } from "../config";

export interface SubmitArgs {
    petitionId: bigint;
    nullifier: `0x${string}`;
    proof: `0x${string}`;
    /** Length 3: [petition_id, enrollment_root, nullifier] — as 0x-hex32. */
    publicInputs: `0x${string}`[];
}

export interface SubmitOk {
    ok: true;
    txHash: `0x${string}`;
    blockExplorerUrl: string | null;
}

export interface SubmitErr {
    ok: false;
    code: string;
    status: number;
    detail?: string;
}

export async function submitSignature(
    args: SubmitArgs,
): Promise<SubmitOk | SubmitErr> {
    const body = {
        petitionId: args.petitionId.toString(10),
        nullifier: args.nullifier,
        proof: args.proof,
        publicInputs: args.publicInputs,
    };
    let res: Response;
    try {
        res = await fetch(`${config.relayerUrl}/v2/submit`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
        });
    } catch (err) {
        return {
            ok: false,
            code: "Network",
            status: 0,
            detail: err instanceof Error ? err.message : String(err),
        };
    }
    if (res.status === 200) {
        const j = (await res.json()) as SubmitOk;
        return { ...j, ok: true };
    }
    let parsed: { error?: string; detail?: string } = {};
    try {
        parsed = (await res.json()) as typeof parsed;
    } catch {
        // body wasn't JSON
    }
    return {
        ok: false,
        code: parsed.error ?? "Unknown",
        status: res.status,
        detail: parsed.detail,
    };
}

// Mirrors `submitSignature`. The relayer posts `revokeVote(petitionId,
// nullifier, proof, publicInputs)` on behalf of the citizen.
//
// Endpoint shape per the v2 relayer brief:
//   POST <RELAYER_URL>/v2/revoke
//   body: { petitionId, nullifier, proof, publicInputs }
//   200:  { ok: true, txHash, blockExplorerUrl }
//   err:  { ok: false, code, status, detail? }
//
// `code` of "NullifierNotUsed" means the citizen tried to revoke a
// petition they hadn't signed (or the chain already saw a revoke).
export interface RevokeArgs {
    petitionId: bigint;
    nullifier: `0x${string}`;
    proof: `0x${string}`;
    /** Length 3: [petition_id, enrollment_root, nullifier] — as 0x-hex32. */
    publicInputs: `0x${string}`[];
}

export async function submitRevoke(
    args: RevokeArgs,
): Promise<SubmitOk | SubmitErr> {
    const body = {
        petitionId: args.petitionId.toString(10),
        nullifier: args.nullifier,
        proof: args.proof,
        publicInputs: args.publicInputs,
    };
    let res: Response;
    try {
        res = await fetch(`${config.relayerUrl}/v2/revoke`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
        });
    } catch (err) {
        return {
            ok: false,
            code: "Network",
            status: 0,
            detail: err instanceof Error ? err.message : String(err),
        };
    }
    if (res.status === 200) {
        const j = (await res.json()) as SubmitOk;
        return { ...j, ok: true };
    }
    let parsed: { error?: string; detail?: string } = {};
    try {
        parsed = (await res.json()) as typeof parsed;
    } catch {
        // body wasn't JSON
    }
    return {
        ok: false,
        code: parsed.error ?? "Unknown",
        status: res.status,
        detail: parsed.detail,
    };
}

// Renamed from `basescanTxUrl` post-#61 cutover (Base Sepolia →
// Ethereum Sepolia). The body always read `config.blockExplorerUrl`
// dynamically — only the symbol was brand-leaking.
export function explorerTxUrl(txHash: string): string {
    if (!config.blockExplorerUrl) return "";
    const base = config.blockExplorerUrl.replace(/\/$/, "");
    return `${base}/tx/${txHash}`;
}

// #55 — relayer-default enrollment submit. When the citizen has no wallet
// connected (the default UX), the relayer signs `EnrollmentRegistry.
// updateRoot(newRoot, newCommitments, signature)` on their behalf so they
// don't need to touch ETH to enroll. Wallet path remains available via
// the existing self-submit flow in Enroll.tsx.
//
// Endpoint shape per team-lead's #55 brief:
//   POST <RELAYER_URL>/v2/enroll
//   body: { newRoot, newCommitments, signature }
//   200:  { txHash, blockNumber, status }

export interface EnrollSubmitArgs {
    newRoot: `0x${string}`;
    newCommitments: `0x${string}`[];
    /** Attester sig from the OPRF service (65 bytes EIP-191). */
    signature: `0x${string}`;
}

export interface EnrollSubmitOk {
    ok: true;
    txHash: `0x${string}`;
    blockNumber: number;
    status: "success";
}

export interface EnrollSubmitErr {
    ok: false;
    code: string;
    status: number;
    detail?: string;
}

export async function submitEnrollment(
    args: EnrollSubmitArgs,
): Promise<EnrollSubmitOk | EnrollSubmitErr> {
    let res: Response;
    try {
        res = await fetch(`${config.relayerUrl}/v2/enroll`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                newRoot: args.newRoot,
                newCommitments: args.newCommitments,
                signature: args.signature,
            }),
        });
    } catch (err) {
        return {
            ok: false,
            code: "Network",
            status: 0,
            detail: err instanceof Error ? err.message : String(err),
        };
    }
    if (res.status === 200) {
        const j = (await res.json()) as {
            txHash: `0x${string}`;
            blockNumber: number;
            status?: "success";
        };
        return {
            ok: true,
            txHash: j.txHash,
            blockNumber: j.blockNumber,
            status: "success",
        };
    }
    let parsed: { error?: string; detail?: string } = {};
    try {
        parsed = (await res.json()) as typeof parsed;
    } catch {
        // body wasn't JSON
    }
    return {
        ok: false,
        code: parsed.error ?? "Unknown",
        status: res.status,
        detail: parsed.detail,
    };
}
