// v2 relayer client. Endpoint shape coordinates with task #34 (N5).
//
// For demo purposes the relayer accepts `vote` + the 3-input public
// array `[petition_id, enrollment_root, nullifier]` and posts
// `PetitionRegistryV2.signPetition` on behalf of the citizen. No
// per-citizen fee — the relayer absorbs gas.

import { config } from "../config";

export interface SubmitArgs {
    petitionId: bigint;
    vote: number;
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
        vote: args.vote,
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

export function basescanTxUrl(txHash: string): string {
    if (!config.blockExplorerUrl) return "";
    const base = config.blockExplorerUrl.replace(/\/$/, "");
    return `${base}/tx/${txHash}`;
}
