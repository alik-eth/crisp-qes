// Relayer client. Endpoint shape mirrors packages/relayer/src/app.ts.

import { config } from "../config";

export interface SubmitArgs {
    petitionId: bigint;
    nullifier: string;
    leafPubkeyX: string;
    leafPubkeyY: string;
    leafSigR: string;
    leafSigS: string;
    intermediatePubkeyX: string;
    intermediatePubkeyY: string;
    intermediateSigR: string;
    intermediateSigS: string;
    proof: string;
    publicInputs: string[];
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

export async function submitSignature(args: SubmitArgs): Promise<SubmitOk | SubmitErr> {
    const body = {
        petitionId: args.petitionId.toString(10),
        nullifier: args.nullifier,
        leafPubkeyX: args.leafPubkeyX,
        leafPubkeyY: args.leafPubkeyY,
        leafSigR: args.leafSigR,
        leafSigS: args.leafSigS,
        intermediatePubkeyX: args.intermediatePubkeyX,
        intermediatePubkeyY: args.intermediatePubkeyY,
        intermediateSigR: args.intermediateSigR,
        intermediateSigS: args.intermediateSigS,
        proof: args.proof,
        publicInputs: args.publicInputs,
    };
    let res: Response;
    try {
        res = await fetch(`${config.relayerUrl}/submit`, {
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
