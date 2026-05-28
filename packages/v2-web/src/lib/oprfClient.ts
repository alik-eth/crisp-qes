// Client for the v2 OPRF service (task #32, single-node Fastify).
//
// Wire shape mirrors §3.1 of the v2 spec:
//
//   POST /oprf/blind-eval
//     body: { blindedInput: hex, attestation: { p7s: base64 } }
//     200:  { Y: hex, kSchnorrProof: { c: hex, s: hex }, K: hex }
//
//   POST /oprf/register
//     body: { commitment: hex32, blindedInputUsed: hex }
//     200:  { leafIndex, merklePath: hex32[20], merklePathIndices: 0|1[20],
//             oldRoot: hex32, newRoot: hex32, attesterSig: hex }
//     409:  { error: "already enrolled" }
//
//   GET /enrollment/:commitment/path
//     200: { leafIndex, merklePath, merklePathIndices, root }
//
// Until task #32 deploys its real `/healthz` shape we keep the routes
// loose with `unknown` JSON; the typed surface below is what the
// enrollment flow consumes after we narrow.

import { config } from "../config";

export interface BlindEvalResponse {
    /** 32-byte ristretto-encoded `Y = k * M`. */
    Y: `0x${string}`;
    /** Server pubkey `K = k*G` (32-byte ristretto encoding). */
    K: `0x${string}`;
    /** DLEQ proof: c, s as 32-byte little-endian scalars. */
    proof: { c: `0x${string}`; s: `0x${string}` };
}

export interface RegisterResponse {
    leafIndex: number;
    merklePath: `0x${string}`[];
    merklePathIndices: (0 | 1)[];
    oldRoot: `0x${string}`;
    newRoot: `0x${string}`;
    attesterSig: `0x${string}`;
}

export interface RecoverPathResponse {
    leafIndex: number;
    merklePath: `0x${string}`[];
    merklePathIndices: (0 | 1)[];
    root: `0x${string}`;
}

function toBase64(b: Uint8Array): string {
    let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
    return btoa(s);
}

function hex(b: Uint8Array): `0x${string}` {
    let s = "0x";
    for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
    return s as `0x${string}`;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
    const r = await fetch(`${config.oprfUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
    if (!r.ok) {
        let detail: string;
        try {
            detail = JSON.stringify(await r.json());
        } catch {
            detail = await r.text();
        }
        const err = new Error(`OPRF ${path} → ${r.status}: ${detail}`);
        (err as Error & { status: number }).status = r.status;
        throw err;
    }
    return (await r.json()) as T;
}

export async function oprfBlindEval(
    blindedElement: Uint8Array,
    p7sBytes: Uint8Array,
): Promise<BlindEvalResponse> {
    return postJson("/oprf/blind-eval", {
        blindedInput: hex(blindedElement),
        attestation: { p7s: toBase64(p7sBytes) },
    });
}

export async function oprfRegister(
    commitment: `0x${string}`,
    blindedInputUsed: Uint8Array,
): Promise<RegisterResponse> {
    return postJson("/oprf/register", {
        commitment,
        blindedInputUsed: hex(blindedInputUsed),
    });
}

export async function oprfRecoverPath(
    commitment: `0x${string}`,
): Promise<RecoverPathResponse> {
    const r = await fetch(
        `${config.oprfUrl}/enrollment/${commitment}/path`,
        { method: "GET" },
    );
    if (r.status === 404) throw new Error("commitment not enrolled");
    if (!r.ok) throw new Error(`OPRF recover → ${r.status}`);
    return (await r.json()) as RecoverPathResponse;
}
