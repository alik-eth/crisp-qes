// Client for the v2 OPRF service (`packages/oprf`).
//
// Wire shapes, in lock-step with `packages/oprf/src/app.ts`:
//
//   POST /oprf/blind-eval
//     body: { blindedInput: hex32, attestation: { p7s: base64 } }
//     200:  { Y: hex32, proof: hex(64), blindedInput: hex32, oprfPubkey: hex32 }
//     401: AttestationError
//     400: BadRequest | BadBlindedInput
//
//   POST /oprf/register
//     body: { commitment: hex32, blindedInputUsed: hex32, unblindedOutput: hex32 }
//     200:  { leafIndex, merklePath: hex32[20], merklePathIndices: 0|1[20],
//             oldRoot: hex32, newRoot: hex32, newCommitments: hex32[],
//             attesterSig: hex, attesterAddr: hex }
//     400: BadRequest | CommitmentMismatch
//     409: AlreadyEnrolled
//
// `newCommitments` is passed through verbatim to
// `EnrollmentRegistry.updateRoot(newRoot, newCommitments, signature)`;
// the attester signs `keccak256(abi.encode(oldRoot, newRoot,
// keccak256(packed(newCommitments)), chainId, address(this)))`.
//
//   GET /enrollment/:commitment/path
//     200: { leafIndex, merklePath, merklePathIndices, root }
//     404: NotEnrolled

import { config } from "../config";

export interface BlindEvalResponse {
    /** 32-byte ristretto-encoded `Y = k * M`. */
    Y: `0x${string}`;
    /** Server pubkey `K = k*G` (32-byte ristretto encoding). */
    oprfPubkey: `0x${string}`;
    /** DLEQ proof: 64 bytes = `c (32 LE) || s (32 LE)`. */
    proof: `0x${string}`;
    /** Echo of the request's blindedInput (reconciliation). */
    blindedInput: `0x${string}`;
}

export interface RegisterResponse {
    leafIndex: number;
    merklePath: `0x${string}`[];
    merklePathIndices: (0 | 1)[];
    oldRoot: `0x${string}`;
    newRoot: `0x${string}`;
    /**
     * Batch passed verbatim to `EnrollmentRegistry.updateRoot`. For a single
     * enrollment this is `[commitment]`, but we never assume — the OPRF
     * service decides batch shape and pre-signs `attesterSig` over it.
     */
    newCommitments: `0x${string}`[];
    attesterSig: `0x${string}`;
    attesterAddr: `0x${string}`;
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
        let parsed: { error?: string; detail?: string } = {};
        try {
            parsed = (await r.json()) as typeof parsed;
        } catch {
            // body wasn't JSON
        }
        const err = new Error(
            `OPRF ${path} → ${r.status} ${parsed.error ?? ""} ${
                parsed.detail ?? ""
            }`.trim(),
        ) as Error & { status: number; code: string };
        err.status = r.status;
        err.code = parsed.error ?? "Unknown";
        throw err;
    }
    return (await r.json()) as T;
}

export async function oprfBlindEval(
    blindedElement: Uint8Array,
    p7sBytes: Uint8Array,
): Promise<BlindEvalResponse> {
    const resp: BlindEvalResponse = await postJson("/oprf/blind-eval", {
        blindedInput: hex(blindedElement),
        attestation: { p7s: toBase64(p7sBytes) },
    });

    // v2.1: pin the server's K_pub at build time and refuse anything else.
    // Without this, an MITM could substitute its own (K_pub*, k*) — DLEQ
    // would still pass against the spoofed pubkey, the server only ever
    // proves consistency to itself. v2.2 will move K_pub on-chain into
    // EnrollmentRegistry and the client will read it from there at boot.
    const expected = config.oprfPubkey.toLowerCase();
    const observed = resp.oprfPubkey.toLowerCase();
    if (observed !== expected) {
        const err = new Error(
            `oprf-pubkey-mismatch: server returned ${observed}, build pinned ${expected}`,
        ) as Error & { code: string };
        err.code = "OprfPubkeyMismatch";
        throw err;
    }

    return resp;
}

export async function oprfRegister(args: {
    commitment: `0x${string}`;
    blindedInputUsed: Uint8Array;
    unblindedOutput: Uint8Array;
}): Promise<RegisterResponse> {
    return postJson("/oprf/register", {
        commitment: args.commitment,
        blindedInputUsed: hex(args.blindedInputUsed),
        unblindedOutput: hex(args.unblindedOutput),
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
