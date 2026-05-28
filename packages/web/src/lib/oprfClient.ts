// Client for the v2 OPRF service (`packages/oprf`).
//
// Wire shapes, in lock-step with `packages/oprf/src/app.ts`:
//
//   POST /oprf/blind-eval
//     body: { blindedInput: hex32, attestation: { p7s: base64 } }
//     200:  { Y: hex32,
//             proof: { c: hex32, s: hex32 }  OR  hex(64),
//             blindedInput: hex32,
//             oprfPubkey: hex32 }
//     401: AttestationError
//     400: BadRequest | BadBlindedInput
//
// #53 bug fix: the live OPRF service ships `proof: { c, s }` (an object
// with each scalar as a 0x-hex 32-byte LE string). An earlier draft of
// this client expected `proof` as a single 64-byte hex string and called
// `hexDecode(resp.proof)` — which, when `resp.proof` is an object, tries
// `obj.slice(2)` and throws `t.slice is not a function` (the minified
// production trace user saw at the OPRF step). We now accept both wire
// shapes here and normalise to a flat 64-byte `Uint8Array` before
// returning, so callers never have to care.
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
    /**
     * DLEQ proof, normalised to a flat 64-byte buffer = `c (32 LE) || s (32 LE)`.
     * `verifyBlindEval` consumes this directly.
     */
    proof: Uint8Array;
    /** Echo of the request's blindedInput (reconciliation). */
    blindedInput: `0x${string}`;
}

/**
 * Raw wire shape before normalisation. Two server variants are
 * supported by `coerceProof`:
 *   (a) `proof: "0x<64-byte hex>"`        — flat scalar concat
 *   (b) `proof: { c: "0x...", s: "0x..." }` — object form (current
 *                                             v2-oprf live shape)
 */
interface RawBlindEvalResponse {
    Y: `0x${string}`;
    oprfPubkey: `0x${string}`;
    proof:
        | `0x${string}`
        | { c: `0x${string}`; s: `0x${string}` }
        | unknown;
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

function hexToBytes(h: string): Uint8Array {
    const s = h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h;
    if (s.length % 2 !== 0) throw new Error(`odd-length hex: ${h}`);
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
    }
    return out;
}

/**
 * Coerce the server's `proof` field into the flat 64-byte buffer the
 * client side needs. Tolerant of both wire shapes (#53 fix):
 *
 *   • string `"0x..."` of 64 bytes  → decode as-is.
 *   • `{ c: "0x...", s: "0x..." }`  → concat `c` (32 LE) || `s` (32 LE).
 *
 * Throws with a clear diagnostic if neither shape applies, so a future
 * server wire-shape drift surfaces as a recognisable error rather than
 * a downstream `t.slice is not a function`.
 */
function coerceProof(raw: unknown): Uint8Array {
    if (typeof raw === "string") {
        const bytes = hexToBytes(raw);
        if (bytes.length !== 64) {
            throw new Error(
                `OPRF proof: expected 64 bytes, got ${bytes.length}`,
            );
        }
        return bytes;
    }
    if (
        raw !== null &&
        typeof raw === "object" &&
        "c" in raw &&
        "s" in raw &&
        typeof (raw as { c: unknown }).c === "string" &&
        typeof (raw as { s: unknown }).s === "string"
    ) {
        const c = hexToBytes((raw as { c: string }).c);
        const s = hexToBytes((raw as { s: string }).s);
        if (c.length !== 32 || s.length !== 32) {
            throw new Error(
                `OPRF proof: expected (c,s) = (32,32) bytes, got (${c.length},${s.length})`,
            );
        }
        const out = new Uint8Array(64);
        out.set(c, 0);
        out.set(s, 32);
        return out;
    }
    throw new Error(
        `OPRF proof: unknown wire shape ${JSON.stringify(raw)?.slice(0, 80)}`,
    );
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
    const raw: RawBlindEvalResponse = await postJson("/oprf/blind-eval", {
        blindedInput: hex(blindedElement),
        attestation: { p7s: toBase64(p7sBytes) },
    });

    // v2.1: pin the server's K_pub at build time and refuse anything else.
    // Without this, an MITM could substitute its own (K_pub*, k*) — DLEQ
    // would still pass against the spoofed pubkey, the server only ever
    // proves consistency to itself. v2.2 will move K_pub on-chain into
    // EnrollmentRegistry and the client will read it from there at boot.
    if (typeof raw.oprfPubkey !== "string") {
        throw new Error(
            `OPRF blind-eval response missing oprfPubkey (got ${typeof raw.oprfPubkey})`,
        );
    }
    const expected = config.oprfPubkey.toLowerCase();
    const observed = raw.oprfPubkey.toLowerCase();
    if (observed !== expected) {
        const err = new Error(
            `oprf-pubkey-mismatch: server returned ${observed}, build pinned ${expected}`,
        ) as Error & { code: string };
        err.code = "OprfPubkeyMismatch";
        throw err;
    }

    // Normalise to the flat 64-byte proof so callers don't have to
    // know which wire shape the server is on this week (see #53).
    return {
        Y: raw.Y,
        oprfPubkey: raw.oprfPubkey,
        proof: coerceProof(raw.proof),
        blindedInput: raw.blindedInput,
    };
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
