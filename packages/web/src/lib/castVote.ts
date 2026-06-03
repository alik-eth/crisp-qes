// ADR-0001 path (C) — the live in-browser vote flow (desktop). Composes the
// proven pieces: committee BFV pubkey (from the coordinator) + the voter's
// enrollment leaf/path + the chosen option -> proveVoteInBrowser (v3 worker) ->
// broadcast to the coordinator, which submits CRISPQESProgram.publishInput.
//
// The cryptography is proven (Task 4.0b). The remaining live dependencies are
// infra: the coordinator must serve /state/lite + /qes/broadcast with CORS for
// the web origin, and the voter's enrollment leaf must be in the round's pinned
// root with a valid Merkle path (same enrollment-path concern as the petition
// flow). The caller supplies `enrollment`.

import { pedersenNullifier } from "./pedersen.js";
import { proveVoteInBrowser, type VoteWitness } from "./voteProver.js";
import { oneHotVote } from "./vote.js";
import type { VoteRound } from "./voteRound.js";

export type Enrollment = {
    /** the citizen's enrollment secret = Merkle leaf */
    enrollmentSecret: bigint;
    /** depth-20 sibling path + left/right indices for the leaf in the round's root */
    merklePath: bigint[];
    merklePathIndices: number[];
};

export type CastResult = {
    ok: boolean;
    status: string;
    txHash?: string;
    nullifier: string;
    detail?: string;
};

const stripSlash = (u: string) => u.replace(/\/+$/, "");

async function postJson(base: string, path: string, body: unknown): Promise<Response> {
    return fetch(stripSlash(base) + path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
}

/** Fetch the round's committee BFV public key from the coordinator (/state/lite). */
export async function fetchCommitteeKey(coordinatorUrl: string, e3Id: bigint): Promise<Uint8Array> {
    const res = await postJson(coordinatorUrl, "/state/lite", { round_id: Number(e3Id) });
    if (!res.ok) throw new Error(`committee key fetch failed (http ${res.status})`);
    const j = await res.json();
    const pk: number[] | undefined = j.committee_public_key;
    if (!pk || pk.length === 0 || (pk.length === 1 && Number(pk[0]) === 0)) {
        throw new Error("committee key not published yet for this round");
    }
    return new Uint8Array(pk.map((b) => Number(b)));
}

const sToHex = (s: bigint) => ("0x" + s.toString(16).padStart(64, "0")) as `0x${string}`;

/**
 * Cast a vote entirely client-side: prove in the v3 worker, then broadcast.
 * Returns the coordinator's broadcast result (tx hash on success).
 */
export async function castVoteInBrowser(args: {
    round: VoteRound;
    optionIndex: number;
    enrollment: Enrollment;
    coordinatorUrl: string;
    onStage?: (s: string) => void;
}): Promise<CastResult> {
    const { round, optionIndex, enrollment, coordinatorUrl, onStage } = args;

    onStage?.("fetching committee key…");
    const publicKey = await fetchCommitteeKey(coordinatorUrl, round.e3Id);

    // nullifier = pedersen([s, e3Id, DOMAIN_PETITION_V2]) — must equal what the
    // circuit recomputes from enrollment_secret (pedersen is bb-version-stable).
    const nullifier = BigInt(await pedersenNullifier(sToHex(enrollment.enrollmentSecret), round.e3Id));
    const enrollmentRoot = BigInt(round.enrollmentRoot);

    const witness: VoteWitness = {
        vote: oneHotVote(optionIndex, round.options.length),
        publicKey,
        enrollmentSecret: enrollment.enrollmentSecret,
        merklePath: enrollment.merklePath,
        merklePathIndices: enrollment.merklePathIndices,
        enrollmentRoot,
        nullifier,
        petitionId: round.e3Id, // contract binds pub[6] == e3Id
    };

    onStage?.("proving in-browser (~90s)…");
    const { encoded } = await proveVoteInBrowser(witness, onStage);

    onStage?.("broadcasting…");
    const res = await postJson(coordinatorUrl, "/qes/broadcast", {
        round_id: Number(round.e3Id),
        encoded_proof: encoded,
        enrollment_root: enrollmentRoot.toString(),
    });
    const body = await res.json().catch(() => ({}) as Record<string, unknown>);
    return {
        ok: res.ok && body.status === "success",
        status: (body.status as string) ?? `http ${res.status}`,
        txHash: body.tx_hash as string | undefined,
        nullifier: nullifier.toString(),
        detail: body.detail as string | undefined,
    };
}
