export type LiveTally = { roundId: number; counts: number[]; nVotes: number; decryptedAt: number };

/**
 * Demo/dev-only: ask the coordination server to threshold-decrypt the *current*
 * encrypted vote sum for a round and return the live per-option counts. The
 * round stays open; this is repeatable + non-destructive. A real deployment
 * hides these counts until the round closes — the endpoint is env-gated off in
 * prod.
 */
export async function recalcTally(coordinatorUrl: string, roundId: number): Promise<LiveTally> {
    const res = await fetch(`${coordinatorUrl}/rounds/tally-now`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ round_id: roundId }),
    });
    if (!res.ok) throw new Error(`tally-now failed: ${res.status} ${await res.text()}`);
    const j = await res.json();
    return { roundId: j.round_id, counts: j.counts, nVotes: j.n_votes, decryptedAt: j.decrypted_at };
}
