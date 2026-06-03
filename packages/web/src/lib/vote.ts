/** Build a one-hot ballot vector: 1 at `index`, 0 elsewhere. */
export function oneHotVote(index: number, numOptions: number): number[] {
    if (!Number.isInteger(index) || index < 0 || index >= numOptions) {
        throw new Error(`option ${index} out of range 0..${numOptions - 1}`);
    }
    return Array.from({ length: numOptions }, (_, i) => (i === index ? 1 : 0));
}

// NOTE: the previous buildVotePayload() stub (which dynamically imported
// @crisp-e3/sdk on the main thread) is superseded by the isolated v3 vote worker
// — see lib/voteProver.ts (proveVoteInBrowser) + lib/castVote.ts. The SDK is NOT
// a dependency of the main app graph; it lives only in the separate worker build
// (vite.voteworker.config.ts). Keeping that import here broke `vite build`.
