import { useEffect, useState } from "react";
import { createPublicClient, http } from "viem";
import { config } from "../config.js";
import { fetchRounds, type VoteRound } from "../lib/voteRound.js";
import { fetchTally, toResults, winningOption, type OptionResult } from "../lib/voteTally.js";
import { voteWorkerSelftest } from "../lib/voteProver.js";

const DECODE_TALLY_ABI = [
    {
        type: "function",
        name: "decodeTally",
        stateMutability: "view",
        inputs: [{ type: "uint256" }],
        outputs: [{ type: "uint256[]" }],
    },
] as const;

type RoundView = VoteRound & { results: OptionResult[] | null };

async function loadRoundResults(rounds: VoteRound[]): Promise<RoundView[]> {
    const client = createPublicClient({ transport: http(config.fheOperatorRpc) });
    const readDecodeTally = (e3Id: bigint) =>
        client.readContract({
            address: config.fheCrispProgram,
            abi: DECODE_TALLY_ABI,
            functionName: "decodeTally",
            args: [e3Id],
        }) as Promise<readonly bigint[]>;

    return Promise.all(
        rounds.map(async (r) => {
            try {
                const counts = await fetchTally(readDecodeTally, r.e3Id);
                // decodeTally returns one count per option only once decrypted.
                if (counts.length === r.options.length) {
                    return { ...r, results: toResults(r.options, counts) };
                }
            } catch {
                /* not decrypted yet → tally pending */
            }
            return { ...r, results: null };
        }),
    );
}

export function Rounds() {
    const [rounds, setRounds] = useState<RoundView[] | null>(null);
    const [err, setErr] = useState<string | null>(null);
    // ADR-0001 path (C) experimental probe: prove the v3 vote toolchain loads in
    // its own Web Worker realm (isolated from the main thread's v4 bb.js).
    const [proverProbe, setProverProbe] = useState<string | null>(null);
    const now = Math.floor(Date.now() / 1000);

    const probeVoteProver = async () => {
        setProverProbe("running…");
        try {
            const r = await voteWorkerSelftest();
            setProverProbe(
                `v3 worker OK — bb.js ${r.version} loaded in isolated realm, wasm executed=${r.initialized}`,
            );
        } catch (e) {
            setProverProbe(`worker failed: ${e instanceof Error ? e.message : String(e)}`);
        }
    };

    useEffect(() => {
        let alive = true;
        void (async () => {
            try {
                const list = await fetchRounds(config.fheOperatorRpc, config.fheBallotRegistry);
                const withResults = await loadRoundResults(list);
                if (alive) setRounds(withResults);
            } catch (e) {
                if (alive) setErr(e instanceof Error ? e.message : "load failed");
            }
        })();
        return () => {
            alive = false;
        };
    }, []);

    return (
        <section className="rounds-page">
            <h1>Encrypted votes</h1>
            <p className="muted">
                Multi-option ballots are BFV-encrypted and tallied by a threshold committee — no
                individual vote is ever revealed, only the final per-option counts.
            </p>

            {err && <p className="error">Could not load rounds: {err}</p>}
            {!rounds && !err && <p className="muted">Loading rounds…</p>}
            {rounds && rounds.length === 0 && <p className="muted">No voting rounds yet.</p>}

            {rounds?.map((r) => {
                const open = r.isOpen(now);
                const win = r.results ? winningOption(r.results) : null;
                return (
                    <article key={r.e3Id.toString()} className="round-card">
                        <header>
                            <h2>{r.question}</h2>
                            <span className={open ? "badge open" : "badge closed"}>
                                {open ? "Voting open" : "Closed"}
                            </span>
                        </header>

                        {r.results ? (
                            <ul className="round-results">
                                {r.results.map((o) => (
                                    <li
                                        key={o.label}
                                        className={win && o.label === win.label ? "winner" : ""}
                                    >
                                        <span className="opt">{o.label}</span>
                                        <span className="count">{o.count.toString()}</span>
                                    </li>
                                ))}
                            </ul>
                        ) : (
                            <ul className="round-options">
                                {r.options.map((o) => (
                                    <li key={o}>{o}</li>
                                ))}
                                <li className="muted tally-pending">Tally pending decryption</li>
                            </ul>
                        )}
                    </article>
                );
            })}

            <details className="vote-prover-probe">
                <summary className="muted">In-browser vote prover (experimental, desktop)</summary>
                <p className="muted">
                    Runs the v3 vote toolchain in an isolated Web Worker (ADR-0001 path C). The
                    main thread keeps its v4 bb.js for enrollment; the worker loads v3 separately.
                </p>
                <button type="button" onClick={() => void probeVoteProver()}>
                    Run v3 worker self-test
                </button>
                {proverProbe && <p className="muted" style={{ fontFamily: "monospace" }}>{proverProbe}</p>}
            </details>
        </section>
    );
}
