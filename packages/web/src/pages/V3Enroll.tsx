import { useState, useCallback } from "react";
import { runEnrollment, type RunStage, type RunResult } from "../lib/v3enroll.js";

// EXPERIMENTAL / UNAUDITED v3 demo. In-browser operator-blind enrollment:
//   build witness -> prove enroll_commit_v2 (UltraHonk, ~118k gates) ->
//   POST live Grumpkin OPRF -> prove oprf_nullifier -> derive commitment.
// This is BOTH the operator-blind enrollment demo AND the iOS in-browser
// proving feasibility test. The cert/RNOKPP/DOB are synthetic; M, the live
// round-trip, both proofs, the DLEQ, the unblind and commitment are real.

const STAGE_ORDER: RunStage["key"][] = [
    "enrollWitness",
    "enrollProve",
    "serviceEval",
    "nullifierProve",
    "commitment",
];

function fmtMs(ms?: number): string {
    if (ms === undefined) return "";
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(1)} s`;
}

export function V3Enroll() {
    const [running, setRunning] = useState(false);
    const [stages, setStages] = useState<Record<string, RunStage>>({});
    const [result, setResult] = useState<RunResult | null>(null);
    const [error, setError] = useState<string | null>(null);

    const onRun = useCallback(async () => {
        setRunning(true);
        setStages({});
        setResult(null);
        setError(null);
        try {
            const res = await runEnrollment((s) => {
                setStages((prev) => ({ ...prev, [s.key]: s }));
            });
            setResult(res);
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setRunning(false);
        }
    }, []);

    return (
        <section className="section">
            <div
                className="notice notice--bad"
                style={{ marginBottom: "1rem" }}
            >
                <strong>EXPERIMENTAL / UNAUDITED v3 demo.</strong> In-browser
                operator-blind enrollment. The certificate, RNOKPP and date of
                birth are <em>synthetic</em> (generated in this tab). The
                blinded element, the live service round-trip, both UltraHonk
                proofs, the DLEQ verification and the final commitment are real.
            </div>

            <h1>Operator-blind enrollment (v3)</h1>
            <p className="muted">
                Proves <span className="mono">enroll_commit_v2</span> (~118k
                gates) in this browser, sends the public blinded element to the
                live Grumpkin OPRF service, then proves{" "}
                <span className="mono">oprf_nullifier</span> and derives the
                enrollment commitment — all client-side.
            </p>

            <div className="row" style={{ margin: "1rem 0" }}>
                <button
                    className="btn btn--primary"
                    onClick={onRun}
                    disabled={running}
                >
                    {running ? "Running…" : "Run operator-blind enrollment"}
                </button>
            </div>

            <ol className="card" style={{ listStyle: "none", padding: "1rem", margin: 0 }}>
                {STAGE_ORDER.map((key) => {
                    const s = stages[key];
                    const status = s?.status;
                    const icon =
                        status === "done"
                            ? "✓"
                            : status === "running"
                              ? "…"
                              : status === "error"
                                ? "✕"
                                : "·";
                    return (
                        <li
                            key={key}
                            className="small"
                            style={{
                                display: "flex",
                                justifyContent: "space-between",
                                padding: "0.35rem 0",
                                opacity: s ? 1 : 0.45,
                            }}
                        >
                            <span>
                                <span
                                    className="mono"
                                    style={{ marginRight: "0.5rem" }}
                                >
                                    {icon}
                                </span>
                                {s?.label ?? key}
                            </span>
                            <span className="mono muted">{fmtMs(s?.ms)}</span>
                        </li>
                    );
                })}
            </ol>

            {error ? (
                <div
                    className="notice notice--bad"
                    style={{ marginTop: "1rem" }}
                >
                    <strong>Failed:</strong>{" "}
                    <span className="mono small">{error}</span>
                </div>
            ) : null}

            {result ? (
                <div
                    className="notice notice--ok"
                    style={{ marginTop: "1rem" }}
                >
                    <p>
                        <strong>Enrollment commitment</strong>
                    </p>
                    <p
                        className="mono small"
                        style={{ wordBreak: "break-all" }}
                    >
                        {result.commitment}
                    </p>
                    <p className="muted small" style={{ marginTop: "0.5rem" }}>
                        Blinded element M:{" "}
                        <span
                            className="mono"
                            style={{ wordBreak: "break-all" }}
                        >
                            {result.M}
                        </span>
                    </p>
                    <p className="muted small">
                        Total time: {fmtMs(result.totalMs)}
                    </p>
                </div>
            ) : null}
        </section>
    );
}
