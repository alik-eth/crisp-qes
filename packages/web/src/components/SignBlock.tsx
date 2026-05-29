import { useState, useCallback, useEffect } from "react";
import {
    VotesForMode,
    type BallotMode,
} from "../lib/abi.js";
import type { PetitionView } from "../lib/registry.js";
import {
    readEnrollmentRoot,
    readHasNullifier,
    readVoteByNullifier,
} from "../lib/registry.js";
import { pedersenNullifier } from "../lib/pedersen.js";
import {
    submitSignature,
    submitRevoke,
    explorerTxUrl,
} from "../lib/relayer.js";
import { unlockVault } from "../lib/unlock.js";
import { getSessionVault } from "../lib/passkeySession.js";
import { config } from "../config.js";

interface Props {
    petition: PetitionView;
    onSigned: (txHash: `0x${string}`) => void;
}

type Stage =
    | "idle"
    | "unlocking"
    | "preparing"
    | "proving"
    | "submitting"
    | "done"
    | "error";

type Mode = "sign" | "revoke" | "change";

interface ProveOutput {
    proofBytes: Uint8Array;
    publicInputs: string[];
}

export function SignBlock({ petition, onSigned }: Props) {
    const allowedVotes = VotesForMode[petition.mode as BallotMode];
    const isSignatureMode = petition.modeLabel === "Signature";

    const [vote, setVote] = useState<number | null>(
        isSignatureMode ? 0 : null,
    );
    const [stage, setStage] = useState<Stage>("idle");
    const [stageLine, setStageLine] = useState("");
    const [errMsg, setErrMsg] = useState<string | null>(null);
    const [txHash, setTxHash] = useState<`0x${string}` | null>(null);
    const [revokedTx, setRevokedTx] = useState<`0x${string}` | null>(null);
    // The mode of whatever flow is currently busy. Used to label progress
    // and decide what to do on success.
    const [activeMode, setActiveMode] = useState<Mode>("sign");

    // If the vault is already unlocked this session, derive the nullifier
    // for this petition and check whether the chain already knows it.
    // Surfaces the revoke / change-vote affordances when so.
    const [alreadySigned, setAlreadySigned] = useState<boolean | null>(null);
    // The original vote the user cast (1 + vote on chain; null if unknown
    // or not signed). Needed so YesNo / YesNoAbstain modes can grey out
    // "Change vote" until a *different* vote is selected.
    const [originalVote, setOriginalVote] = useState<number | null>(null);

    useEffect(() => {
        setVote(isSignatureMode ? 0 : null);
        setRevokedTx(null);
        setOriginalVote(null);
    }, [isSignatureMode, petition.id]);

    useEffect(() => {
        let alive = true;
        const v = getSessionVault();
        if (!v) {
            setAlreadySigned(null);
            return;
        }
        void (async () => {
            try {
                const nul = await pedersenNullifier(
                    v.enrollmentSecret,
                    petition.id,
                );
                // Read the encoded vote (0 = unsigned, otherwise 1+vote).
                // Fall back to `hasNullifier` if the encoded read fails
                // for any reason — the legacy bool view is still wired.
                const encoded = await readVoteByNullifier(petition.id, nul).catch(
                    () => -1,
                );
                if (!alive) return;
                if (encoded > 0) {
                    setAlreadySigned(true);
                    setOriginalVote(encoded - 1);
                    if (!isSignatureMode) setVote(encoded - 1);
                } else if (encoded === 0) {
                    setAlreadySigned(false);
                    setOriginalVote(null);
                } else {
                    const used = await readHasNullifier(petition.id, nul);
                    if (alive) {
                        setAlreadySigned(used);
                        setOriginalVote(null);
                    }
                }
            } catch {
                if (alive) setAlreadySigned(null);
            }
        })();
        return () => {
            alive = false;
        };
    }, [petition.id, isSignatureMode]);

    // Shared proof generation. The circuit takes the same 3-input public
    // array for both sign and revoke — only the on-chain entry point and
    // the relayer endpoint differ. Returns the proof bytes + the public
    // inputs the relayer will echo to the contract.
    const generateProof = useCallback(
        async (
            secret: `0x${string}`,
            merklePath: `0x${string}`[],
            merklePathIndices: number[],
            nul: `0x${string}`,
            root: `0x${string}`,
        ): Promise<ProveOutput> => {
            const witness = {
                enrollment_secret: secret,
                merkle_path: merklePath,
                merkle_path_indices: merklePathIndices,
                petition_id: `0x${petition.id.toString(16).padStart(64, "0")}`,
                enrollment_root: root,
                nullifier: nul,
            };
            const worker = new Worker(
                new URL("../worker/prove.worker.ts", import.meta.url),
                { type: "module" },
            );
            return new Promise<ProveOutput>((resolve, reject) => {
                worker.onmessage = (ev: MessageEvent) => {
                    const m = ev.data as
                        | { type: "stage"; stage: string }
                        | {
                              type: "done";
                              proofBytes: number[];
                              publicInputs: string[];
                          }
                        | { type: "error"; detail: string };
                    if (m.type === "stage") {
                        setStageLine(workerStageLabel(m.stage));
                    } else if (m.type === "done") {
                        resolve({
                            proofBytes: new Uint8Array(m.proofBytes),
                            publicInputs: m.publicInputs,
                        });
                        worker.terminate();
                    } else {
                        reject(new Error(m.detail));
                        worker.terminate();
                    }
                };
                worker.onerror = (e) => {
                    reject(new Error(e.message));
                    worker.terminate();
                };
                worker.postMessage({
                    type: "prove",
                    witness,
                    circuitUrl: config.circuitUrl,
                });
            });
        },
        [petition.id],
    );

    const onSign = useCallback(async () => {
        if (vote === null) return;
        setErrMsg(null);
        setActiveMode("sign");
        setStage("unlocking");
        setStageLine("Unlocking your vault…");
        try {
            const u = await unlockVault();

            setStage("preparing");
            setStageLine("Deriving nullifier and reading the chain root…");
            const [nul, root] = await Promise.all([
                pedersenNullifier(u.enrollmentSecret, petition.id),
                readEnrollmentRoot(),
            ]);

            // Last-chance pre-flight: avoid a guaranteed revert if a
            // sibling tab signed since this page rendered.
            const used = await readHasNullifier(petition.id, nul);
            if (used) {
                setAlreadySigned(true);
                setStage("idle");
                return;
            }

            setStage("proving");
            setStageLine(
                "Generating UltraHonk proof in this browser (5–30 seconds)…",
            );
            const proveOut = await generateProof(
                u.enrollmentSecret,
                u.merklePath,
                u.merklePathIndices,
                nul,
                root,
            );

            setStage("submitting");
            setStageLine("Submitting via the relayer…");
            const proofHex = bytesToHex(proveOut.proofBytes);
            const res = await submitSignature({
                petitionId: petition.id,
                vote,
                nullifier: nul,
                proof: proofHex,
                publicInputs: proveOut.publicInputs as `0x${string}`[],
            });
            if (!res.ok) {
                throw new Error(`${res.code}${res.detail ? ": " + res.detail : ""}`);
            }
            setTxHash(res.txHash);
            setStage("done");
            onSigned(res.txHash);
        } catch (e) {
            setErrMsg(e instanceof Error ? e.message : String(e));
            setStage("error");
        }
    }, [vote, petition.id, onSigned, generateProof]);

    // Revoke flow. If `andSignWith` is non-null we chain a sign with the
    // new vote after the revoke confirms — "Change vote" is revoke +
    // sign as a single button click. If sign fails after a successful
    // revoke the user is left unsigned with an error — they can retry.
    const runRevoke = useCallback(
        async (andSignWith: number | null) => {
            setErrMsg(null);
            setActiveMode(andSignWith === null ? "revoke" : "change");
            setStage("unlocking");
            setStageLine("Unlocking your vault…");
            try {
                const u = await unlockVault();

                setStage("preparing");
                setStageLine("Deriving nullifier and reading the chain root…");
                const [nul, root] = await Promise.all([
                    pedersenNullifier(u.enrollmentSecret, petition.id),
                    readEnrollmentRoot(),
                ]);

                setStage("proving");
                setStageLine(
                    "Generating UltraHonk proof in this browser (5–30 seconds)…",
                );
                const proveOut = await generateProof(
                    u.enrollmentSecret,
                    u.merklePath,
                    u.merklePathIndices,
                    nul,
                    root,
                );

                setStage("submitting");
                setStageLine("Submitting revoke via the relayer…");
                const proofHex = bytesToHex(proveOut.proofBytes);
                const res = await submitRevoke({
                    petitionId: petition.id,
                    nullifier: nul,
                    proof: proofHex,
                    publicInputs: proveOut.publicInputs as `0x${string}`[],
                });
                if (!res.ok) {
                    if (res.code === "NullifierNotUsed") {
                        // Defensive: only reachable if state drifted under
                        // us. Roll the UI back to the unsigned state.
                        setAlreadySigned(false);
                        setOriginalVote(null);
                        throw new Error(
                            "You hadn't signed this petition (or it was already revoked).",
                        );
                    }
                    throw new Error(
                        `${res.code}${res.detail ? ": " + res.detail : ""}`,
                    );
                }

                // Revoke is on chain. Clear local "already signed" state
                // and tell the parent to refresh tallies.
                setAlreadySigned(false);
                setOriginalVote(null);
                setRevokedTx(res.txHash);
                onSigned(res.txHash);

                if (andSignWith === null) {
                    // Plain revoke — show the "Revoked" confirmation.
                    setStage("done");
                    return;
                }

                // Chain into a sign with the new vote. We re-run the full
                // proof for cleanliness — the circuit is fast enough and
                // any state (root, etc) might have drifted in the gap.
                setActiveMode("change");
                setStage("preparing");
                setStageLine("Re-reading the chain root for the new vote…");
                const root2 = await readEnrollmentRoot();
                setStage("proving");
                setStageLine(
                    "Generating UltraHonk proof for the new vote…",
                );
                const proveOut2 = await generateProof(
                    u.enrollmentSecret,
                    u.merklePath,
                    u.merklePathIndices,
                    nul,
                    root2,
                );
                setStage("submitting");
                setStageLine("Submitting new vote via the relayer…");
                const proofHex2 = bytesToHex(proveOut2.proofBytes);
                const res2 = await submitSignature({
                    petitionId: petition.id,
                    vote: andSignWith,
                    nullifier: nul,
                    proof: proofHex2,
                    publicInputs: proveOut2.publicInputs as `0x${string}`[],
                });
                if (!res2.ok) {
                    throw new Error(
                        `${res2.code}${res2.detail ? ": " + res2.detail : ""}`,
                    );
                }
                setTxHash(res2.txHash);
                setAlreadySigned(true);
                setOriginalVote(andSignWith);
                setStage("done");
                onSigned(res2.txHash);
            } catch (e) {
                setErrMsg(e instanceof Error ? e.message : String(e));
                setStage("error");
            }
        },
        [petition.id, onSigned, generateProof],
    );

    const busy = ["unlocking", "preparing", "proving", "submitting"].includes(
        stage,
    );

    // --- "already signed" branch: revoke / change vote ---
    if (alreadySigned && stage !== "done") {
        const canChange =
            !isSignatureMode &&
            vote !== null &&
            originalVote !== null &&
            vote !== originalVote;
        return (
            <div className="detail__cta">
                <div className="notice notice--ok">
                    <div>You've already signed this petition.</div>
                </div>
                {!isSignatureMode ? (
                    <div style={{ marginTop: 16, marginBottom: 16 }}>
                        <div
                            className="muted small"
                            style={{ marginBottom: 8 }}
                        >
                            {originalVote !== null
                                ? `Your vote: ${voteLabel(originalVote)}. Pick a different option to change it.`
                                : "Pick a vote to change to."}
                        </div>
                        <div className="row">
                            {allowedVotes.map((v) => (
                                <label key={v} className="radio">
                                    <input
                                        type="radio"
                                        name="vote-revoke"
                                        checked={vote === v}
                                        disabled={busy}
                                        onChange={() => setVote(v)}
                                    />
                                    <span>{voteLabel(v)}</span>
                                </label>
                            ))}
                        </div>
                    </div>
                ) : null}

                <div className="row" style={{ marginTop: 12 }}>
                    <button
                        type="button"
                        className="btn btn--primary"
                        style={{ background: "var(--bad)" }}
                        onClick={() => void runRevoke(null)}
                        disabled={busy}
                    >
                        {busy && activeMode === "revoke"
                            ? "Working…"
                            : "Revoke signature"}
                    </button>
                    {!isSignatureMode ? (
                        <button
                            type="button"
                            className="btn btn--ghost"
                            onClick={() =>
                                vote !== null && void runRevoke(vote)
                            }
                            disabled={busy || !canChange}
                            title={
                                canChange
                                    ? undefined
                                    : "Pick a different vote to enable"
                            }
                        >
                            {busy && activeMode === "change"
                                ? "Working…"
                                : "Change vote"}
                        </button>
                    ) : null}
                </div>

                <p className="muted small" style={{ marginTop: 12 }}>
                    Only the nullifier reaches the chain — not your
                    identity. Change vote = revoke + re-sign in one step.
                </p>

                {busy ? (
                    <div className="progress-band" style={{ marginTop: 16 }}>
                        <Spinner />
                        <span className="small">{stageLine}</span>
                    </div>
                ) : null}

                {errMsg ? (
                    <div
                        className="notice notice--bad"
                        style={{ marginTop: 16 }}
                    >
                        <div>
                            <strong>Couldn't finish.</strong>
                            <br />
                            <span className="small mono">{errMsg}</span>
                        </div>
                    </div>
                ) : null}
            </div>
        );
    }

    // --- post-success branches ---
    if (stage === "done" && (activeMode === "revoke") && revokedTx) {
        return (
            <div className="detail__cta">
                <div className="notice notice--ok">
                    <div>Revoked.</div>
                </div>
                <p className="muted small" style={{ marginTop: 12 }}>
                    <a
                        href={explorerTxUrl(revokedTx)}
                        target="_blank"
                        rel="noreferrer"
                        className="mono"
                    >
                        {revokedTx}
                    </a>
                </p>
            </div>
        );
    }

    if (stage === "done" && txHash) {
        return (
            <div className="detail__cta">
                <div className="notice notice--ok">
                    <div>
                        {activeMode === "change"
                            ? "Vote changed. New signature is on chain."
                            : "Your signature is on chain."}
                    </div>
                </div>
                <p className="muted small" style={{ marginTop: 12 }}>
                    <a
                        href={explorerTxUrl(txHash)}
                        target="_blank"
                        rel="noreferrer"
                        className="mono"
                    >
                        {txHash}
                    </a>
                </p>
            </div>
        );
    }

    // --- default branch: first-time sign ---
    return (
        <div className="detail__cta">
            {petition.modeLabel !== "Signature" ? (
                <div style={{ marginBottom: 16 }}>
                    <div className="muted small" style={{ marginBottom: 8 }}>
                        Your vote
                    </div>
                    <div className="row">
                        {allowedVotes.map((v) => (
                            <label key={v} className="radio">
                                <input
                                    type="radio"
                                    name="vote"
                                    checked={vote === v}
                                    onChange={() => setVote(v)}
                                />
                                <span>{voteLabel(v)}</span>
                            </label>
                        ))}
                    </div>
                </div>
            ) : null}

            <button
                type="button"
                className="btn btn--primary"
                onClick={() => void onSign()}
                disabled={busy || vote === null}
            >
                {busy ? "Working…" : "Sign"}
            </button>
            <p className="muted small" style={{ marginTop: 12 }}>
                Only a nullifier reaches the chain — not your identity.
            </p>

            {busy ? (
                <div className="progress-band" style={{ marginTop: 16 }}>
                    <Spinner />
                    <span className="small">{stageLine}</span>
                </div>
            ) : null}

            {errMsg ? (
                <div className="notice notice--bad" style={{ marginTop: 16 }}>
                    <div>
                        <strong>Couldn't sign.</strong>
                        <br />
                        <span className="small mono">{errMsg}</span>
                    </div>
                </div>
            ) : null}
        </div>
    );
}

function voteLabel(v: number): string {
    return v === 1 ? "Yes" : v === 0 ? "No" : "Abstain";
}

function bytesToHex(b: Uint8Array): `0x${string}` {
    return ("0x" +
        Array.from(b, (n) => n.toString(16).padStart(2, "0")).join(
            "",
        )) as `0x${string}`;
}

function workerStageLabel(stage: string): string {
    switch (stage) {
        case "initWorker":
            return "Booting the prover…";
        case "loadingCircuit":
            return "Loading the circuit…";
        case "buildWitness":
            return "Building witness…";
        case "proving":
            return "Generating UltraHonk proof…";
        default:
            return stage;
    }
}

function Spinner() {
    return <span className="spinner" aria-hidden="true" />;
}
