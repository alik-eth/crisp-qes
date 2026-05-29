import { useState, useCallback, useEffect } from "react";
import {
    VotesForMode,
    type BallotMode,
} from "../lib/abi.js";
import type { PetitionView } from "../lib/registry.js";
import { readEnrollmentRoot, readHasNullifier } from "../lib/registry.js";
import { pedersenNullifier } from "../lib/pedersen.js";
import { submitSignature, explorerTxUrl } from "../lib/relayer.js";
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

export function SignBlock({ petition, onSigned }: Props) {
    const allowedVotes = VotesForMode[petition.mode as BallotMode];
    const [vote, setVote] = useState<number | null>(
        petition.modeLabel === "Signature" ? 0 : null,
    );
    const [stage, setStage] = useState<Stage>("idle");
    const [stageLine, setStageLine] = useState("");
    const [errMsg, setErrMsg] = useState<string | null>(null);
    const [txHash, setTxHash] = useState<`0x${string}` | null>(null);

    // If the vault is already unlocked this session, derive the nullifier
    // for this petition and check whether the chain already knows it.
    // Avoids showing the vote UI when the user has already signed.
    const [alreadySigned, setAlreadySigned] = useState<boolean | null>(null);

    useEffect(() => {
        setVote(petition.modeLabel === "Signature" ? 0 : null);
    }, [petition.modeLabel]);

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
                const used = await readHasNullifier(petition.id, nul);
                if (alive) setAlreadySigned(used);
            } catch {
                if (alive) setAlreadySigned(null);
            }
        })();
        return () => {
            alive = false;
        };
    }, [petition.id]);

    const onSign = useCallback(async () => {
        if (vote === null) return;
        setErrMsg(null);
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
            const witness = {
                enrollment_secret: u.enrollmentSecret,
                merkle_path: u.merklePath,
                merkle_path_indices: u.merklePathIndices,
                petition_id: `0x${petition.id.toString(16).padStart(64, "0")}`,
                enrollment_root: root,
                nullifier: nul,
            };
            const worker = new Worker(
                new URL("../worker/prove.worker.ts", import.meta.url),
                { type: "module" },
            );
            const proveOut = await new Promise<{
                proofBytes: Uint8Array;
                publicInputs: string[];
            }>((resolve, reject) => {
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

            setStage("submitting");
            setStageLine("Submitting via the relayer…");
            const proofHex = ("0x" +
                Array.from(proveOut.proofBytes, (n) =>
                    n.toString(16).padStart(2, "0"),
                ).join("")) as `0x${string}`;
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
    }, [vote, petition.id, onSigned]);

    if (alreadySigned) {
        return (
            <div className="detail__cta">
                <div className="notice notice--ok">
                    <div>You've already signed this petition.</div>
                </div>
                <p className="muted small" style={{ marginTop: 12 }}>
                    Your nullifier is on chain. Each enrollment can sign a
                    given petition only once.
                </p>
            </div>
        );
    }

    if (stage === "done" && txHash) {
        return (
            <div className="detail__cta">
                <div className="notice notice--ok">
                    <div>Your signature is on chain.</div>
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

    const busy = ["unlocking", "preparing", "proving", "submitting"].includes(
        stage,
    );

    return (
        <div className="detail__cta">
            {petition.modeLabel !== "Signature" ? (
                <div style={{ marginBottom: 16 }}>
                    <div className="muted small" style={{ marginBottom: 8 }}>
                        Your vote
                    </div>
                    <div className="row">
                        {allowedVotes.map((v) => {
                            const label =
                                v === 1 ? "Yes" : v === 0 ? "No" : "Abstain";
                            return (
                                <label key={v} className="radio">
                                    <input
                                        type="radio"
                                        name="vote"
                                        checked={vote === v}
                                        onChange={() => setVote(v)}
                                    />
                                    <span>{label}</span>
                                </label>
                            );
                        })}
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
