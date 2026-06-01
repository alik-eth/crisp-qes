import { useState, useCallback, useEffect } from "react";
import type { PetitionView } from "../lib/registry.js";
import { readHasNullifier } from "../lib/registry.js";
import { pedersenNullifier } from "../lib/pedersen.js";
import { v3RecoverPath, NotEnrolledError } from "../lib/v3enroll.js";
import {
    submitSignature,
    submitRevoke,
    explorerTxUrl,
} from "../lib/relayer.js";
import { unlockVault } from "../lib/unlock.js";
import { getSessionVault } from "../lib/passkeySession.js";
import { clearAll } from "../lib/encryptedStore.js";
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

type Mode = "sign" | "revoke";

interface ProveOutput {
    proofBytes: Uint8Array;
    publicInputs: string[];
}

export function SignBlock({ petition, onSigned }: Props) {
    const [stage, setStage] = useState<Stage>("idle");
    const [stageLine, setStageLine] = useState("");
    const [errMsg, setErrMsg] = useState<string | null>(null);
    const [txHash, setTxHash] = useState<`0x${string}` | null>(null);
    const [revokedTx, setRevokedTx] = useState<`0x${string}` | null>(null);
    // Set when the recover-path lookup reports the vault's commitment is not on
    // the current registry (orphaned vault after a clean-slate redeploy). Drives
    // a re-enroll prompt instead of a dead "Couldn't sign." error.
    const [staleVault, setStaleVault] = useState(false);
    const [resetting, setResetting] = useState(false);
    // The mode of whatever flow is currently busy. Used to label progress
    // and decide what to do on success.
    const [activeMode, setActiveMode] = useState<Mode>("sign");

    // If the vault is already unlocked this session, derive the nullifier
    // for this petition and check whether the chain already knows it.
    // Surfaces the revoke affordance when so.
    const [alreadySigned, setAlreadySigned] = useState<boolean | null>(null);

    useEffect(() => {
        setRevokedTx(null);
    }, [petition.id]);

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
        setErrMsg(null);
        setActiveMode("sign");
        setStage("unlocking");
        setStageLine("Unlocking your vault…");
        try {
            const u = await unlockVault();

            setStage("preparing");
            setStageLine("Deriving nullifier and syncing the chain root…");
            // The enrollment tree is append-only, so a path stored at
            // enrollment time goes stale the moment anyone else enrolls.
            // Always fetch a fresh path + root from the chain-synced OPRF
            // service right before proving. The vault's enrollmentSecret
            // IS the on-chain leaf (pedersen(N) commitment).
            const [nul, fresh] = await Promise.all([
                pedersenNullifier(u.enrollmentSecret, petition.id),
                v3RecoverPath(u.enrollmentSecret),
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
                fresh.merklePath,
                fresh.merklePathIndices,
                nul,
                fresh.root,
            );

            setStage("submitting");
            setStageLine("Submitting via the relayer…");
            const proofHex = bytesToHex(proveOut.proofBytes);
            let res = await submitSignature({
                petitionId: petition.id,
                nullifier: nul,
                proof: proofHex,
                publicInputs: proveOut.publicInputs as `0x${string}`[],
            });
            // The tree may have grown between our path fetch and the
            // relayer's mine. Re-sync the path, re-prove, and resubmit
            // once before giving up.
            if (!res.ok && res.code === "StaleEnrollmentRoot") {
                setStage("preparing");
                setStageLine("Root moved — re-syncing and re-proving…");
                const fresh2 = await v3RecoverPath(u.enrollmentSecret);
                setStage("proving");
                setStageLine(
                    "Generating UltraHonk proof in this browser (5–30 seconds)…",
                );
                const proveOut2 = await generateProof(
                    u.enrollmentSecret,
                    fresh2.merklePath,
                    fresh2.merklePathIndices,
                    nul,
                    fresh2.root,
                );
                setStage("submitting");
                setStageLine("Submitting via the relayer…");
                res = await submitSignature({
                    petitionId: petition.id,
                    nullifier: nul,
                    proof: bytesToHex(proveOut2.proofBytes),
                    publicInputs: proveOut2.publicInputs as `0x${string}`[],
                });
            }
            if (!res.ok) {
                throw new Error(`${res.code}${res.detail ? ": " + res.detail : ""}`);
            }
            setTxHash(res.txHash);
            setStage("done");
            onSigned(res.txHash);
        } catch (e) {
            if (e instanceof NotEnrolledError) {
                setStaleVault(true);
                setStage("error");
                return;
            }
            setErrMsg(e instanceof Error ? e.message : String(e));
            setStage("error");
        }
    }, [petition.id, onSigned, generateProof]);

    // Revoke flow — a plain withdraw of the citizen's signature. After it
    // confirms the UI rolls back to the unsigned state and shows the
    // "Revoked" confirmation.
    const runRevoke = useCallback(async () => {
        setErrMsg(null);
        setActiveMode("revoke");
        setStage("unlocking");
        setStageLine("Unlocking your vault…");
        try {
            const u = await unlockVault();

            setStage("preparing");
            setStageLine("Deriving nullifier and syncing the chain root…");
            // Same append-only staleness applies to revoke: fetch a
            // fresh path + root from the chain-synced OPRF service.
            const [nul, fresh] = await Promise.all([
                pedersenNullifier(u.enrollmentSecret, petition.id),
                v3RecoverPath(u.enrollmentSecret),
            ]);

            setStage("proving");
            setStageLine(
                "Generating UltraHonk proof in this browser (5–30 seconds)…",
            );
            const proveOut = await generateProof(
                u.enrollmentSecret,
                fresh.merklePath,
                fresh.merklePathIndices,
                nul,
                fresh.root,
            );

            setStage("submitting");
            setStageLine("Submitting revoke via the relayer…");
            const proofHex = bytesToHex(proveOut.proofBytes);
            let res = await submitRevoke({
                petitionId: petition.id,
                nullifier: nul,
                proof: proofHex,
                publicInputs: proveOut.publicInputs as `0x${string}`[],
            });
            // Re-sync + re-prove once if the tree grew under us.
            if (!res.ok && res.code === "StaleEnrollmentRoot") {
                setStage("preparing");
                setStageLine("Root moved — re-syncing and re-proving…");
                const fresh2 = await v3RecoverPath(u.enrollmentSecret);
                setStage("proving");
                setStageLine(
                    "Generating UltraHonk proof in this browser (5–30 seconds)…",
                );
                const proveOut2 = await generateProof(
                    u.enrollmentSecret,
                    fresh2.merklePath,
                    fresh2.merklePathIndices,
                    nul,
                    fresh2.root,
                );
                setStage("submitting");
                setStageLine("Submitting revoke via the relayer…");
                res = await submitRevoke({
                    petitionId: petition.id,
                    nullifier: nul,
                    proof: bytesToHex(proveOut2.proofBytes),
                    publicInputs: proveOut2.publicInputs as `0x${string}`[],
                });
            }
            if (!res.ok) {
                if (res.code === "NullifierNotUsed") {
                    // Defensive: only reachable if state drifted under
                    // us. Roll the UI back to the unsigned state.
                    setAlreadySigned(false);
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
            setRevokedTx(res.txHash);
            setStage("done");
            onSigned(res.txHash);
        } catch (e) {
            if (e instanceof NotEnrolledError) {
                setStaleVault(true);
                setStage("error");
                return;
            }
            setErrMsg(e instanceof Error ? e.message : String(e));
            setStage("error");
        }
    }, [petition.id, onSigned, generateProof]);

    // Orphaned-vault recovery: wipe the stale local enrollment row and send the
    // user through a fresh /verify enrollment. A hard navigation also drops the
    // in-memory session vault (the stale enrollmentSecret) so nothing carries
    // over. The Passkey (`accounts` row) is intentionally kept — re-enrollment
    // re-wraps to it.
    const onReEnroll = useCallback(async () => {
        setResetting(true);
        try {
            await clearAll();
        } catch {
            // Even if the wipe fails, re-enrollment overwrites the row; proceed.
        }
        window.location.assign("/verify");
    }, []);

    const busy = ["unlocking", "preparing", "proving", "submitting"].includes(
        stage,
    );

    // --- "already signed" branch: revoke ---
    if (alreadySigned && stage !== "done") {
        return (
            <div className="detail__cta">
                <div className="notice notice--ok">
                    <div>You've already signed this petition.</div>
                </div>

                <div className="row" style={{ marginTop: 12 }}>
                    <button
                        type="button"
                        className="btn btn--primary"
                        style={{ background: "var(--bad)" }}
                        onClick={() => void runRevoke()}
                        disabled={busy}
                    >
                        {busy ? "Working…" : "Revoke signature"}
                    </button>
                </div>

                <p className="muted small" style={{ marginTop: 12 }}>
                    Only the nullifier reaches the chain — not your
                    identity.
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

    // --- orphaned-vault branch: re-enroll ---
    // The recover-path lookup said this device's commitment isn't on the current
    // registry (e.g. it was minted before a clean-slate redeploy). Signing can
    // never succeed with it; guide the user to re-enroll instead of dead-ending.
    if (staleVault) {
        return (
            <div className="detail__cta">
                <div className="notice notice--bad">
                    <div>
                        <strong>Re-enrollment needed.</strong>
                        <br />
                        <span className="small">
                            This device's enrollment isn't on the current
                            registry — it was most likely reset. Re-enroll with
                            your Diia QES to keep signing. Your identity stays
                            private; this only refreshes the key stored on this
                            device.
                        </span>
                    </div>
                </div>

                <div className="row" style={{ marginTop: 12 }}>
                    <button
                        type="button"
                        className="btn btn--primary"
                        onClick={() => void onReEnroll()}
                        disabled={resetting}
                    >
                        {resetting ? "Resetting…" : "Re-enroll"}
                    </button>
                </div>
            </div>
        );
    }

    // --- post-success branches ---
    if (stage === "done" && activeMode === "revoke" && revokedTx) {
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

    // --- default branch: first-time sign ---
    return (
        <div className="detail__cta">
            <button
                type="button"
                className="btn btn--primary"
                onClick={() => void onSign()}
                disabled={busy}
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
