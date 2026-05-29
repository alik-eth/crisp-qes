// v2 sign flow:
//   1. Pick a vote from the petition's allowed set.
//   2. WebAuthn `get` with PRF; unwrap the encrypted enrollment record
//      from IndexedDB.
//   3. Compute the nullifier in-browser (Pedersen over BN254). Read the
//      current `enrollmentRoot` from chain.
//   4. Run the v2 circuit in a worker; emit a 3-input ZK proof.
//   5. Submit via the v2 relayer.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { readPetition, readEnrollmentRoot, type PetitionView } from "../lib/registry";
import { VotesForMode } from "../lib/abi";
import {
    evaluatePrfWithCredential,
} from "../lib/webauthnPrf";
import {
    listEnrollments,
    unwrapPayload,
    hex as encHex,
} from "../lib/encryptedStore";
import { pedersenNullifier } from "../lib/pedersen";
import { submitSignature, basescanTxUrl } from "../lib/relayer";
import { config } from "../config";

interface Props {
    petitionId: bigint;
    onBack: () => void;
    onRecover?: () => void;
    onDone: (txHash: `0x${string}`, vote: number) => void;
}

type ProveStage =
    | "idle"
    | "initWorker"
    | "loadingCircuit"
    | "buildWitness"
    | "proving"
    | "done";

interface ProveOutput {
    proofBytes: Uint8Array;
    publicInputs: string[];
}

interface UnlockedRecord {
    enrollmentSecret: `0x${string}`;
    merklePath: `0x${string}`[];
    merklePathIndices: number[];
    commitment: `0x${string}`;
}

export function Sign({ petitionId, onBack, onRecover, onDone }: Props) {
    const { t } = useTranslation();

    const [petition, setPetition] = useState<PetitionView | null>(null);
    const [petitionErr, setPetitionErr] = useState<string | null>(null);
    const [enrollmentRoot, setEnrollmentRoot] = useState<`0x${string}` | null>(
        null,
    );
    const [hasEnrollment, setHasEnrollment] = useState<boolean | null>(null);

    const [vote, setVote] = useState<number | null>(null);

    const [unlocking, setUnlocking] = useState(false);
    const [unlockErr, setUnlockErr] = useState<string | null>(null);
    const [unlocked, setUnlocked] = useState<UnlockedRecord | null>(null);

    const [proveStage, setProveStage] = useState<ProveStage>("idle");
    const [proveErr, setProveErr] = useState<string | null>(null);
    const [proof, setProof] = useState<ProveOutput | null>(null);
    const [nullifier, setNullifier] = useState<`0x${string}` | null>(null);

    const [submitting, setSubmitting] = useState(false);
    const [submitErr, setSubmitErr] = useState<string | null>(null);
    const [submittedTx, setSubmittedTx] = useState<`0x${string}` | null>(null);

    useEffect(() => {
        let alive = true;
        (async () => {
            try {
                const [p, root, list] = await Promise.all([
                    readPetition(petitionId),
                    readEnrollmentRoot().catch(() => null),
                    listEnrollments(),
                ]);
                if (!alive) return;
                if (!p) {
                    setPetitionErr("petition not found");
                    return;
                }
                setPetition(p);
                if (root) setEnrollmentRoot(root as `0x${string}`);
                setHasEnrollment(list.length > 0);
            } catch (e) {
                if (alive)
                    setPetitionErr(e instanceof Error ? e.message : String(e));
            }
        })();
        return () => {
            alive = false;
        };
    }, [petitionId]);

    const allowedVotes = useMemo(() => {
        if (!petition) return [] as number[];
        return VotesForMode[petition.mode];
    }, [petition]);

    async function handleUnlock() {
        const list = await listEnrollments();
        if (list.length === 0) {
            setUnlockErr(t("sign.vote.missingEnrollment"));
            return;
        }
        // Use the most-recent enrollment. (For multi-epoch scenarios
        // we'd let the user pick, but for the demo the latest is right.)
        const rec = list[list.length - 1]!;
        setUnlocking(true);
        setUnlockErr(null);
        try {
            const credId = encHex.fromHex(rec.credentialId);
            const prfOutput = await evaluatePrfWithCredential(credId);
            const payload = await unwrapPayload(rec.ciphertext, prfOutput);
            setUnlocked({
                enrollmentSecret: payload.enrollmentSecret,
                merklePath: payload.merklePath,
                merklePathIndices: payload.merklePathIndices.map((b) =>
                    b === 0 || b === 1 ? b : 0,
                ),
                commitment: rec.commitment,
            });
        } catch (e) {
            setUnlockErr(e instanceof Error ? e.message : String(e));
        } finally {
            setUnlocking(false);
        }
    }

    async function startProve() {
        if (!petition || !unlocked || vote === null) return;
        setProveErr(null);
        setProveStage("initWorker");
        try {
            const nul = await pedersenNullifier(
                unlocked.enrollmentSecret,
                petition.id,
            );
            setNullifier(nul);
            const root =
                enrollmentRoot ??
                // Fallback for the unblocked scaffold: zero root.
                (("0x" + "0".repeat(64)) as `0x${string}`);

            const witness = {
                enrollment_secret: unlocked.enrollmentSecret,
                merkle_path: unlocked.merklePath,
                merkle_path_indices: unlocked.merklePathIndices,
                petition_id: `0x${petition.id.toString(16).padStart(64, "0")}`,
                enrollment_root: root,
                nullifier: nul,
            };

            const worker = new Worker(
                new URL("../worker/prove.worker.ts", import.meta.url),
                { type: "module" },
            );

            const out: ProveOutput = await new Promise((resolve, reject) => {
                worker.onmessage = (ev: MessageEvent) => {
                    const m = ev.data as
                        | { type: "stage"; stage: ProveStage }
                        | { type: "done"; proofBytes: number[]; publicInputs: string[] }
                        | { type: "error"; detail: string };
                    if (m.type === "stage") setProveStage(m.stage);
                    else if (m.type === "done") {
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

            setProof(out);
            setProveStage("done");
        } catch (e) {
            setProveErr(e instanceof Error ? e.message : String(e));
            setProveStage("idle");
        }
    }

    async function doSubmit() {
        if (!petition || !proof || !nullifier || vote === null) return;
        setSubmitting(true);
        setSubmitErr(null);
        try {
            const proofHex = ("0x" +
                Array.from(proof.proofBytes, (n) =>
                    n.toString(16).padStart(2, "0"),
                ).join("")) as `0x${string}`;

            const res = await submitSignature({
                petitionId: petition.id,
                vote,
                nullifier,
                proof: proofHex,
                publicInputs: proof.publicInputs as `0x${string}`[],
            });
            if (res.ok) {
                setSubmittedTx(res.txHash);
                onDone(res.txHash, vote);
                return;
            }
            setSubmitErr(res.code);
        } catch (e) {
            setSubmitErr(e instanceof Error ? e.message : "Unknown");
        } finally {
            setSubmitting(false);
        }
    }

    const checklist: Array<{ key: "vote" | "unlock" | "root"; ok: boolean }> = [
        { key: "vote", ok: vote !== null },
        { key: "unlock", ok: unlocked !== null },
        { key: "root", ok: enrollmentRoot !== null },
    ];
    const allReady = checklist.every((c) => c.ok);

    return (
        <section className="section">
            <button className="btn--link" onClick={onBack} type="button">
                ← {t("sign.back")}
            </button>
            <h2 className="section__title" style={{ marginTop: 8 }}>
                {t("sign.heading", { id: petitionId.toString() })}
            </h2>

            {petitionErr ? <p className="error-line">{petitionErr}</p> : null}

            {hasEnrollment === false ? (
                <div className="panel panel--inline-error">
                    <p className="error-line">
                        {t("sign.vote.missingEnrollment")}
                    </p>
                    {onRecover ? (
                        // YEL-6 fix (option a): surface Recover only at the
                        // moment a citizen actually needs it — i.e. when
                        // signing fails because there's no enrollment on this
                        // device — rather than as a cold-start nav entry.
                        // See bench/ux-results-2026-05-29.md §YELLOW-6.
                        <button
                            className="btn--link"
                            onClick={onRecover}
                            type="button"
                        >
                            {t("sign.vote.alreadyEnrolledElsewhere")}
                        </button>
                    ) : null}
                </div>
            ) : null}

            {/* 1. Vote */}
            {petition ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.vote.title")}</p>
                    <p className="note">
                        {t("sign.vote.intro", { mode: petition.modeLabel })}
                    </p>
                    <div className="actions">
                        {allowedVotes.map((v) => {
                            // Contract vote semantics (#31):
                            //   Signature: 0 = sign
                            //   YesNo / YesNoAbstain: 0=No, 1=Yes, 2=Abstain
                            const label =
                                petition.modeLabel === "Signature"
                                    ? t("sign.vote.signOnly")
                                    : v === 1
                                      ? t("sign.vote.yes")
                                      : v === 0
                                        ? t("sign.vote.no")
                                        : t("sign.vote.abstain");
                            return (
                                <button
                                    key={v}
                                    type="button"
                                    className={
                                        "btn btn--small " +
                                        (vote === v ? "btn--accent" : "btn--ghost")
                                    }
                                    onClick={() => setVote(v)}
                                >
                                    {label}
                                </button>
                            );
                        })}
                    </div>
                </div>
            ) : null}

            {/* 2. Unlock */}
            {petition && vote !== null ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.unlock.title")}</p>
                    <p className="note">{t("sign.unlock.intro")}</p>
                    {unlocked ? (
                        <p className="tag-ok">✓ {t("sign.unlock.ok")}</p>
                    ) : (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={handleUnlock}
                                disabled={unlocking}
                            >
                                {unlocking
                                    ? t("sign.unlock.running")
                                    : t("sign.unlock.start")}
                            </button>
                        </div>
                    )}
                    {unlockErr ? (
                        <p className="error-line">
                            {t("sign.unlock.error", { detail: unlockErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 3. Prove */}
            {petition && vote !== null && unlocked ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.prove.title")}</p>
                    <p className="note">{t("sign.prove.intro")}</p>
                    <ul className="checklist">
                        {checklist.map((c) => (
                            <li
                                key={c.key}
                                className={
                                    c.ok
                                        ? "checklist__item checklist__item--ok"
                                        : "checklist__item"
                                }
                            >
                                <span aria-hidden>{c.ok ? "✓" : "○"}</span>{" "}
                                {t(`sign.prove.needs.${c.key}`)}
                            </li>
                        ))}
                    </ul>
                    {proveStage === "done" ? (
                        <p className="tag-ok">✓ {t("sign.prove.stages.done")}</p>
                    ) : proveStage !== "idle" ? (
                        <div className="progress">
                            <span>{t(`sign.prove.stages.${proveStage}`)}</span>
                            <div className="progress__line">
                                <span />
                            </div>
                        </div>
                    ) : (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={startProve}
                                disabled={!allReady}
                                title={
                                    allReady ? undefined : t("sign.prove.waiting")
                                }
                            >
                                {t("sign.prove.start")}
                            </button>
                        </div>
                    )}
                    {proveErr ? (
                        <p className="error-line">
                            {t("sign.prove.error", { detail: proveErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 4. Submit */}
            {proof ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.steps.submit")}</p>
                    <p className="note">{t("sign.submit.intro")}</p>
                    <div className="actions">
                        <button
                            className="btn btn--accent"
                            onClick={doSubmit}
                            type="button"
                            disabled={submitting}
                        >
                            {submitting
                                ? t("sign.submit.sending")
                                : t("sign.submit.send")}
                        </button>
                    </div>
                    {submittedTx ? (
                        <p className="note mono">
                            <a href={basescanTxUrl(submittedTx)} target="_blank">
                                {submittedTx}
                            </a>
                        </p>
                    ) : null}
                    {submitErr ? (
                        <p className="error-line">
                            {t(`sign.submit.errors.${submitErr}`, {
                                defaultValue: t("sign.submit.errors.Unknown"),
                            })}
                        </p>
                    ) : null}
                </div>
            ) : null}
        </section>
    );
}
