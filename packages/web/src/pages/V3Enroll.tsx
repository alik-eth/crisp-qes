import { useState, useCallback } from "react";
import { useLocation } from "wouter";
import { useTranslation } from "react-i18next";
import { parseP7s, type ParsedP7s } from "@crisp-qes/sdk";
import { extractRnokpp, extractDOB, tinuaPrefixOk } from "../lib/rnokpp.js";
import {
    runRealEnrollment,
    type RealRunStage,
    type RealEnrollResult,
} from "../lib/v3enroll.js";
import { submitEnrollment, explorerTxUrl } from "../lib/relayer.js";
import {
    putEnrollment,
    wrapPayload,
    type EnrollmentPayload,
} from "../lib/encryptedStore.js";
import { evaluatePrf } from "../lib/webauthnPrf.js";
import { getAccount } from "../lib/account.js";
import { getSessionPrf, setSessionPrf } from "../lib/passkeySession.js";
import { sha256 } from "@noble/hashes/sha2";
import { hashToCurve, N } from "../lib/grumpkin.js";
import { buildChallengeBytesV3, ENROLL_V3_EPOCH } from "../lib/enrollmentChallengeV3.js";
import { useWakeLock } from "../lib/useWakeLock.js";

// PRIMARY operator-blind enrollment (v3), EXPERIMENTAL / UNAUDITED.
//
// Real Diia .p7s, entirely in-browser:
//   parse .p7s + build enroll_commit_v2 witness -> prove (~118k gates) ->
//   POST live Grumpkin /v3/blind-eval -> prove oprf_nullifier -> POST
//   /v3/register (both proofs) -> relayer /v2/enroll (on-chain) -> wrap the
//   vault under the Passkey PRF (enrollment_secret = s = pedersen([N.x,N.y])
//   = the on-chain Merkle leaf). The EXISTING v2 sign/revoke flow then works
//   unchanged because the vault shape + leaf semantics are identical.

interface Props {
    onDone: () => Promise<void>;
}

type Substage =
    | "identify"
    | "challenge"
    | "upload"
    | "running"
    | "enrolled"
    | "saving"
    | "saved";

const RNOKPP_RE = /^[0-9]{10}$/;

type EnrollPhase = "preparing" | "proving" | "finishing";

// Map the raw RealRunStage keys to the 3 friendly phases. We advance to the
// next phase as soon as its first stage starts; a stage is "reached" if we've
// seen ANY status for it.
function currentPhase(stages: Record<string, RealRunStage>): EnrollPhase {
    const seen = (k: RealRunStage["key"]) => stages[k] !== undefined;
    if (seen("register") || seen("chain")) return "finishing";
    if (seen("enrollProve") || seen("serviceEval") || seen("nullifierProve"))
        return "proving";
    return "preparing";
}

const PHASE_ORDER: EnrollPhase[] = ["preparing", "proving", "finishing"];

// Crypto-random blinding scalar in [1, N) (fresh blinding per session). The
// SAME r is reused for the enroll proof so the proof's M matches the challenge
// the citizen signs in Diia and the service reconstructs.
function randomScalarPublic(): bigint {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    let v = 0n;
    for (const b of buf) v = (v << 8n) | BigInt(b);
    return (v % (N - 1n)) + 1n;
}

export function V3Enroll({ onDone }: Props) {
    const { t } = useTranslation();
    const [, navigate] = useLocation();
    const [stage, setStage] = useState<Substage>("identify");
    const [rnokppInput, setRnokppInput] = useState("");
    const [blindState, setBlindState] = useState<{
        r: bigint;
        rnokpp: string;
    } | null>(null);
    const [parsed, setParsed] = useState<ParsedP7s | null>(null);
    const [p7sBytes, setP7sBytes] = useState<Uint8Array | null>(null);
    const [rnokpp, setRnokpp] = useState<string | null>(null);
    const [stages, setStages] = useState<Record<string, RealRunStage>>({});
    const [result, setResult] = useState<RealEnrollResult | null>(null);
    const [error, setError] = useState<string | null>(null);

    const onGenerate = useCallback(() => {
        setError(null);
        const rnokpp = rnokppInput.trim();
        if (!RNOKPP_RE.test(rnokpp)) {
            setError("RNOKPP must be exactly 10 digits.");
            return;
        }
        try {
            const r = randomScalarPublic();
            const M = hashToCurve(new TextEncoder().encode(rnokpp)).multiply(r);
            const bytes = buildChallengeBytesV3(M, ENROLL_V3_EPOCH);
            const ab = new ArrayBuffer(bytes.byteLength);
            new Uint8Array(ab).set(bytes);
            const url = URL.createObjectURL(
                new Blob([ab], { type: "text/plain" }),
            );
            const a = document.createElement("a");
            a.href = url;
            a.download = "crisp-qes-challenge.txt";
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
            setBlindState({ r, rnokpp });
            setStage("challenge");
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        }
    }, [rnokppInput]);

    const onFile = useCallback(async (file: File) => {
        setError(null);
        setParsed(null);
        setP7sBytes(null);
        setRnokpp(null);
        try {
            const bytes = new Uint8Array(await file.arrayBuffer());
            const p = parseP7s(bytes);
            if (!tinuaPrefixOk(p)) {
                setError(
                    "This isn't a Diia QES. The certificate must be signed by a Ukrainian QTSP.",
                );
                return;
            }
            let certRnokpp: string;
            try {
                certRnokpp = extractRnokpp(p);
            } catch (e) {
                setError(
                    "Couldn't read RNOKPP from the certificate: " +
                        (e instanceof Error ? e.message : String(e)),
                );
                return;
            }
            if (!RNOKPP_RE.test(certRnokpp)) {
                setError(`Certificate RNOKPP is not 10 digits: ${certRnokpp}`);
                return;
            }
            if (!blindState || certRnokpp !== blindState.rnokpp) {
                setError(
                    `The certificate's RNOKPP (${certRnokpp}) doesn't match the one you typed` +
                        (blindState ? ` (${blindState.rnokpp}).` : "."),
                );
                return;
            }
            // Local challenge pre-check: the .p7s must be signed over THIS
            // session's challenge. Compare the cert's PKCS#9 messageDigest to
            // sha256(current challenge) so a stale/wrong signature fails
            // instantly here — instead of after a ~30s in-browser proof and a
            // confusing 409 ChallengeMismatch from the service.
            const Mcheck = hashToCurve(
                new TextEncoder().encode(blindState.rnokpp),
            ).multiply(blindState.r);
            const expectedDigest = sha256(
                buildChallengeBytesV3(Mcheck, ENROLL_V3_EPOCH),
            );
            const gotDigest = p.messageDigest;
            const digestOk =
                gotDigest.length === expectedDigest.length &&
                gotDigest.every((b, i) => b === expectedDigest[i]);
            if (!digestOk) {
                setError(
                    "This signature is for a different (or older) challenge. " +
                        "Click “Generate challenge” to get the current crisp-qes-challenge.txt, " +
                        "sign THAT file in Diia, and upload it.",
                );
                return;
            }
            setP7sBytes(bytes);
            setParsed(p);
            setRnokpp(certRnokpp);
        } catch (e) {
            setError(
                "Couldn't read the .p7s file: " +
                    (e instanceof Error ? e.message : String(e)),
            );
        }
    }, [blindState]);

    const onRun = useCallback(async () => {
        if (!p7sBytes || !parsed || !blindState) return;
        setStage("running");
        setStages({});
        setResult(null);
        setError(null);
        try {
            const dob = extractDOB(parsed);
            const res = await runRealEnrollment(
                p7sBytes,
                dob,
                async (a) => {
                    const r = await submitEnrollment(a);
                    return r.ok
                        ? { ok: true as const, txHash: r.txHash }
                        : { ok: false as const, code: r.code, detail: r.detail };
                },
                (s) => setStages((prev) => ({ ...prev, [s.key]: s })),
                { r: blindState.r },
            );
            setResult(res);
            setStage("enrolled");
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            setStage("upload");
        }
    }, [p7sBytes, parsed, blindState]);

    const onSave = useCallback(async () => {
        if (!result) return;
        setStage("saving");
        setError(null);
        try {
            const acct = await getAccount();
            if (!acct) throw new Error("missing local Passkey account");
            let prf = getSessionPrf();
            if (!prf) {
                const got = await evaluatePrf();
                prf = got.prfOutput;
                setSessionPrf(prf);
            }
            const payload: EnrollmentPayload = {
                enrollmentSecret: result.commitment,
                oprfOutputN: result.oprfOutputN,
                merklePath: result.merklePath,
                merklePathIndices: result.merklePathIndices,
            };
            const ciphertext = await wrapPayload(payload, prf);
            await putEnrollment({
                version: 1,
                commitment: result.commitment,
                leafIndex: result.leafIndex,
                credentialId: acct.credentialId,
                ciphertext,
            });
            setStage("saved");
            await onDone();
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            setStage("enrolled");
        }
    }, [result, onDone]);

    return (
        <section className="verify">
            <div className="notice notice--bad" style={{ marginBottom: 24 }}>
                <strong>EXPERIMENTAL / UNAUDITED.</strong>
            </div>

            <header style={{ marginBottom: 32 }}>
                <h1>{t("verify.heading")}</h1>
                <p className="muted" style={{ marginTop: 8, maxWidth: 600 }}>
                    {t("verify.subtitle")}
                </p>
            </header>

            {error ? (
                <div className="notice notice--bad" style={{ marginTop: 24 }}>
                    <div>
                        <strong>{t("verify.verifyFailed")}</strong>
                        <br />
                        <span className="small mono">{error}</span>
                    </div>
                </div>
            ) : null}

            <div className="verify__panel">
                {stage === "identify" ? (
                    <IdentifyPanel
                        rnokppInput={rnokppInput}
                        onChange={setRnokppInput}
                        onGenerate={onGenerate}
                    />
                ) : stage === "challenge" || stage === "upload" ? (
                    <UploadPanel
                        rnokpp={blindState?.rnokpp ?? null}
                        parsed={parsed}
                        certRnokpp={rnokpp}
                        onFile={onFile}
                        onRun={() => void onRun()}
                        onRegenerate={() => {
                            setParsed(null);
                            setP7sBytes(null);
                            setRnokpp(null);
                            onGenerate();
                        }}
                        onReset={() => {
                            setBlindState(null);
                            setParsed(null);
                            setP7sBytes(null);
                            setRnokpp(null);
                            setStage("identify");
                        }}
                    />
                ) : stage === "running" ? (
                    <RunningPanel stages={stages} />
                ) : stage === "saving" ? (
                    <SavingPanel />
                ) : stage === "saved" ? (
                    <SavedPanel onContinue={() => navigate("/petitions")} />
                ) : (
                    <EnrolledPanel
                        result={result!}
                        onSave={() => void onSave()}
                    />
                )}
            </div>
        </section>
    );
}

function IdentifyPanel({
    rnokppInput,
    onChange,
    onGenerate,
}: {
    rnokppInput: string;
    onChange: (s: string) => void;
    onGenerate: () => void;
}) {
    const { t } = useTranslation();
    return (
        <div className="card">
            <h3>{t("verify.identifyTitle")}</h3>
            <p
                className="muted small"
                style={{ marginTop: 8, marginBottom: 16 }}
            >
                {t("verify.identifyBody")}
            </p>
            <label>
                <input
                    type="text"
                    inputMode="numeric"
                    autoComplete="off"
                    pattern="[0-9]*"
                    maxLength={10}
                    value={rnokppInput}
                    onChange={(e) =>
                        onChange(e.target.value.replace(/[^0-9]/g, ""))
                    }
                    placeholder="0000000000"
                    style={{ marginTop: 8 }}
                />
            </label>
            <p className="muted small" style={{ marginTop: 12 }}>
                {t("verify.identifyPrivacy")}
            </p>
            <button
                type="button"
                className="btn btn--primary"
                style={{ marginTop: 20 }}
                onClick={onGenerate}
                disabled={!RNOKPP_RE.test(rnokppInput)}
            >
                {t("verify.identifyBtn")}
            </button>
        </div>
    );
}

function UploadPanel({
    rnokpp,
    parsed,
    certRnokpp,
    onFile,
    onRun,
    onRegenerate,
    onReset,
}: {
    rnokpp: string | null;
    parsed: ParsedP7s | null;
    certRnokpp: string | null;
    onFile: (file: File) => Promise<void>;
    onRun: () => void;
    onRegenerate: () => void;
    onReset: () => void;
}) {
    const { t } = useTranslation();
    return (
        <div className="card">
            <h3>{t("verify.challengeTitle")}</h3>
            <p className="muted small" style={{ marginTop: 8, marginBottom: 16 }}>
                {t("verify.challengeIntro")}
            </p>
            <ol
                className="challenge-steps"
                style={{ marginBottom: 16 }}
            >
                {(t("verify.challengeSteps", { returnObjects: true }) as string[]).map(
                    (step, i) => (
                        <li key={i} dangerouslySetInnerHTML={{ __html: step }} />
                    ),
                )}
            </ol>
            <p className="muted small" style={{ marginBottom: 16 }}>
                {t("verify.rnokppLabel")}{" "}
                <span className="mono">{rnokpp}</span>
            </p>
            <label
                className="dropzone"
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                    e.preventDefault();
                    const f = e.dataTransfer?.files[0];
                    if (f) void onFile(f);
                }}
            >
                <input
                    type="file"
                    onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) void onFile(f);
                    }}
                    style={{ display: "none" }}
                />
                <span className="dropzone__label">
                    {t("verify.dropLabel")}
                </span>
                <span className="dropzone__hint muted small">
                    {t("verify.dropHint")}
                </span>
            </label>
            {parsed ? (
                <div className="notice notice--ok" style={{ marginTop: 16 }}>
                    <div>
                        {t("verify.parsed")}
                    </div>
                </div>
            ) : null}
            <div className="row" style={{ marginTop: 20 }}>
                <button
                    type="button"
                    className="btn btn--primary"
                    onClick={onRun}
                    disabled={!parsed}
                >
                    {t("verify.verifyBtn")}
                </button>
                <button
                    type="button"
                    className="btn btn--ghost"
                    onClick={onRegenerate}
                >
                    {t("verify.redownload")}
                </button>
                <button
                    type="button"
                    className="btn btn--link"
                    onClick={onReset}
                >
                    {t("verify.startOver")}
                </button>
            </div>
        </div>
    );
}

function RunningPanel({ stages }: { stages: Record<string, RealRunStage> }) {
    const { t } = useTranslation();
    // Hold a screen wake lock for the whole time this panel is mounted (the
    // proof is in flight). Released automatically on unmount / done / error.
    useWakeLock(true);

    const phase = currentPhase(stages);
    const activeIdx = PHASE_ORDER.indexOf(phase);

    return (
        <div className="card">
            <h3>{t("verify.runningTitle")}</h3>

            <div
                className="enroll-run"
                style={{ marginTop: 16 }}
                aria-live="polite"
                aria-busy="true"
            >
                <div className="enroll-run__lede">
                    <span
                        className="spinner spinner--lg"
                        aria-hidden="true"
                    />
                    <div>
                        <div className="enroll-run__status">
                            {t(`verify.runningPhase.${phase}`)}
                        </div>
                        <div className="enroll-run__eta">
                            {t("verify.runningEta")}
                        </div>
                    </div>
                </div>

                <ol className="enroll-phases">
                    {PHASE_ORDER.map((p, i) => {
                        const state =
                            i < activeIdx
                                ? "done"
                                : i === activeIdx
                                  ? "active"
                                  : "todo";
                        return (
                            <li
                                key={p}
                                className={`enroll-phase enroll-phase--${state}`}
                            >
                                <span
                                    className="enroll-phase__mark"
                                    aria-hidden="true"
                                >
                                    <span>{state === "done" ? "✓" : i + 1}</span>
                                </span>
                                <span className="enroll-phase__label">
                                    {t(`verify.runningPhase.${p}`)}
                                </span>
                                {state === "active" ? (
                                    <span
                                        className="enroll-phase__pulse"
                                        aria-hidden="true"
                                    />
                                ) : null}
                            </li>
                        );
                    })}
                </ol>

                <p className="enroll-run__keepon">
                    <span
                        className="enroll-run__keepon-mark"
                        aria-hidden="true"
                    >
                        !
                    </span>
                    <span>{t("verify.runningKeepOn")}</span>
                </p>
            </div>
        </div>
    );
}

function EnrolledPanel({
    result,
    onSave,
}: {
    result: RealEnrollResult;
    onSave: () => void;
}) {
    const { t } = useTranslation();
    return (
        <div className="card">
            <h3>{result.recovered ? t("verify.verifiedRecoveredTitle") : t("verify.verifiedTitle")}</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                {result.recovered ? (
                    t("verify.verifiedRecoveredBody")
                ) : (
                    <>
                        {t("verify.verifiedBody")}{" "}
                        {result.txHash && (
                            <a
                                href={explorerTxUrl(result.txHash)}
                                target="_blank"
                                rel="noreferrer"
                            >
                                {t("verify.viewTx")}
                            </a>
                        )}
                    </>
                )}
            </p>
            <p
                className="mono small"
                style={{ wordBreak: "break-all", marginTop: 12 }}
            >
                {result.commitment}
            </p>
            <button type="button" className="btn btn--primary" style={{ marginTop: 20 }} onClick={onSave}>
                {result.recovered ? t("verify.restoreBtn") : t("verify.saveBtn")}
            </button>
        </div>
    );
}

function SavingPanel() {
    const { t } = useTranslation();
    return (
        <div className="card">
            <h3>{t("verify.savingTitle")}</h3>
            <div className="progress-band" style={{ marginTop: 12 }}>
                <span className="spinner" aria-hidden="true" />
                <span className="small">{t("verify.savingBody")}</span>
            </div>
        </div>
    );
}

function SavedPanel({ onContinue }: { onContinue: () => void }) {
    const { t } = useTranslation();
    return (
        <div className="card">
            <div className="notice notice--ok">
                <div>{t("verify.savedOk")}</div>
            </div>
            <button
                type="button"
                className="btn btn--primary btn--block"
                style={{ marginTop: 20 }}
                onClick={onContinue}
            >
                {t("verify.savedBtn")}
            </button>
        </div>
    );
}
