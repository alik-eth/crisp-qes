import { useState, useCallback } from "react";
import { useLocation } from "wouter";
import { useTranslation } from "react-i18next";
import { parseP7s, type ParsedP7s } from "@crisp-qes/sdk";
import { extractRnokpp, tinuaPrefixOk } from "../lib/rnokpp.js";
import { blind, unblind, verifyBlindEval } from "../lib/voprf.js";
import { oprfBlindEval, oprfRegister, oprfRecoverPath } from "../lib/oprfClient.js";
import { pedersenS } from "../lib/pedersen.js";
import { submitEnrollment, explorerTxUrl } from "../lib/relayer.js";
import {
    putEnrollment,
    wrapPayload,
    type EnrollmentPayload,
} from "../lib/encryptedStore.js";
import { evaluatePrf } from "../lib/webauthnPrf.js";
import { getAccount } from "../lib/account.js";
import {
    getSessionPrf,
    setSessionPrf,
} from "../lib/passkeySession.js";
import { buildChallengeBytes } from "../lib/enrollmentChallenge.js";
import { config } from "../config.js";

interface Props {
    onDone: () => Promise<void>;
}

type Substage =
    | "identify"
    | "challenge"
    | "verifying"
    | "verified"
    | "saving"
    | "saved";

interface BlindState {
    r: bigint;
    blindedElement: Uint8Array;
    rnokpp: string;
}

interface OprfArtifacts {
    N: Uint8Array;
    s: `0x${string}`;
    leafIndex: number;
    merklePath: `0x${string}`[];
    merklePathIndices: (0 | 1)[];
    txHash: `0x${string}` | null;
    recovered: boolean;
}

function hexEncode(b: Uint8Array): `0x${string}` {
    let s = "0x";
    for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
    return s as `0x${string}`;
}
function hexDecode(h: `0x${string}`): Uint8Array {
    const s = h.startsWith("0x") ? h.slice(2) : h;
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++)
        out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
    return out;
}

const RNOKPP_RE = /^[0-9]{10}$/;

export function Verify({ onDone }: Props) {
    const { t } = useTranslation();
    const [, navigate] = useLocation();
    const [stage, setStage] = useState<Substage>("identify");
    const [rnokppInput, setRnokppInput] = useState("");
    const [blindState, setBlindState] = useState<BlindState | null>(null);
    const [parsed, setParsed] = useState<ParsedP7s | null>(null);
    const [p7sBytes, setP7sBytes] = useState<Uint8Array | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const [ageBlocked, setAgeBlocked] = useState<{
        min: number;
        found: number;
    } | null>(null);
    const [oprfResult, setOprfResult] = useState<OprfArtifacts | null>(null);

    const onGenerate = useCallback(() => {
        setErr(null);
        const rnokpp = rnokppInput.trim();
        if (!RNOKPP_RE.test(rnokpp)) {
            setErr("RNOKPP must be exactly 10 digits.");
            return;
        }
        try {
            const inputBytes = new TextEncoder().encode(rnokpp);
            const { blind: r, blindedElement } = blind(inputBytes);
            const bytes = buildChallengeBytes(
                blindedElement,
                config.oprfEnrollmentEpoch,
            );
            const ab = new ArrayBuffer(bytes.byteLength);
            new Uint8Array(ab).set(bytes);
            const blob = new Blob([ab], { type: "text/plain" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "crisp-qes-challenge.txt";
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
            setBlindState({ r, blindedElement, rnokpp });
            setStage("challenge");
        } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
        }
    }, [rnokppInput]);

    const onFile = useCallback(
        async (file: File) => {
            if (!blindState) return;
            setErr(null);
            setParsed(null);
            try {
                const bytes = new Uint8Array(await file.arrayBuffer());
                const p = parseP7s(bytes);
                if (!tinuaPrefixOk(p)) {
                    setErr(
                        "This isn't a Diia QES. The certificate must be signed by a Ukrainian QTSP.",
                    );
                    return;
                }
                let certRnokpp: string;
                try {
                    certRnokpp = extractRnokpp(p);
                } catch (e) {
                    setErr(
                        "Couldn't read RNOKPP from the certificate: " +
                            (e instanceof Error ? e.message : String(e)),
                    );
                    return;
                }
                if (certRnokpp !== blindState.rnokpp) {
                    setErr(
                        `The certificate's RNOKPP (${certRnokpp}) doesn't match ` +
                            `the one you typed (${blindState.rnokpp}). Re-upload a ` +
                            `.p7s signed by the same Diia identity.`,
                    );
                    return;
                }
                setP7sBytes(bytes);
                setParsed(p);
            } catch (e) {
                setErr(
                    "Couldn't read the .p7s file: " +
                        (e instanceof Error ? e.message : String(e)),
                );
            }
        },
        [blindState],
    );

    const runVerify = useCallback(async () => {
        if (!parsed || !p7sBytes || !blindState) return;
        setStage("verifying");
        setErr(null);
        setAgeBlocked(null);
        try {
            const resp = await oprfBlindEval(
                blindState.blindedElement,
                p7sBytes,
            );
            const ok = verifyBlindEval(blindState.blindedElement, {
                serverPubkey: hexDecode(resp.oprfPubkey),
                evaluatedElement: hexDecode(resp.Y),
                proof: resp.proof,
            });
            if (!ok) throw new Error("OPRF DLEQ proof did not verify");
            const N = unblind(hexDecode(resp.Y), blindState.r);
            const s = await pedersenS(N);

            let artifacts: Omit<OprfArtifacts, "N" | "s">;
            try {
                const reg = await oprfRegister({
                    commitment: s,
                    blindedInputUsed: blindState.blindedElement,
                    unblindedOutput: N,
                });
                const tx = await submitEnrollment({
                    newRoot: reg.newRoot,
                    newCommitments: reg.newCommitments,
                    signature: reg.attesterSig,
                });
                if (!tx.ok) {
                    throw new Error(tx.detail ?? tx.code ?? "chain submit failed");
                }
                artifacts = {
                    leafIndex: reg.leafIndex,
                    merklePath: reg.merklePath,
                    merklePathIndices: reg.merklePathIndices,
                    txHash: tx.txHash,
                    recovered: false,
                };
            } catch (regErr) {
                const re = regErr as { status?: number; code?: string };
                if (re?.status === 409 && re.code === "AlreadyEnrolled") {
                    const rec = await oprfRecoverPath(s);
                    artifacts = {
                        leafIndex: rec.leafIndex,
                        merklePath: rec.merklePath,
                        merklePathIndices: rec.merklePathIndices,
                        txHash: null,
                        recovered: true,
                    };
                } else {
                    throw regErr;
                }
            }

            setOprfResult({ N, s, ...artifacts });
            setStage("verified");
        } catch (e) {
            const eo = e as {
                status?: number;
                code?: string;
                body?: { min?: unknown; found?: unknown };
                message?: string;
            };
            if (eo?.status === 403 && eo.code === "age_below_threshold") {
                setAgeBlocked({
                    min: typeof eo.body?.min === "number" ? eo.body.min : 18,
                    found:
                        typeof eo.body?.found === "number"
                            ? eo.body.found
                            : 0,
                });
                setStage("challenge");
                return;
            }
            if (eo?.status === 401 && eo.code === "PayloadMismatch") {
                setErr(
                    "Your .p7s doesn't sign over the challenge we generated. " +
                        "Re-download the challenge file and sign that exact file " +
                        "in Diia, then upload the new .p7s.",
                );
                setStage("challenge");
                return;
            }
            setErr(eo.message ?? String(e));
            setStage("challenge");
        }
    }, [parsed, p7sBytes, blindState]);

    const runSave = useCallback(async () => {
        if (!oprfResult) return;
        setStage("saving");
        setErr(null);
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
                enrollmentSecret: oprfResult.s,
                oprfOutputN: hexEncode(oprfResult.N),
                merklePath: oprfResult.merklePath,
                merklePathIndices: oprfResult.merklePathIndices,
            };
            const ciphertext = await wrapPayload(payload, prf);
            await putEnrollment({
                version: 1,
                commitment: oprfResult.s,
                leafIndex: oprfResult.leafIndex,
                credentialId: acct.credentialId,
                ciphertext,
            });
            setStage("saved");
            await onDone();
        } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
            setStage("verified");
        }
    }, [oprfResult, onDone]);

    const onContinue = useCallback(() => navigate("/petitions"), [navigate]);

    return (
        <section className="verify">
            <header style={{ marginBottom: 32 }}>
                <h1>{t("verify.heading")}</h1>
                <p className="muted" style={{ marginTop: 8, maxWidth: 600 }}>
                    {t("verify.subtitle")}
                </p>
            </header>

            <StageStrip stage={stage} />

            {ageBlocked ? (
                <div className="notice notice--bad" style={{ marginTop: 24 }}>
                    <div>
                        <strong>{t("verify.adultsOnly")}</strong>{" "}
                        {t("verify.adultsOnlyDetail", { min: ageBlocked.min, found: ageBlocked.found })}
                    </div>
                </div>
            ) : null}

            {err ? (
                <div className="notice notice--bad" style={{ marginTop: 24 }}>
                    <div>
                        <strong>{t("verify.verifyFailed")}</strong>
                        <br />
                        <span className="small mono">{err}</span>
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
                ) : stage === "challenge" ? (
                    <ChallengePanel
                        blindState={blindState!}
                        parsed={parsed}
                        onFile={onFile}
                        onVerify={() => void runVerify()}
                        onRegenerate={() => {
                            setParsed(null);
                            setP7sBytes(null);
                            onGenerate();
                        }}
                        onReset={() => {
                            setBlindState(null);
                            setParsed(null);
                            setP7sBytes(null);
                            setStage("identify");
                        }}
                    />
                ) : stage === "verifying" ? (
                    <VerifyingPanel />
                ) : stage === "verified" ? (
                    <VerifiedPanel
                        oprfResult={oprfResult!}
                        onSave={() => void runSave()}
                    />
                ) : stage === "saving" ? (
                    <SavingPanel />
                ) : (
                    <SavedPanel onContinue={onContinue} />
                )}
            </div>
        </section>
    );
}

function StageStrip({ stage }: { stage: Substage }) {
    const { t } = useTranslation();
    const steps: { key: string; label: string; match: Substage[] }[] = [
        { key: "identify", label: t("verify.step1"), match: ["identify"] },
        { key: "challenge", label: t("verify.step2"), match: ["challenge"] },
        { key: "verify", label: t("verify.step3"), match: ["verifying"] },
        { key: "save", label: t("verify.step4"), match: ["verified", "saving"] },
    ];
    return (
        <ol className="strip" aria-label="Progress">
            {steps.map((s, i) => {
                const done = stepIsDone(stage, s.key);
                const active = s.match.includes(stage);
                const cls = active
                    ? "strip__step strip__step--active"
                    : done
                      ? "strip__step strip__step--done"
                      : "strip__step";
                return (
                    <li key={s.key} className={cls}>
                        <span className="strip__n"><span>{i + 1}</span></span>
                        <span className="strip__label">{s.label}</span>
                    </li>
                );
            })}
        </ol>
    );
}

function stepIsDone(stage: Substage, step: string): boolean {
    const order: Substage[] = [
        "identify",
        "challenge",
        "verifying",
        "verified",
        "saving",
        "saved",
    ];
    const idx = order.indexOf(stage);
    if (step === "identify") return idx >= 1;
    if (step === "challenge") return idx >= 2;
    if (step === "verify") return idx >= 3;
    if (step === "save") return idx >= 5;
    return false;
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
            <p className="muted small" style={{ marginTop: 8, marginBottom: 16 }}>
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

function ChallengePanel({
    blindState,
    parsed,
    onFile,
    onVerify,
    onRegenerate,
    onReset,
}: {
    blindState: BlindState;
    parsed: ParsedP7s | null;
    onFile: (file: File) => Promise<void>;
    onVerify: () => void;
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
                <span className="mono">{blindState.rnokpp}</span>
            </p>
            <label
                className="dropzone"
                onDragOver={(e) => { e.preventDefault(); }}
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
                    <div>{t("verify.parsed")}</div>
                </div>
            ) : null}
            <div className="row" style={{ marginTop: 20 }}>
                <button
                    type="button"
                    className="btn btn--primary"
                    onClick={onVerify}
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

function VerifyingPanel() {
    const { t } = useTranslation();
    return (
        <div className="card">
            <h3>{t("verify.verifyingTitle")}</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                {t("verify.verifyingBody")}
            </p>
            <div className="progress-band" style={{ marginTop: 16 }}>
                <span className="spinner" aria-hidden="true" />
                <span className="small mono">{t("verify.verifyingWait")}</span>
            </div>
        </div>
    );
}

function VerifiedPanel({
    oprfResult,
    onSave,
}: {
    oprfResult: OprfArtifacts;
    onSave: () => void;
}) {
    const { t } = useTranslation();
    return (
        <div className="card">
            <h3>{oprfResult.recovered ? t("verify.verifiedRecoveredTitle") : t("verify.verifiedTitle")}</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                {oprfResult.recovered
                    ? t("verify.verifiedRecoveredBody")
                    : t("verify.verifiedBody")}
            </p>
            {oprfResult.txHash ? (
                <p className="small" style={{ marginTop: 12 }}>
                    <a
                        href={explorerTxUrl(oprfResult.txHash)}
                        target="_blank"
                        rel="noreferrer"
                    >
                        {t("verify.viewTx")}
                    </a>
                </p>
            ) : null}
            <button
                type="button"
                className="btn btn--primary"
                style={{ marginTop: 20 }}
                onClick={onSave}
            >
                {oprfResult.recovered ? t("verify.restoreBtn") : t("verify.saveBtn")}
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
