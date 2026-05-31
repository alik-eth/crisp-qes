import { useState, useCallback } from "react";
import { useLocation } from "wouter";
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
import { hashToCurve, N } from "../lib/grumpkin.js";
import { buildChallengeBytesV3, ENROLL_V3_EPOCH } from "../lib/enrollmentChallengeV3.js";

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

const STAGE_ORDER: RealRunStage["key"][] = [
    "parseWitness",
    "enrollProve",
    "serviceEval",
    "nullifierProve",
    "register",
    "chain",
];

const RNOKPP_RE = /^[0-9]{10}$/;

function fmtMs(ms?: number): string {
    if (ms === undefined) return "";
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(1)} s`;
}

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
                <h1>Verify with Diia QES — operator-blind</h1>
                <p className="muted" style={{ marginTop: 8, maxWidth: 560 }}>
                    Prove you're a verified Ukrainian adult, anonymously. Your
                    RNOKPP is hashed and blinded locally; the service evaluates
                    a blind OPRF and never learns your identity.
                </p>
            </header>

            {error ? (
                <div className="notice notice--bad" style={{ marginTop: 24 }}>
                    <div>
                        <strong>Enrollment failed.</strong>
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
    return (
        <div className="card">
            <h3>Enter your RNOKPP</h3>
            <p
                className="muted small"
                style={{ marginTop: 8, marginBottom: 16 }}
            >
                We use this to compute your anonymous identity locally and to
                cross-check the certificate in your .p7s. Find it in the Diia
                app under Documents → РНОКПП. 10 digits, all numeric.
            </p>
            <label>
                RNOKPP
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
                Your RNOKPP never reaches the service. It's hashed and blinded
                locally; only the blinded element M is sent, gated by a
                zero-knowledge proof of your Diia certificate.
            </p>
            <button
                type="button"
                className="btn btn--primary"
                style={{ marginTop: 20 }}
                onClick={onGenerate}
                disabled={!RNOKPP_RE.test(rnokppInput)}
            >
                Generate challenge
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
}: {
    rnokpp: string | null;
    parsed: ParsedP7s | null;
    certRnokpp: string | null;
    onFile: (file: File) => Promise<void>;
    onRun: () => void;
}) {
    return (
        <div className="card">
            <h3>Sign the challenge in Diia</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                A file <span className="mono">crisp-qes-challenge.txt</span> was
                downloaded to this device. It contains the exact bytes you must
                sign with your Diia QES — this binds your signature to THIS
                enrollment and to the blinded element the service evaluates.
            </p>
            <ol
                className="muted small"
                style={{ marginTop: 12, paddingLeft: 18, marginBottom: 16 }}
            >
                <li>Open the Diia app.</li>
                <li>Go to "Sign documents" (Підписати документ).</li>
                <li>
                    Select the downloaded{" "}
                    <span className="mono">crisp-qes-challenge.txt</span>.
                </li>
                <li>Enter your Diia PIN to sign.</li>
                <li>
                    Save the resulting <span className="mono">.p7s</span> file
                    and upload it here.
                </li>
            </ol>
            <p className="muted small" style={{ marginBottom: 16 }}>
                RNOKPP being enrolled:{" "}
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
                    Drop the signed .p7s here, or click to choose
                </span>
                <span className="dropzone__hint muted small">
                    Must be the .p7s produced by signing the file above
                </span>
            </label>
            {parsed ? (
                <div className="notice notice--ok" style={{ marginTop: 16 }}>
                    <div>
                        Diia QES recognised and RNOKPP matches{" "}
                        <span className="mono">{certRnokpp}</span>.
                    </div>
                </div>
            ) : null}
            <button
                type="button"
                className="btn btn--primary"
                style={{ marginTop: 20 }}
                onClick={onRun}
                disabled={!parsed}
            >
                Enroll (operator-blind)
            </button>
        </div>
    );
}

function RunningPanel({ stages }: { stages: Record<string, RealRunStage> }) {
    return (
        <div className="card">
            <h3>Enrolling anonymously…</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                Two UltraHonk proofs run in this browser. This can take
                10–60 seconds on a phone. Don't close this tab.
            </p>
            <ol
                style={{ listStyle: "none", padding: "1rem 0 0", margin: 0 }}
            >
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
    return (
        <div className="card">
            <h3>{result.recovered ? "Recovered." : "Verified on chain."}</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                {result.recovered ? (
                    "This Diia identity was already enrolled — recovered the existing on-chain commitment for this device."
                ) : (
                    <>
                        Your anonymous commitment is now on Sepolia.{" "}
                        {result.txHash && (
                            <a
                                href={explorerTxUrl(result.txHash)}
                                target="_blank"
                                rel="noreferrer"
                            >
                                View transaction →
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
            <p style={{ marginTop: 20, marginBottom: 16 }}>
                Last step: encrypt your private signing material with your
                Passkey and save it to this device.
            </p>
            <button type="button" className="btn btn--primary" onClick={onSave}>
                Encrypt and save
            </button>
        </div>
    );
}

function SavingPanel() {
    return (
        <div className="card">
            <h3>Saving…</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                Waiting for the Passkey prompt, then encrypting.
            </p>
        </div>
    );
}

function SavedPanel({ onContinue }: { onContinue: () => void }) {
    return (
        <div className="card">
            <div className="notice notice--ok">
                <div>
                    You're verified. You can sign and create petitions now.
                </div>
            </div>
            <button
                type="button"
                className="btn btn--primary btn--block"
                style={{ marginTop: 20 }}
                onClick={onContinue}
            >
                Browse petitions
            </button>
        </div>
    );
}
