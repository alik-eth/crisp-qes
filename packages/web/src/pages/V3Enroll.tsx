import { useState, useCallback } from "react";
import { useLocation, Link } from "wouter";
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

type Substage = "upload" | "running" | "enrolled" | "saving" | "saved";

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

export function V3Enroll({ onDone }: Props) {
    const [, navigate] = useLocation();
    const [stage, setStage] = useState<Substage>("upload");
    const [parsed, setParsed] = useState<ParsedP7s | null>(null);
    const [p7sBytes, setP7sBytes] = useState<Uint8Array | null>(null);
    const [rnokpp, setRnokpp] = useState<string | null>(null);
    const [stages, setStages] = useState<Record<string, RealRunStage>>({});
    const [result, setResult] = useState<RealEnrollResult | null>(null);
    const [error, setError] = useState<string | null>(null);

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
            setP7sBytes(bytes);
            setParsed(p);
            setRnokpp(certRnokpp);
        } catch (e) {
            setError(
                "Couldn't read the .p7s file: " +
                    (e instanceof Error ? e.message : String(e)),
            );
        }
    }, []);

    const onRun = useCallback(async () => {
        if (!p7sBytes || !parsed) return;
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
            );
            setResult(res);
            setStage("enrolled");
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            setStage("upload");
        }
    }, [p7sBytes, parsed]);

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
                <strong>EXPERIMENTAL / UNAUDITED.</strong> Operator-blind
                enrollment (v3). The OPRF service never sees your RNOKPP — only
                a blinded element, gated by a zero-knowledge proof of your Diia
                certificate. Both UltraHonk proofs run in this browser. This
                path is not yet audited; the{" "}
                <Link href="/verify-legacy">classic verifier</Link> remains
                available as a fallback.
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
                {stage === "upload" ? (
                    <UploadPanel
                        parsed={parsed}
                        rnokpp={rnokpp}
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

function UploadPanel({
    parsed,
    rnokpp,
    onFile,
    onRun,
}: {
    parsed: ParsedP7s | null;
    rnokpp: string | null;
    onFile: (file: File) => Promise<void>;
    onRun: () => void;
}) {
    return (
        <div className="card">
            <h3>Upload your Diia signature</h3>
            <p className="muted small" style={{ marginTop: 8, marginBottom: 16 }}>
                Sign any document with your Diia QES and upload the resulting
                <span className="mono"> .p7s</span> here. We read your RNOKPP
                and date of birth from the certificate inside it, then prove —
                in zero knowledge — that they're valid, without sending them to
                the service.
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
                    A Diia-signed .p7s (CAdES-BES)
                </span>
            </label>
            {parsed ? (
                <div className="notice notice--ok" style={{ marginTop: 16 }}>
                    <div>
                        Diia QES recognised. RNOKPP{" "}
                        <span className="mono">{rnokpp}</span>.
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
            <h3>Verified on chain.</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                Your anonymous commitment is now on Sepolia.{" "}
                <a
                    href={explorerTxUrl(result.txHash)}
                    target="_blank"
                    rel="noreferrer"
                >
                    View transaction →
                </a>
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
