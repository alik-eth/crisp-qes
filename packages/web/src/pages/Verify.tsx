import { useState, useCallback } from "react";
import { useLocation } from "wouter";
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

// Substages of the v2.1 verify flow, in order:
//
//   identify     — Citizen types their RNOKPP. We blind it locally; the
//                  cert in their .p7s will be cross-checked against it.
//   challenge    — We've generated and downloaded the JSON binding file
//                  the citizen must sign in Diia. Drop zone awaits the
//                  resulting .p7s.
//   verifying    — POST blindedInput + .p7s → OPRF → unblind → enroll.
//   verified     — On-chain enrollment confirmed; awaiting Passkey wrap.
//   saving       — Passkey PRF gesture in flight, writing the encrypted vault.
//   saved        — Done; redirect to /petitions.
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
    // `null` in the recovery path: this Diia identity was already enrolled
    // on-chain, so no fresh leaf was appended and there's no enrollment tx.
    txHash: `0x${string}` | null;
    // true => we rebuilt the local vault from the existing on-chain leaf
    // (device-loss recovery), false => fresh first-time enrollment.
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

            // Try a fresh enrollment first. If this Diia identity is already
            // on-chain (same RNOKPP + epoch → same deterministic commitment),
            // the OPRF returns 409 AlreadyEnrolled — that's the device-loss
            // recovery case: fetch the existing leaf's Merkle path and rebuild
            // the local vault, no new leaf, no chain write. The blind-eval
            // gates (fresh .p7s, age, rate-limit, dedup) already ran above, so
            // recovery is no easier to abuse than a first enrollment.
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
                <h1>Verify with Diia QES</h1>
                <p className="muted" style={{ marginTop: 8, maxWidth: 560 }}>
                    Prove you're a verified Ukrainian adult, anonymously.
                    Your identity never reaches the chain.
                </p>
            </header>

            <StageStrip stage={stage} />

            {ageBlocked ? (
                <div className="notice notice--bad" style={{ marginTop: 24 }}>
                    <div>
                        <strong>Adults only.</strong> The Diia signature you
                        uploaded is below the {ageBlocked.min}-year age
                        threshold (resolved to {ageBlocked.found}).
                    </div>
                </div>
            ) : null}

            {err ? (
                <div className="notice notice--bad" style={{ marginTop: 24 }}>
                    <div>
                        <strong>Verification failed.</strong>
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
    const steps: { key: string; label: string; match: Substage[] }[] = [
        { key: "identify", label: "Identify", match: ["identify"] },
        {
            key: "challenge",
            label: "Sign challenge",
            match: ["challenge"],
        },
        {
            key: "verify",
            label: "Verify anonymously",
            match: ["verifying"],
        },
        {
            key: "save",
            label: "Save to device",
            match: ["verified", "saving"],
        },
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
                        <span className="strip__n">{i + 1}</span>
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
    return (
        <div className="card">
            <h3>Enter your RNOKPP</h3>
            <p
                className="muted small"
                style={{ marginTop: 8, marginBottom: 16 }}
            >
                We use this to compute your anonymous identity locally and to
                cross-check the certificate in your .p7s. Find it in the
                Diia app under Documents → РНОКПП. 10 digits, all numeric.
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
                Your RNOKPP never reaches the chain. It's hashed and blinded
                locally; only the blinded value is sent to the OPRF service.
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
    return (
        <div className="card">
            <h3>Sign the challenge in Diia</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                A file <span className="mono">crisp-qes-challenge.txt</span>{" "}
                was downloaded to this device. It contains the exact bytes
                you must sign with your Diia QES — this binds your signature
                to THIS enrollment.
            </p>
            <ol
                className="muted small"
                style={{ marginTop: 12, paddingLeft: 18, marginBottom: 16 }}
            >
                <li>Open the Diia app.</li>
                <li>Go to "Sign documents" (Підписати документ).</li>
                <li>Select the downloaded <span className="mono">crisp-qes-challenge.txt</span>.</li>
                <li>Enter your Diia PIN to sign.</li>
                <li>Save the resulting <span className="mono">.p7s</span> file and upload it here.</li>
            </ol>
            <p className="muted small" style={{ marginBottom: 16 }}>
                RNOKPP being verified:{" "}
                <span className="mono">{blindState.rnokpp}</span>
            </p>
            <label
                className="dropzone"
                onDragOver={(e) => {
                    e.preventDefault();
                }}
                onDrop={(e) => {
                    e.preventDefault();
                    const f = e.dataTransfer?.files[0];
                    if (f) void onFile(f);
                }}
            >
                <input
                    type="file"
                    // No `accept` filter on purpose: mobile pickers (iOS
                    // Files, Android) grey out files whose extension/UTI they
                    // don't recognise, and `.p7s` has no standard mobile UTI —
                    // so a filter makes the signed file unselectable. We
                    // validate contents in onFile (parseP7s + RNOKPP cross-
                    // check) regardless, so an unfiltered picker is safe.
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
                        Diia QES recognised and RNOKPP matches.
                    </div>
                </div>
            ) : null}
            <div className="row" style={{ marginTop: 20 }}>
                <button
                    type="button"
                    className="btn btn--primary"
                    onClick={onVerify}
                    disabled={!parsed}
                >
                    Verify
                </button>
                <button
                    type="button"
                    className="btn btn--ghost"
                    onClick={onRegenerate}
                >
                    Re-download challenge
                </button>
                <button
                    type="button"
                    className="btn btn--link"
                    onClick={onReset}
                >
                    Start over
                </button>
            </div>
        </div>
    );
}

function VerifyingPanel() {
    return (
        <div className="card">
            <h3>Verifying anonymously…</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                Contacting OPRF · verifying DLEQ · unblinding · submitting to
                chain.
            </p>
            <p
                className="muted small"
                style={{ marginTop: 16, fontFamily: "var(--mono)" }}
            >
                This can take 10–20 seconds. Don't close this tab.
            </p>
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
    return (
        <div className="card">
            <h3>{oprfResult.recovered ? "Welcome back." : "Verified on chain."}</h3>
            {oprfResult.recovered ? (
                <p className="muted small" style={{ marginTop: 8 }}>
                    This Diia identity is already enrolled this epoch — no new
                    commitment was created. We re-derived your existing
                    anonymous identity from your Diia signature.
                </p>
            ) : (
                <p className="muted small" style={{ marginTop: 8 }}>
                    Your anonymous commitment is now on Sepolia.{" "}
                    {oprfResult.txHash ? (
                        <a
                            href={explorerTxUrl(oprfResult.txHash)}
                            target="_blank"
                            rel="noreferrer"
                        >
                            View transaction →
                        </a>
                    ) : null}
                </p>
            )}
            <p style={{ marginTop: 20, marginBottom: 16 }}>
                Last step: encrypt your private signing material with your
                Passkey and save it to this device.
            </p>
            <button
                type="button"
                className="btn btn--primary"
                onClick={onSave}
            >
                {oprfResult.recovered ? "Restore on this device" : "Encrypt and save"}
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
                <div>You're verified. You can sign and create petitions now.</div>
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
