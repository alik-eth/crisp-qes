// 5-step enrollment flow.
//
// 1. Upload .p7s, extract RNOKPP (subjectSerial after `TINUA-`).
// 2. Create a Passkey + read PRF output.
// 3. Blind RNOKPP, call OPRF /blind-eval, verify DLEQ, unblind to obtain `N`.
//    Pedersen-commit `N` to obtain `commitment`. Pedersen-derive `s`.
// 4. Call OPRF /register with the commitment to get Merkle path + attesterSig.
//    Submit `EnrollmentRegistry.updateRoot(newRoot, attesterSig)` via wallet.
// 5. Store the encrypted payload in IndexedDB, show the BIP-39 mnemonic.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { parseP7s, type ParsedP7s } from "@crisp-qes/sdk";
import { DropZone } from "../components/DropZone";
import { rnokppBytes, tinuaPrefixOk } from "../lib/rnokpp";
import {
    probeWebauthn,
    registerPasskey,
} from "../lib/webauthnPrf";
import { blind, unblind, verifyBlindEval } from "../lib/voprf";
import {
    pedersenCommit,
    pedersenSecret,
} from "../lib/pedersen";
import { oprfBlindEval, oprfRegister } from "../lib/oprfClient";
import {
    putEnrollment,
    wrapPayload,
    type EnrollmentPayload,
} from "../lib/encryptedStore";
import { mnemonicFromN } from "../lib/bip39Recovery";

interface Props {
    onBack: () => void;
    onDone: () => void;
}

type Stage =
    | "upload"
    | "passkey"
    | "oprf"
    | "register"
    | "backup"
    | "done";

function hexEncode(b: Uint8Array): `0x${string}` {
    let s = "0x";
    for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
    return s as `0x${string}`;
}

function hexDecode(h: `0x${string}`): Uint8Array {
    const s = h.slice(2);
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
    }
    return out;
}

export function Enroll({ onBack, onDone }: Props) {
    const { t } = useTranslation();
    const probe = useMemo(() => probeWebauthn(), []);

    const [p7sBytes, setP7sBytes] = useState<Uint8Array | null>(null);
    const [parsed, setParsed] = useState<ParsedP7s | null>(null);
    const [parseErr, setParseErr] = useState<string | null>(null);

    const [passkey, setPasskey] = useState<{
        credentialId: Uint8Array;
        prfOutput: Uint8Array;
    } | null>(null);
    const [passkeyBusy, setPasskeyBusy] = useState(false);
    const [passkeyErr, setPasskeyErr] = useState<string | null>(null);

    const [oprfResult, setOprfResult] = useState<{
        N: Uint8Array;
        commitment: `0x${string}`;
        secret: `0x${string}`;
    } | null>(null);
    const [oprfBusy, setOprfBusy] = useState(false);
    const [oprfErr, setOprfErr] = useState<string | null>(null);

    const [registerResult, setRegisterResult] = useState<{
        merklePath: `0x${string}`[];
        merklePathIndices: (0 | 1)[];
        leafIndex: number;
        newRoot: `0x${string}`;
        attesterSig: `0x${string}`;
    } | null>(null);
    const [registerBusy, setRegisterBusy] = useState(false);
    const [registerErr, setRegisterErr] = useState<string | null>(null);

    const [mnemonic, setMnemonic] = useState<string | null>(null);
    const [mnemonicRevealed, setMnemonicRevealed] = useState(false);

    const [stage, setStage] = useState<Stage>("upload");

    // Auto-advance the visible "current step" based on which artifacts exist.
    useEffect(() => {
        if (mnemonic) setStage("backup");
        else if (registerResult) setStage("backup");
        else if (oprfResult) setStage("register");
        else if (passkey) setStage("oprf");
        else if (parsed) setStage("passkey");
        else setStage("upload");
    }, [parsed, passkey, oprfResult, registerResult, mnemonic]);

    async function onFile(file: File) {
        setParseErr(null);
        try {
            const bytes = new Uint8Array(await file.arrayBuffer());
            const p = parseP7s(bytes);
            if (!tinuaPrefixOk(p)) {
                setParseErr(t("enroll.upload.wrongPrefix"));
                return;
            }
            setP7sBytes(bytes);
            setParsed(p);
        } catch (e) {
            setParseErr(
                t("enroll.upload.parseError", {
                    detail: e instanceof Error ? e.message : String(e),
                }),
            );
        }
    }

    async function createPasskey() {
        if (!parsed) return;
        setPasskeyBusy(true);
        setPasskeyErr(null);
        try {
            const userId = crypto.getRandomValues(new Uint8Array(16));
            const userName = `crisp-qes-v2-${Date.now()}`;
            const result = await registerPasskey(
                "CRISP-QES v2",
                userId,
                userName,
                userName,
            );
            setPasskey(result);
        } catch (e) {
            setPasskeyErr(e instanceof Error ? e.message : String(e));
        } finally {
            setPasskeyBusy(false);
        }
    }

    async function runOprf() {
        if (!parsed || !p7sBytes || !passkey) return;
        setOprfBusy(true);
        setOprfErr(null);
        try {
            const rn = rnokppBytes(parsed);
            const { blind: r, blindedElement } = blind(rn);
            const resp = await oprfBlindEval(blindedElement, p7sBytes);
            const ok = verifyBlindEval(blindedElement, {
                serverPubkey: hexDecode(resp.K),
                evaluatedElement: hexDecode(resp.Y),
                proofC: hexDecode(resp.proof.c),
                proofS: hexDecode(resp.proof.s),
            });
            if (!ok) {
                setOprfErr(t("enroll.oprf.dleqInvalid"));
                return;
            }
            const N = unblind(hexDecode(resp.Y), r);
            const commitment = await pedersenCommit(N);
            const secret = await pedersenSecret(N);
            setOprfResult({ N, commitment, secret });
        } catch (e) {
            setOprfErr(e instanceof Error ? e.message : String(e));
        } finally {
            setOprfBusy(false);
        }
    }

    async function runRegister() {
        if (!oprfResult || !passkey) return;
        setRegisterBusy(true);
        setRegisterErr(null);
        try {
            const r = await oprfRegister(
                oprfResult.commitment,
                // For the demo we don't strictly need the blinded element
                // again — it's a reconciliation field. The OPRF server is
                // free to ignore it.
                new Uint8Array(32),
            );

            // TODO(blocked by #31): once the EnrollmentRegistry address is
            // live, submit `updateRoot(newRoot, attesterSig)` via the
            // wallet connector here. For now we record the OPRF response
            // and rely on the relayer (task #34) to land the root update.

            setRegisterResult({
                merklePath: r.merklePath,
                merklePathIndices: r.merklePathIndices,
                leafIndex: r.leafIndex,
                newRoot: r.newRoot,
                attesterSig: r.attesterSig,
            });

            // Persist the enrollment encrypted under the PRF key.
            const payload: EnrollmentPayload = {
                enrollmentSecret: oprfResult.secret,
                oprfOutputN: hexEncode(oprfResult.N),
                merklePath: r.merklePath,
                merklePathIndices: r.merklePathIndices,
            };
            const ciphertext = await wrapPayload(payload, passkey.prfOutput);
            await putEnrollment({
                version: 1,
                commitment: oprfResult.commitment,
                leafIndex: r.leafIndex,
                credentialId: hexEncode(passkey.credentialId),
                ciphertext,
            });

            setMnemonic(mnemonicFromN(oprfResult.N));
        } catch (e) {
            setRegisterErr(e instanceof Error ? e.message : String(e));
        } finally {
            setRegisterBusy(false);
        }
    }

    return (
        <section className="section">
            <button className="btn--link" onClick={onBack} type="button">
                ← {t("enroll.back")}
            </button>
            <h2 className="section__title" style={{ marginTop: 8 }}>
                {t("enroll.heading")}
            </h2>
            <p className="note" style={{ marginBottom: 24 }}>
                {t("enroll.intro")}
            </p>

            <ol className="steps">
                {(["upload", "passkey", "oprf", "register", "backup"] as const).map(
                    (k) => {
                        const isActive = stage === k;
                        return (
                            <li
                                key={k}
                                className={
                                    "steps__item " +
                                    (isActive ? "steps__item--active" : "")
                                }
                            >
                                {t(`enroll.steps.${k}`)}
                            </li>
                        );
                    },
                )}
            </ol>

            {/* 1. Upload */}
            <div className="panel">
                <p className="panel__title">{t("enroll.upload.title")}</p>
                <p className="note">{t("enroll.upload.intro")}</p>
                <DropZone onFile={onFile} />
                {parseErr ? <p className="error-line">{parseErr}</p> : null}
                {parsed ? (
                    <p className="tag-ok">✓ {t("enroll.upload.parsed")}</p>
                ) : null}
            </div>

            {/* 2. Passkey */}
            {parsed ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.passkey.title")}</p>
                    <p className="note">{t("enroll.passkey.intro")}</p>
                    {!probe.available ? (
                        <p className="error-line">
                            {t("enroll.passkey.unsupported")}
                            {probe.reason ? ` — ${probe.reason}` : ""}
                        </p>
                    ) : passkey ? (
                        <p className="tag-ok">✓ {t("enroll.passkey.created")}</p>
                    ) : (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={createPasskey}
                                disabled={passkeyBusy}
                            >
                                {passkeyBusy
                                    ? t("enroll.passkey.creating")
                                    : t("enroll.passkey.create")}
                            </button>
                        </div>
                    )}
                    {passkeyErr ? (
                        <p className="error-line">
                            {t("enroll.passkey.error", { detail: passkeyErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 3. OPRF */}
            {parsed && passkey ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.oprf.title")}</p>
                    <p className="note">{t("enroll.oprf.intro")}</p>
                    {oprfResult ? (
                        <dl>
                            <div className="field-row">
                                <dt>{t("enroll.oprf.commit")}</dt>
                                <dd className="mono">{oprfResult.commitment}</dd>
                            </div>
                            <div className="field-row">
                                <dt>{t("enroll.oprf.secret")}</dt>
                                <dd className="mono">{oprfResult.secret}</dd>
                            </div>
                        </dl>
                    ) : oprfBusy ? (
                        <p className="progress">
                            {t("enroll.oprf.running")}
                            <span className="progress__line">
                                <span />
                            </span>
                        </p>
                    ) : (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={runOprf}
                            >
                                {t("enroll.oprf.running")}
                            </button>
                        </div>
                    )}
                    {oprfErr ? (
                        <p className="error-line">
                            {t("enroll.oprf.error", { detail: oprfErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 4. Register */}
            {oprfResult && passkey ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.register.title")}</p>
                    <p className="note">{t("enroll.register.intro")}</p>
                    {registerResult ? (
                        <dl>
                            <div className="field-row">
                                <dt>{t("enroll.register.newRoot")}</dt>
                                <dd className="mono">{registerResult.newRoot}</dd>
                            </div>
                            <div className="field-row">
                                <dt>{t("enroll.register.leafIndex")}</dt>
                                <dd className="mono">{registerResult.leafIndex}</dd>
                            </div>
                        </dl>
                    ) : registerBusy ? (
                        <p className="progress">
                            {t("enroll.register.running")}
                            <span className="progress__line">
                                <span />
                            </span>
                        </p>
                    ) : (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={runRegister}
                            >
                                {t("enroll.register.submit")}
                            </button>
                        </div>
                    )}
                    {registerErr ? (
                        <p className="error-line">
                            {t("enroll.register.error", { detail: registerErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 5. Backup */}
            {mnemonic ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.backup.title")}</p>
                    <p className="note">{t("enroll.backup.intro")}</p>
                    <p className="note text-warn">{t("enroll.backup.warning")}</p>
                    {mnemonicRevealed ? (
                        <p className="mono" style={{ fontSize: 15, lineHeight: 1.7 }}>
                            {mnemonic}
                        </p>
                    ) : null}
                    <div className="actions">
                        <button
                            className="btn btn--ghost"
                            type="button"
                            onClick={() => setMnemonicRevealed((v) => !v)}
                        >
                            {mnemonicRevealed
                                ? t("enroll.backup.hide")
                                : t("enroll.backup.show")}
                        </button>
                        <button
                            className="btn btn--accent"
                            type="button"
                            onClick={onDone}
                            disabled={!mnemonicRevealed}
                            title={
                                mnemonicRevealed
                                    ? undefined
                                    : t("enroll.backup.show")
                            }
                        >
                            {t("enroll.backup.saved")}
                        </button>
                    </div>
                </div>
            ) : null}
        </section>
    );
}
