import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Modal } from "./Modal.js";
import {
    registerPasskey,
    probeWebauthn,
} from "../lib/webauthnPrf.js";
import { putAccount } from "../lib/account.js";
import { setSessionPrf } from "../lib/passkeySession.js";

interface Props {
    onClose: () => void;
    onRegistered: () => Promise<void>;
}

type Stage = "intro" | "running" | "error" | "done";

function bytesToHex(b: Uint8Array): `0x${string}` {
    let s = "0x";
    for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
    return s as `0x${string}`;
}

export function RegisterModal({ onClose, onRegistered }: Props) {
    const { t } = useTranslation();
    const probe = probeWebauthn();
    const [stage, setStage] = useState<Stage>("intro");
    const [errMsg, setErrMsg] = useState<string>("");

    const run = async () => {
        setStage("running");
        setErrMsg("");
        try {
            const userId = crypto.getRandomValues(new Uint8Array(16));
            const result = await registerPasskey(
                "Civic Voice",
                userId,
                `civic-${Date.now()}`,
                "Civic Voice account",
            );
            await putAccount({
                credentialId: bytesToHex(result.credentialId),
                supportsPRF: true,
                createdAt: Date.now(),
            });
            setSessionPrf(result.prfOutput);
            setStage("done");
            await onRegistered();
        } catch (e) {
            const msg = e instanceof Error ? e.message : "unknown error";
            setErrMsg(msg);
            setStage("error");
        }
    };

    return (
        <Modal title={t("register.title")} onClose={onClose} dismissable={stage !== "running"}>
            {!probe.available ? (
                <div className="stack">
                    <p>{probe.reason ?? t("register.unavailable")}</p>
                    <button
                        type="button"
                        className="btn btn--ghost btn--block"
                        onClick={onClose}
                    >
                        {t("register.close")}
                    </button>
                </div>
            ) : stage === "intro" ? (
                <div className="stack--4">
                    <p>{t("register.intro")}</p>
                    <p className="muted small">{t("register.hint")}</p>
                    <button
                        type="button"
                        className="btn btn--primary btn--block"
                        onClick={() => void run()}
                    >
                        {t("register.createBtn")}
                    </button>
                </div>
            ) : stage === "running" ? (
                <div className="stack--4">
                    <p>{t("register.waiting")}</p>
                    <p className="muted small">{t("register.waitingHint")}</p>
                </div>
            ) : stage === "error" ? (
                <div className="stack--4">
                    <div className="notice notice--bad">
                        <div>
                            <strong>{t("register.failed")}</strong>
                            <br />
                            <span className="small mono">{errMsg}</span>
                        </div>
                    </div>
                    <p className="muted small">{t("register.failedHint")}</p>
                    <button
                        type="button"
                        className="btn btn--primary btn--block"
                        onClick={() => void run()}
                    >
                        {t("register.tryAgain")}
                    </button>
                    <button
                        type="button"
                        className="btn btn--ghost btn--block"
                        onClick={onClose}
                    >
                        {t("common.cancel")}
                    </button>
                </div>
            ) : (
                <div className="stack--4">
                    <div className="notice notice--ok">
                        <div>{t("register.created")}</div>
                    </div>
                    <p className="muted small">{t("register.createdHint")}</p>
                    <button
                        type="button"
                        className="btn btn--primary btn--block"
                        onClick={onClose}
                    >
                        {t("common.continue")}
                    </button>
                </div>
            )}
        </Modal>
    );
}
