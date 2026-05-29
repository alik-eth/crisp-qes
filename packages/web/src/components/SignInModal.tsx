import { useState } from "react";
import { Modal } from "./Modal.js";
import { evaluatePrfWithCredential } from "../lib/webauthnPrf.js";
import { setSessionPrf } from "../lib/passkeySession.js";

interface Props {
    onClose: () => void;
    onUnlocked: () => void;
    credentialId: `0x${string}`;
    onRecover: () => void;
}

type Stage = "intro" | "running" | "error";

function hexToBytes(h: string): Uint8Array {
    const s = h.startsWith("0x") ? h.slice(2) : h;
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
    }
    return out;
}

export function SignInModal({
    onClose,
    onUnlocked,
    credentialId,
    onRecover,
}: Props) {
    const [stage, setStage] = useState<Stage>("intro");
    const [errMsg, setErrMsg] = useState("");

    const run = async () => {
        setStage("running");
        setErrMsg("");
        try {
            const prf = await evaluatePrfWithCredential(hexToBytes(credentialId));
            setSessionPrf(prf);
            onUnlocked();
        } catch (e) {
            setErrMsg(e instanceof Error ? e.message : "unknown error");
            setStage("error");
        }
    };

    return (
        <Modal title="Sign in" onClose={onClose} dismissable={stage !== "running"}>
            {stage === "intro" ? (
                <div className="stack--4">
                    <p>
                        Use your Passkey to unlock this account on this device.
                    </p>
                    <button
                        type="button"
                        className="btn btn--primary btn--block"
                        onClick={() => void run()}
                    >
                        Use Passkey
                    </button>
                    <button
                        type="button"
                        className="btn btn--link"
                        onClick={onRecover}
                    >
                        Lost this device?
                    </button>
                </div>
            ) : stage === "running" ? (
                <div className="stack--4">
                    <p>Waiting for the Passkey prompt…</p>
                </div>
            ) : (
                <div className="stack--4">
                    <div className="notice notice--bad">
                        <div>
                            <strong>Couldn't unlock.</strong>
                            <br />
                            <span className="small mono">{errMsg}</span>
                        </div>
                    </div>
                    <button
                        type="button"
                        className="btn btn--primary btn--block"
                        onClick={() => void run()}
                    >
                        Try again
                    </button>
                    <button
                        type="button"
                        className="btn btn--link"
                        onClick={onRecover}
                    >
                        Lost this device?
                    </button>
                </div>
            )}
        </Modal>
    );
}
