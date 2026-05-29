import { useState } from "react";
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
    const probe = probeWebauthn();
    const [stage, setStage] = useState<Stage>("intro");
    const [errMsg, setErrMsg] = useState<string>("");

    const run = async () => {
        setStage("running");
        setErrMsg("");
        try {
            const userId = crypto.getRandomValues(new Uint8Array(16));
            const result = await registerPasskey(
                "CRISP-QES",
                userId,
                `crisp-${Date.now()}`,
                "CRISP-QES account",
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
        <Modal title="Register" onClose={onClose} dismissable={stage !== "running"}>
            {!probe.available ? (
                <div className="stack">
                    <p>{probe.reason ?? "WebAuthn unavailable."}</p>
                    <button
                        type="button"
                        className="btn btn--ghost btn--block"
                        onClick={onClose}
                    >
                        Close
                    </button>
                </div>
            ) : stage === "intro" ? (
                <div className="stack--4">
                    <p>
                        Create a Passkey on this device. It locks your private
                        signing key locally — nothing leaves the browser, and
                        there's no password or seed phrase.
                    </p>
                    <p className="muted small">
                        You'll be prompted by your browser to choose where to
                        save it: device, password manager, or hardware key.
                    </p>
                    <button
                        type="button"
                        className="btn btn--primary btn--block"
                        onClick={() => void run()}
                    >
                        Create Passkey
                    </button>
                </div>
            ) : stage === "running" ? (
                <div className="stack--4">
                    <p>Waiting for the Passkey prompt…</p>
                    <p className="muted small">
                        Follow the browser dialog to complete registration.
                    </p>
                </div>
            ) : stage === "error" ? (
                <div className="stack--4">
                    <div className="notice notice--bad">
                        <div>
                            <strong>Registration failed.</strong>
                            <br />
                            <span className="small mono">{errMsg}</span>
                        </div>
                    </div>
                    <p className="muted small">
                        If your authenticator doesn't support PRF, try a
                        different one (a hardware key or a different
                        password-manager extension).
                    </p>
                    <button
                        type="button"
                        className="btn btn--primary btn--block"
                        onClick={() => void run()}
                    >
                        Try again
                    </button>
                    <button
                        type="button"
                        className="btn btn--ghost btn--block"
                        onClick={onClose}
                    >
                        Cancel
                    </button>
                </div>
            ) : (
                <div className="stack--4">
                    <div className="notice notice--ok">
                        <div>Passkey created. Account ready.</div>
                    </div>
                    <p className="muted small">
                        Next: verify with your Diia QES so you can sign and
                        create petitions.
                    </p>
                    <button
                        type="button"
                        className="btn btn--primary btn--block"
                        onClick={onClose}
                    >
                        Continue
                    </button>
                </div>
            )}
        </Modal>
    );
}
