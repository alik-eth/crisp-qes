// Recovery flow.
//
// The user presents a BIP-39 mnemonic; we re-derive the entropy that
// shipped at enrollment, treat it as `N` for the demo (see
// `bip39Recovery.ts`), recompute the commitment, ask the OPRF service
// for the up-to-date Merkle path, and bind everything to a fresh
// Passkey on this device.

import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
    entropyFromMnemonic,
    isValidMnemonic,
} from "../lib/bip39Recovery";
import { pedersenCommit, pedersenSecret } from "../lib/pedersen";
import { oprfRecoverPath } from "../lib/oprfClient";
import {
    registerPasskey,
} from "../lib/webauthnPrf";
import {
    putEnrollment,
    wrapPayload,
    type EnrollmentPayload,
} from "../lib/encryptedStore";

interface Props {
    onBack: () => void;
}

function hexEncode(b: Uint8Array): `0x${string}` {
    let s = "0x";
    for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
    return s as `0x${string}`;
}

export function Recover({ onBack }: Props) {
    const { t } = useTranslation();

    const [mnemonic, setMnemonic] = useState("");
    const [phase, setPhase] = useState<
        "idle" | "restoring" | "ok" | "passkey"
    >("idle");
    const [err, setErr] = useState<string | null>(null);
    const [recovered, setRecovered] = useState<{
        N: Uint8Array;
        commitment: `0x${string}`;
        secret: `0x${string}`;
        merklePath: `0x${string}`[];
        merklePathIndices: (0 | 1)[];
        leafIndex: number;
    } | null>(null);

    async function handleRestore() {
        setErr(null);
        const m = mnemonic.trim();
        if (!isValidMnemonic(m)) {
            setErr(t("recover.invalidMnemonic"));
            return;
        }
        setPhase("restoring");
        try {
            // For the demo we use the recovered 32-byte entropy directly as
            // `N`. Production would re-run the OPRF protocol from scratch
            // against the same RNOKPP and assert that the returned `N`
            // matches the cached one.
            const N = entropyFromMnemonic(m);
            const commitment = await pedersenCommit(N);
            const secret = await pedersenSecret(N);
            const path = await oprfRecoverPath(commitment);
            setRecovered({
                N,
                commitment,
                secret,
                merklePath: path.merklePath,
                merklePathIndices: path.merklePathIndices,
                leafIndex: path.leafIndex,
            });
            setPhase("ok");
        } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
            setPhase("idle");
        }
    }

    async function handleNewPasskey() {
        if (!recovered) return;
        setPhase("passkey");
        setErr(null);
        try {
            const userId = crypto.getRandomValues(new Uint8Array(16));
            const name = `crisp-qes-v2-recovered-${Date.now()}`;
            const pk = await registerPasskey(
                "CRISP-QES v2",
                userId,
                name,
                name,
            );
            const payload: EnrollmentPayload = {
                enrollmentSecret: recovered.secret,
                oprfOutputN: hexEncode(recovered.N),
                merklePath: recovered.merklePath,
                merklePathIndices: recovered.merklePathIndices,
            };
            const ciphertext = await wrapPayload(payload, pk.prfOutput);
            await putEnrollment({
                version: 1,
                commitment: recovered.commitment,
                leafIndex: recovered.leafIndex,
                credentialId: hexEncode(pk.credentialId),
                ciphertext,
            });
            setPhase("ok"); // back to ok with the credential in place
            onBack();
        } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
            setPhase("ok");
        }
    }

    return (
        <section className="section">
            <button className="btn--link" onClick={onBack} type="button">
                ← {t("recover.back")}
            </button>
            <h2 className="section__title" style={{ marginTop: 8 }}>
                {t("recover.heading")}
            </h2>
            <p className="note" style={{ marginBottom: 24 }}>
                {t("recover.intro")}
            </p>

            <div className="panel">
                <label className="field-block">
                    <span className="field-block__label">
                        {t("recover.mnemonic")}
                    </span>
                    <textarea
                        className="textarea"
                        rows={4}
                        spellCheck={false}
                        value={mnemonic}
                        onChange={(e) => setMnemonic(e.target.value)}
                    />
                </label>
                <div className="actions">
                    <button
                        className="btn btn--accent"
                        type="button"
                        disabled={
                            phase === "restoring" ||
                            phase === "passkey" ||
                            mnemonic.trim().length === 0
                        }
                        onClick={handleRestore}
                    >
                        {phase === "restoring"
                            ? t("recover.restoring")
                            : t("recover.restore")}
                    </button>
                </div>
                {err ? (
                    <p className="error-line">
                        {t("recover.error", { detail: err })}
                    </p>
                ) : null}
            </div>

            {recovered ? (
                <div className="panel">
                    <p className="panel__title">{t("recover.ok")}</p>
                    <dl>
                        <div className="field-row">
                            <dt>commitment</dt>
                            <dd className="mono">{recovered.commitment}</dd>
                        </div>
                        <div className="field-row">
                            <dt>leafIndex</dt>
                            <dd className="mono">{recovered.leafIndex}</dd>
                        </div>
                    </dl>
                    <div className="actions">
                        <button
                            className="btn btn--accent"
                            type="button"
                            onClick={handleNewPasskey}
                            disabled={phase === "passkey"}
                        >
                            {t("recover.newPasskey")}
                        </button>
                    </div>
                </div>
            ) : null}
        </section>
    );
}
