import { useEffect, useState, useCallback } from "react";
import { Link, useLocation } from "wouter";
import { useTranslation } from "react-i18next";
import type { AccountState } from "../lib/account.js";
import { clearAccount, shortId } from "../lib/account.js";
import { listEnrollments, clearAll as clearEnrollments } from "../lib/encryptedStore.js";
import {
    clearSessionPrf,
    clearSessionVault,
    getSessionVault,
} from "../lib/passkeySession.js";
import { unlockVault } from "../lib/unlock.js";
import {
    readAllPetitions,
    readHasNullifier,
    type PetitionView,
} from "../lib/registry.js";
import { pedersenNullifier } from "../lib/pedersen.js";

interface Props {
    state: AccountState;
    refresh: () => Promise<void>;
}

interface DeviceFacts {
    credentialId: `0x${string}`;
    commitment: `0x${string}` | null;
    leafIndex: number | null;
    enrolledAt: number | null;
}

export function Me({ state, refresh }: Props) {
    const { t } = useTranslation();
    const [, navigate] = useLocation();
    const [facts, setFacts] = useState<DeviceFacts | null>(null);
    const [signingOut, setSigningOut] = useState(false);
    const [confirmOut, setConfirmOut] = useState(false);

    useEffect(() => {
        let alive = true;
        void (async () => {
            if (!state.credentialId) return;
            const enrollments = await listEnrollments();
            if (!alive) return;
            const latest = enrollments[enrollments.length - 1];
            setFacts({
                credentialId: state.credentialId,
                commitment: latest?.commitment ?? null,
                leafIndex: latest?.leafIndex ?? null,
                enrolledAt: null,
            });
        })();
        return () => {
            alive = false;
        };
    }, [state.credentialId]);

    const [sigStage, setSigStage] = useState<
        "idle" | "unlocking" | "scanning" | "loaded" | "error"
    >("idle");
    const [signed, setSigned] = useState<PetitionView[]>([]);
    const [sigErr, setSigErr] = useState<string | null>(null);

    const scanSignatures = useCallback(async () => {
        if (state.kind !== "verified") return;
        setSigErr(null);
        try {
            setSigStage("unlocking");
            const v = getSessionVault() ?? (await unlockVault());
            setSigStage("scanning");
            const petitions = await readAllPetitions();
            const flags = await Promise.all(
                petitions.map(async (p) => {
                    const n = await pedersenNullifier(
                        v.enrollmentSecret,
                        p.id,
                    );
                    return readHasNullifier(p.id, n).catch(() => false);
                }),
            );
            const mine = petitions.filter((_, i) => flags[i]);
            setSigned(mine);
            setSigStage("loaded");
        } catch (e) {
            setSigErr(e instanceof Error ? e.message : String(e));
            setSigStage("error");
        }
    }, [state.kind]);

    const lock = () => {
        clearSessionPrf();
        clearSessionVault();
        navigate("/petitions");
    };

    const forgetDevice = async () => {
        setSigningOut(true);
        try {
            clearSessionPrf();
            clearSessionVault();
            await clearEnrollments();
            await clearAccount();
            await refresh();
            navigate("/");
        } finally {
            setSigningOut(false);
        }
    };

    return (
        <section className="me">
            <h1>{t("me.heading")}</h1>
            <p className="muted" style={{ marginTop: 8, marginBottom: 24 }}>
                {t("me.subtitle")}
            </p>

            {state.kind === "account" ? (
                <div className="notice notice--info" style={{ marginBottom: 20 }}>
                    <div>
                        {t("me.notVerifiedBefore")}{" "}
                        <Link href="/verify">{t("me.verifyNow")}</Link>
                    </div>
                </div>
            ) : null}

            <dl className="detail__facts">
                <div className="fact">
                    <dt>{t("me.status")}</dt>
                    <dd>
                        <span
                            className={
                                state.kind === "verified"
                                    ? "badge badge--ok"
                                    : "badge"
                            }
                            style={{ marginRight: 8 }}
                        >
                            {state.kind === "verified"
                                ? t("me.verified")
                                : t("me.registered")}
                        </span>
                    </dd>
                </div>
                {state.commitment ? (
                    <div className="fact">
                        <dt>{t("me.anonIdentity")}</dt>
                        <dd className="mono">{shortId(state.commitment)}</dd>
                    </div>
                ) : null}
                {facts?.leafIndex !== null && facts?.leafIndex !== undefined ? (
                    <div className="fact">
                        <dt>{t("me.enrollmentLeaf")}</dt>
                        <dd className="mono">#{facts.leafIndex}</dd>
                    </div>
                ) : null}
                {facts?.credentialId ? (
                    <div className="fact">
                        <dt>{t("me.passkeyCredential")}</dt>
                        <dd className="mono">{shortId(facts.credentialId)}</dd>
                    </div>
                ) : null}
            </dl>

            {facts?.commitment ? (
                <div style={{ marginTop: 24 }}>
                    <div className="muted small" style={{ marginBottom: 4 }}>
                        {t("me.fullCommitment")}
                    </div>
                    <div
                        className="mono"
                        style={{
                            wordBreak: "break-all",
                            padding: "12px 14px",
                            background: "var(--bg-elevated)",
                            border: "1px solid var(--rule)",
                            borderRadius: "var(--r-md)",
                            fontSize: 13,
                        }}
                    >
                        {facts.commitment}
                    </div>
                </div>
            ) : null}

            {state.kind === "verified" ? (
                <>
                    <hr className="hairline" />
                    <h2>{t("me.signedHeading")}</h2>
                    <p className="muted small" style={{ marginTop: 8 }}>
                        {t("me.signedSubtitle")}
                    </p>

                    {sigStage === "idle" ? (
                        <button
                            type="button"
                            className="btn btn--primary"
                            style={{ marginTop: 16 }}
                            onClick={() => void scanSignatures()}
                        >
                            {getSessionVault()
                                ? t("me.showSigned")
                                : t("me.unlockAndShow")}
                        </button>
                    ) : sigStage === "unlocking" ? (
                        <div className="progress-band" style={{ marginTop: 16 }}>
                            <span className="spinner" aria-hidden="true" />
                            <span className="small">{t("me.waitingPasskey")}</span>
                        </div>
                    ) : sigStage === "scanning" ? (
                        <div className="progress-band" style={{ marginTop: 16 }}>
                            <span className="spinner" aria-hidden="true" />
                            <span className="small">{t("me.scanningChain")}</span>
                        </div>
                    ) : sigStage === "error" ? (
                        <div className="notice notice--bad" style={{ marginTop: 16 }}>
                            <div>
                                <strong>{t("me.sigError")}</strong>
                                <br />
                                <span className="small mono">{sigErr}</span>
                            </div>
                        </div>
                    ) : signed.length === 0 ? (
                        <p className="muted" style={{ marginTop: 16 }}>
                            {t("me.noSigned")}
                        </p>
                    ) : (
                        <ul className="petitions" style={{ marginTop: 16 }}>
                            {signed.map((p) => (
                                <li key={p.id.toString()}>
                                    <Link
                                        href={`/p/${p.id.toString()}`}
                                        className="petitions__row"
                                    >
                                        <div className="petitions__main">
                                            <div className="petitions__title">
                                                #{p.id.toString()} ·{" "}
                                                {p.fullText
                                                    .split(/\r?\n/)[0]
                                                    ?.slice(0, 100) ||
                                                    "(untitled)"}
                                            </div>
                                            <div className="petitions__meta">
                                                <span className="muted">{t("me.signed")}</span>
                                                <span className="muted">·</span>
                                                <span className="muted">{p.status}</span>
                                            </div>
                                        </div>
                                    </Link>
                                </li>
                            ))}
                        </ul>
                    )}
                </>
            ) : null}

            <hr className="hairline" />

            <h2>{t("me.recoveryHeading")}</h2>
            <p className="muted small" style={{ marginTop: 8 }}>
                {t("me.recoveryBody")}{" "}
                <Link href="/recover">{t("me.recoveryLink")}</Link>
            </p>

            <hr className="hairline" />

            <h2>{t("me.lockHeading")}</h2>
            <p className="muted small" style={{ marginTop: 8, marginBottom: 16 }}>
                {t("me.lockBody")}
            </p>
            <button
                type="button"
                className="btn btn--ghost"
                onClick={lock}
            >
                {t("me.lockNow")}
            </button>

            <hr className="hairline" />

            <h2 style={{ color: "var(--bad)" }}>{t("me.forgetHeading")}</h2>
            <p className="muted small" style={{ marginTop: 8, marginBottom: 16 }}>
                {t("me.forgetBody")}
            </p>
            {!confirmOut ? (
                <button
                    type="button"
                    className="btn btn--ghost"
                    onClick={() => setConfirmOut(true)}
                >
                    {t("me.forgetBtn")}
                </button>
            ) : (
                <div className="row">
                    <button
                        type="button"
                        className="btn btn--primary"
                        style={{ background: "var(--bad)" }}
                        onClick={() => void forgetDevice()}
                        disabled={signingOut}
                    >
                        {signingOut ? t("me.forgetWiping") : t("me.forgetConfirm")}
                    </button>
                    <button
                        type="button"
                        className="btn btn--ghost"
                        onClick={() => setConfirmOut(false)}
                        disabled={signingOut}
                    >
                        {t("common.cancel")}
                    </button>
                </div>
            )}
        </section>
    );
}
