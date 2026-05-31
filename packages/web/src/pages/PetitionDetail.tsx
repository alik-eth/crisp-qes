import { useEffect, useState, useCallback } from "react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import type { AccountState } from "../lib/account.js";
import { readPetition, type PetitionView } from "../lib/registry.js";
import { SignBlock } from "../components/SignBlock.js";

interface Props {
    id: string;
    state: AccountState;
    onSignIn: () => void;
    refresh: () => Promise<void>;
}

export function PetitionDetail({ id, state, onSignIn }: Props) {
    const { t } = useTranslation();
    const [petition, setPetition] = useState<PetitionView | null>(null);
    const [err, setErr] = useState<string | null>(null);

    const loadPetition = useCallback(async () => {
        try {
            const idBig = BigInt(id);
            const p = await readPetition(idBig);
            if (p) setPetition(p);
            else setErr(t("detail.notFound"));
        } catch (e) {
            setErr(e instanceof Error ? e.message : "load failed");
        }
    }, [id, t]);

    useEffect(() => {
        let alive = true;
        void (async () => {
            const idBig = BigInt(id);
            try {
                const p = await readPetition(idBig);
                if (!alive) return;
                if (p) setPetition(p);
                else setErr(t("detail.notFound"));
            } catch (e) {
                if (alive)
                    setErr(e instanceof Error ? e.message : "load failed");
            }
        })();
        return () => {
            alive = false;
        };
    }, [id, t]);

    if (err) {
        return (
            <section className="section">
                <p className="muted">{err}</p>
                <p style={{ marginTop: 16 }}>
                    <Link href="/petitions" className="btn btn--ghost btn--sm">
                        {t("detail.backBtn")}
                    </Link>
                </p>
            </section>
        );
    }
    if (!petition) {
        return (
            <section className="section">
                <p className="muted">{t("detail.loading")}</p>
            </section>
        );
    }

    const lines = petition.fullText.split(/\r?\n/);
    const title = lines[0] || `#${petition.id.toString()}`;
    const body = lines.slice(1).join("\n").trim();

    return (
        <section className="detail">
            <div className="detail__crumbs">
                <Link href="/petitions">{t("detail.back")}</Link>
            </div>

            <h1 className="detail__title">{title}</h1>

            <dl className="detail__facts">
                <Fact label={t("detail.status")} value={t(`list.status.${petition.status}`)} />
                <Fact
                    label={t("detail.deadline")}
                    value={new Date(
                        Number(petition.deadline) * 1000,
                    ).toLocaleString()}
                />
                <Fact label={t("detail.threshold")} value={petition.threshold.toLocaleString()} />
                <Fact
                    label={t("detail.signatures")}
                    value={petition.signatureCount.toLocaleString()}
                />
                <Fact label={t("detail.creator")} value={shortAddr(petition.creator)} mono />
            </dl>

            {body ? (
                <div className="detail__body">
                    {body.split(/\n\n+/).map((para, i) => (
                        <p key={i}>{para}</p>
                    ))}
                </div>
            ) : null}

            <SignCta
                petition={petition}
                state={state}
                onSignIn={onSignIn}
                onSigned={() => {
                    void loadPetition();
                }}
            />
        </section>
    );
}

function Fact({
    label,
    value,
    mono = false,
}: {
    label: string;
    value: string;
    mono?: boolean;
}) {
    return (
        <div className="fact">
            <dt>{label}</dt>
            <dd className={mono ? "mono" : undefined}>{value}</dd>
        </div>
    );
}

function SignCta({
    petition,
    state,
    onSignIn,
    onSigned,
}: {
    petition: PetitionView;
    state: AccountState;
    onSignIn: () => void;
    onSigned: (txHash: `0x${string}`) => void;
}) {
    const { t } = useTranslation();
    if (petition.status !== "Open") {
        return (
            <div className="detail__cta">
                <p className="muted">{t("detail.closed")}</p>
            </div>
        );
    }
    if (state.kind === "guest") {
        return (
            <div className="detail__cta">
                <button
                    type="button"
                    className="btn btn--primary"
                    onClick={onSignIn}
                >
                    {t("detail.signIn")}
                </button>
            </div>
        );
    }
    if (state.kind === "account") {
        return (
            <div className="detail__cta">
                <Link href="/verify" className="btn btn--primary">
                    {t("detail.verify")}
                </Link>
            </div>
        );
    }
    return <SignBlock petition={petition} onSigned={onSigned} />;
}

function shortAddr(a: `0x${string}`): string {
    return `${a.slice(0, 6)}…${a.slice(-4)}`;
}
