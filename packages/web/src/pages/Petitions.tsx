import { useEffect, useState } from "react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import type { AccountState } from "../lib/account.js";
import {
    readAllPetitions,
    type PetitionView,
} from "../lib/registry.js";

interface Props {
    state: AccountState;
    onSignIn: () => void;
}

function timeRemaining(deadline: bigint): string {
    const now = Math.floor(Date.now() / 1000);
    const secs = Number(deadline) - now;
    if (secs <= 0) return "Closed";
    const days = Math.floor(secs / 86400);
    if (days >= 2) return `${days} days left`;
    if (days === 1) return "1 day left";
    const hours = Math.floor(secs / 3600);
    if (hours >= 1) return `${hours}h left`;
    const mins = Math.floor(secs / 60);
    return `${mins}m left`;
}

export function Petitions({ state, onSignIn }: Props) {
    const { t } = useTranslation();
    const [petitions, setPetitions] = useState<PetitionView[] | null>(null);
    const [err, setErr] = useState<string | null>(null);

    useEffect(() => {
        let alive = true;
        void (async () => {
            try {
                const list = await readAllPetitions();
                if (alive) setPetitions(list);
            } catch (e) {
                if (alive) setErr(e instanceof Error ? e.message : "load failed");
            }
        })();
        return () => {
            alive = false;
        };
    }, []);

    return (
        <section>
            <header className="petitions__head">
                <h1>{t("list.heading")}</h1>
                <CreateCta state={state} onSignIn={onSignIn} />
            </header>

            {state.kind === "account" ? (
                <div className="notice notice--info" style={{ marginBottom: 20 }}>
                    <div>
                        Your account is registered but not verified.{" "}
                        <Link href="/verify">Verify with QES</Link>{" "}
                        to sign or create petitions.
                    </div>
                </div>
            ) : null}

            {err ? (
                <p className="muted">{t("list.error")}: {err}</p>
            ) : petitions === null ? (
                <p className="muted">{t("list.loading")}</p>
            ) : petitions.length === 0 ? (
                <p className="muted">
                    {t("list.empty")}{" "}
                    {state.kind === "verified" ? (
                        <Link href="/p/new">Create the first one.</Link>
                    ) : null}
                </p>
            ) : (
                <ul className="petitions">
                    {petitions
                        .slice()
                        .reverse()
                        .map((p) => (
                            <li key={p.id.toString()}>
                                <Link
                                    href={`/p/${p.id.toString()}`}
                                    className="petitions__row"
                                >
                                    <div className="petitions__main">
                                        <div className="petitions__title">
                                            #{p.id.toString()} ·{" "}
                                            {firstLine(p.fullText) ||
                                                "(untitled)"}
                                        </div>
                                        <div className="petitions__meta">
                                            <span className="muted">
                                                {p.signatureCount} {t("list.card.count")}
                                            </span>
                                            <span className="muted">·</span>
                                            <span className="muted">
                                                {timeRemaining(p.deadline)}
                                            </span>
                                        </div>
                                    </div>
                                    <StatusBadge status={p.status} />
                                </Link>
                            </li>
                        ))}
                </ul>
            )}
        </section>
    );
}

function firstLine(text: string): string {
    return text.split(/\r?\n/)[0]?.slice(0, 120) ?? "";
}

function StatusBadge({ status }: { status: PetitionView["status"] }) {
    const { t } = useTranslation();
    const cls =
        status === "Open" ? "badge badge--ok"
        : status === "ThresholdReached" ? "badge badge--ok"
        : status === "Closed" ? "badge badge--muted"
        : "badge";
    return <span className={cls}>{t(`list.status.${status}`)}</span>;
}

function CreateCta({
    state,
    onSignIn,
}: {
    state: AccountState;
    onSignIn: () => void;
}) {
    if (state.kind === "verified") {
        return (
            <Link href="/p/new" className="btn btn--primary btn--sm">
                New petition
            </Link>
        );
    }
    if (state.kind === "account") {
        return (
            <Link href="/verify" className="btn btn--ghost btn--sm">
                Verify to create
            </Link>
        );
    }
    return (
        <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={onSignIn}
        >
            Sign in to create
        </button>
    );
}
