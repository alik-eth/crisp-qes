import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { readAllPetitions, type PetitionView } from "../lib/registry";

interface Props {
    onSign: (id: bigint) => void;
}

function shortAddr(addr: string): string {
    return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function formatDate(epochSecs: bigint, locale: string): string {
    return new Date(Number(epochSecs) * 1000).toLocaleString(locale, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    });
}

function totalVotes(p: PetitionView): number {
    return p.yesCount + p.noCount + p.abstainCount;
}

export function Petitions({ onSign }: Props) {
    const { t, i18n } = useTranslation();
    const [items, setItems] = useState<PetitionView[] | null>(null);
    const [err, setErr] = useState<string | null>(null);

    useEffect(() => {
        let alive = true;
        (async () => {
            try {
                const all = await readAllPetitions();
                if (alive) setItems(all);
            } catch (e) {
                if (alive) setErr(e instanceof Error ? e.message : String(e));
            }
        })();
        return () => {
            alive = false;
        };
    }, []);

    if (err) {
        return (
            <section className="section">
                <h2 className="section__title">{t("list.heading")}</h2>
                <p className="error-line">{t("list.error")}</p>
                <p className="note mono">{err}</p>
            </section>
        );
    }
    if (items === null) {
        return (
            <section className="section">
                <h2 className="section__title">{t("list.heading")}</h2>
                <p className="note">{t("list.loading")}</p>
                <div className="progress__line">
                    <span />
                </div>
            </section>
        );
    }
    if (items.length === 0) {
        return (
            <section className="section">
                <h2 className="section__title">{t("list.heading")}</h2>
                <p className="note">{t("list.empty")}</p>
            </section>
        );
    }

    return (
        <section className="section">
            <p className="section__label">§ 03</p>
            <h2 className="section__title">{t("list.heading")}</h2>
            <div className="petition-grid">
                {items.map((p) => {
                    const total = totalVotes(p);
                    const ratio =
                        p.threshold > 0 ? Math.min(1, total / p.threshold) : 0;
                    const statusClass =
                        p.status === "Open"
                            ? "status-tag--open"
                            : p.status === "ThresholdReached"
                              ? "status-tag--reached"
                              : "status-tag--closed";
                    const truncated =
                        p.fullText.length > 320
                            ? p.fullText.slice(0, 320) + "…"
                            : p.fullText;
                    return (
                        <article className="petition-card" key={p.id.toString()}>
                            <div>
                                <p className="petition-card__id">
                                    {t("list.card.id", { id: p.id.toString() })}
                                </p>
                                <p className="petition-card__text">{truncated}</p>
                                <div className="petition-card__actions">
                                    <span className={`status-tag ${statusClass}`}>
                                        {t(`list.status.${p.status}`)}
                                    </span>
                                </div>
                            </div>
                            <dl className="petition-card__meta">
                                <div>
                                    <dt>{t("list.card.mode")}</dt>
                                    <dd className="mono">
                                        {p.modeLabel === "Signature"
                                            ? t("list.card.signature")
                                            : p.modeLabel === "YesNo"
                                              ? t("list.card.yesNo")
                                              : t("list.card.yesNoAbstain")}
                                    </dd>
                                </div>
                                <div>
                                    <dt>{t("list.card.count")}</dt>
                                    <dd>
                                        <span className="petition-card__count">
                                            {total}
                                        </span>
                                        <span className="petition-card__count-of">
                                            {t("list.card.of")}{" "}
                                            {p.threshold.toString()}
                                        </span>
                                        <div className="petition-card__bar">
                                            <span style={{ width: `${ratio * 100}%` }} />
                                        </div>
                                        {p.modeLabel !== "Signature" ? (
                                            <p
                                                className="note mono"
                                                style={{ marginTop: 6 }}
                                            >
                                                {p.yesCount} · {p.noCount}
                                                {p.modeLabel === "YesNoAbstain"
                                                    ? ` · ${p.abstainCount}`
                                                    : ""}
                                            </p>
                                        ) : null}
                                    </dd>
                                </div>
                                <div>
                                    <dt>{t("list.card.deadline")}</dt>
                                    <dd>{formatDate(p.deadline, i18n.language)}</dd>
                                </div>
                                <div>
                                    <dt>{t("list.card.creator")}</dt>
                                    <dd className="mono">{shortAddr(p.creator)}</dd>
                                </div>
                                {p.status === "Open" ? (
                                    <div>
                                        <button
                                            className="btn btn--small"
                                            onClick={() => onSign(p.id)}
                                            type="button"
                                        >
                                            {t("list.card.sign")}
                                        </button>
                                    </div>
                                ) : null}
                            </dl>
                        </article>
                    );
                })}
            </div>
        </section>
    );
}
