import { useEffect, useState } from "react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import type { AccountState } from "../lib/account.js";
import { readLeafCount, readAllPetitions } from "../lib/registry.js";

interface Props {
    state: AccountState;
    onSignIn: () => void;
}

interface Stats {
    citizens: number;
    petitions: number;
    signatures: number;
}

export function Landing({ state, onSignIn }: Props) {
    const { t } = useTranslation();
    const [stats, setStats] = useState<Stats | null>(null);
    const [statsErr, setStatsErr] = useState(false);

    useEffect(() => {
        let alive = true;
        void (async () => {
            try {
                const [leafCount, petitions] = await Promise.all([
                    readLeafCount(),
                    readAllPetitions(),
                ]);
                if (!alive) return;
                setStats({
                    citizens: Number(leafCount),
                    petitions: petitions.length,
                    signatures: petitions.reduce(
                        (acc, p) => acc + p.signatureCount,
                        0,
                    ),
                });
            } catch {
                if (alive) setStatsErr(true);
            }
        })();
        return () => {
            alive = false;
        };
    }, []);

    return (
        <section>
            <div className="hero">
                <h1
                    className="hero__title"
                    dangerouslySetInnerHTML={{ __html: t("landing.hero") }}
                />
                <p className="hero__sub">
                    {t("landing.sub")}
                </p>
                <div className="hero__cta">
                    <Link href="/petitions" className="btn btn--primary">
                        {t("landing.cta")}
                    </Link>
                    {state.kind === "guest" ? (
                        <button
                            type="button"
                            className="btn btn--ghost"
                            onClick={onSignIn}
                        >
                            {t("landing.signInOrRegister")}
                        </button>
                    ) : state.kind === "account" ? (
                        <Link href="/verify" className="btn btn--ghost">
                            {t("me.verifyNow")}
                        </Link>
                    ) : null}
                </div>
            </div>

            <div className="statbar">
                <div className="statbar__group">
                    {stats ? (
                        <>
                            <span className="statbar__item">
                                <span className="statbar__num">{stats.citizens}</span>
                                <span className="statbar__label">{t("landing.statCitizens")}</span>
                            </span>
                            <span className="statbar__sep" aria-hidden="true">·</span>
                            <span className="statbar__item">
                                <span className="statbar__num">{stats.petitions}</span>
                                <span className="statbar__label">{t("landing.statPolls")}</span>
                            </span>
                            <span className="statbar__sep" aria-hidden="true">·</span>
                            <span className="statbar__item">
                                <span className="statbar__num">{stats.signatures}</span>
                                <span className="statbar__label">{t("landing.statSignatures")}</span>
                            </span>
                        </>
                    ) : statsErr ? (
                        <span className="muted small">Chain data unavailable.</span>
                    ) : (
                        <span className="muted small">Loading on-chain stats…</span>
                    )}
                </div>
                <span className="statbar__live">LIVE · SEPOLIA</span>
            </div>

            <div className="how-section">
                <p className="how-section__label">— {t("landing.howLabel")} —</p>
                <h2 className="how-section__title">{t("landing.howTitle")}</h2>
                <div className="how-grid">
                    {([1, 2, 3, 4] as const).map((n) => (
                        <div key={n} className="how-card">
                            <span className="how-card__n">{t(`landing.step${n}n`)}</span>
                            <h3 className="how-card__title">{t(`landing.step${n}title`)}</h3>
                            <p className="how-card__body">{t(`landing.step${n}body`)}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}
