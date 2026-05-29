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
                            Sign in or register
                        </button>
                    ) : state.kind === "account" ? (
                        <Link href="/verify" className="btn btn--ghost">
                            Verify with QES
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

            <div style={{ marginTop: 64 }}>
                <h2 className="section__title">{t("landing.howTitle")}</h2>
                <ol className="howlist">
                    <li className="howlist__item">
                        <span className="howlist__num">1</span>
                        <p className="howlist__text">
                            <b>{t("landing.how1title")}</b>{" "}
                            {t("landing.how1body")}
                        </p>
                    </li>
                    <li className="howlist__item">
                        <span className="howlist__num">2</span>
                        <p className="howlist__text">
                            <b>{t("landing.how2title")}</b>{" "}
                            {t("landing.how2body")}
                        </p>
                    </li>
                    <li className="howlist__item">
                        <span className="howlist__num">3</span>
                        <p className="howlist__text">
                            <b>{t("landing.how3title")}</b>{" "}
                            {t("landing.how3body")}
                        </p>
                    </li>
                </ol>
            </div>
        </section>
    );
}
