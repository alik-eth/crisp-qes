import { useTranslation } from "react-i18next";

export function About() {
    const { t } = useTranslation();

    return (
        <section className="verify">
            <h1>{t("about.heading")}</h1>
            <p className="muted" style={{ marginTop: 8, marginBottom: 24 }}>
                {t("about.disclaimer")}
            </p>
            <p className="about-section__body">
                {t("about.body")}
            </p>

            <div className="tech-intro">
                <p className="tech-intro__body">{t("about.techIntro")}</p>
                <p className="tech-intro__stack mono">{t("about.techStack")}</p>
            </div>

            <div className="team-section">
                <p className="team-section__label">— {t("about.teamLabel")} —</p>
                <div className="team-grid">
                    {([1, 2] as const).map((n) => (
                        <div key={n} className="team-card">
                            <div>
                                <h3 className="team-card__name">{t(`about.team${n}name`)}</h3>
                                <p className="team-card__role">{t(`about.team${n}role`)}</p>
                            </div>
                            <p className="team-card__desc">{t(`about.team${n}desc`)}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}
