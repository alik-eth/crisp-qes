import { useTranslation } from "react-i18next";
import { CoverageGrid } from "../components/CoverageGrid.js";

export function About() {
    const { t } = useTranslation();

    return (
        <section className="about-page">
            <h1>{t("about.heading")}</h1>
            <p className="muted" style={{ marginTop: 8, marginBottom: 24 }}>
                {t("about.disclaimer")}
            </p>
            <p className="about-section__body">
                {t("about.body")}
            </p>
            <p className="about-section__body" style={{ marginTop: 24 }}>
                <strong>{t("about.availability")}</strong>
            </p>

            <CoverageGrid />

            <div className="tech-intro">
                <p className="tech-intro__body">{t("about.techIntro")}</p>
                <p className="tech-intro__stack mono">{t("about.techStack")}</p>
            </div>

        </section>
    );
}
