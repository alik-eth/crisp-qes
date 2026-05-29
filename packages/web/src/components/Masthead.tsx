import { useTranslation } from "react-i18next";

interface Props {
    onTogglePetitions?: () => void;
    onEnroll?: () => void;
}

// Recover is intentionally NOT a default top-nav entry — it's an
// "I already enrolled on another device" affordance, not a destination
// for cold-start visitors. See YEL-6 in bench/ux-results-2026-05-29.md
// and team-lead's triage guidance: surface it inline from Sign.tsx's
// `missingEnrollment` branch instead. The `/recover` route remains
// navigable via App.tsx — only the cold-start nav button is gone.
export function Masthead({ onTogglePetitions, onEnroll }: Props) {
    const { t, i18n } = useTranslation();
    const other = i18n.language === "uk" ? "en" : "uk";
    return (
        <header className="masthead">
            <div>
                <h1 className="masthead__brand">{t("app.name")}</h1>
                <p className="masthead__tagline">{t("app.tagline")}</p>
            </div>
            <div className="masthead__meta">
                <span>{t("app.issue")}</span>
                <button onClick={onTogglePetitions} type="button">
                    {t("nav.petitions")}
                </button>
                <button onClick={onEnroll} type="button">
                    {t("nav.enroll")}
                </button>
                <button onClick={() => void i18n.changeLanguage(other)} type="button">
                    {t("meta.languageNameOther")}
                </button>
            </div>
        </header>
    );
}
