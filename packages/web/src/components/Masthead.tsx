import { useTranslation } from "react-i18next";

interface Props {
    onTogglePetitions?: () => void;
    onEnroll?: () => void;
    onRecover?: () => void;
}

export function Masthead({ onTogglePetitions, onEnroll, onRecover }: Props) {
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
                <button onClick={onRecover} type="button">
                    {t("nav.recover")}
                </button>
                <button onClick={() => void i18n.changeLanguage(other)} type="button">
                    {t("meta.languageNameOther")}
                </button>
            </div>
        </header>
    );
}
