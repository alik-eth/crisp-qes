import { useTranslation } from "react-i18next";

interface Props {
    onTogglePetitions?: () => void;
    onCreate?: () => void;
}

export function Masthead({ onTogglePetitions, onCreate }: Props) {
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
                <button onClick={onCreate} type="button">
                    {t("nav.create")}
                </button>
                <button onClick={() => void i18n.changeLanguage(other)} type="button">
                    {t("meta.languageNameOther")}
                </button>
            </div>
        </header>
    );
}
