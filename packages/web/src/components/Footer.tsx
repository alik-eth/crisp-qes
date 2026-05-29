import { useTranslation } from "react-i18next";

export function Footer() {
    const { t } = useTranslation();
    return (
        <footer className="footnote">
            {t("app.footnote")}
        </footer>
    );
}
