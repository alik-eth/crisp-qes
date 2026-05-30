import { Link } from "wouter";
import { useTranslation } from "react-i18next";

export function Footer() {
    const { t } = useTranslation();
    return (
        <footer className="footnote">
            <div className="footnote__inner">
                <span>{t("app.footnote")}</span>
                <span className="footnote__links">
                    <a
                        href="https://github.com/alik-eth/crisp-qes/tree/main"
                        target="_blank"
                        rel="noreferrer"
                    >
                        {t("footer.github")}
                    </a>
                    <Link href="/petitions">{t("footer.polls")}</Link>
                    <Link href="/about">{t("footer.about")}</Link>
                </span>
            </div>
        </footer>
    );
}
