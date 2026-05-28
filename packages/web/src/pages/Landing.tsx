import { useTranslation } from "react-i18next";

interface Props {
    onBrowse: () => void;
}

export function Landing({ onBrowse }: Props) {
    const { t } = useTranslation();
    const guarantees = t("landing.guarantees", { returnObjects: true }) as string[];
    const limits = t("landing.limits", { returnObjects: true }) as string[];
    return (
        <section className="section">
            <p className="lede dropcap">{t("landing.lede")}</p>

            <div className="two-col">
                <div className="col">
                    <p className="section__label">§ 01</p>
                    <h3>{t("landing.sectionGuarantees")}</h3>
                    <ol>
                        {guarantees.map((g, i) => (
                            <li key={i}>{g}</li>
                        ))}
                    </ol>
                </div>
                <div className="two-col__divider" aria-hidden="true" />
                <div className="col">
                    <p className="section__label">§ 02</p>
                    <h3>{t("landing.sectionLimits")}</h3>
                    <ol>
                        {limits.map((g, i) => (
                            <li key={i}>{g}</li>
                        ))}
                    </ol>
                </div>
            </div>

            <div className="cta-row">
                <button className="btn btn--accent" onClick={onBrowse} type="button">
                    {t("landing.cta")}
                </button>
            </div>
        </section>
    );
}
