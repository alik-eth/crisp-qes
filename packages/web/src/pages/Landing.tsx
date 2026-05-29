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

            {/*
             * Primary CTA hoisted above the .two-col block so it lands above
             * the fold on mobile (iPhone-14 390×844). See RED-3 in
             * bench/ux-results-2026-05-29.md — without this hoist the only
             * forward-action sits at y≈1771 px on 844 px viewport.
             * Long-form guarantees / limits stay below as scroll-down reference;
             * the duplicate CTA at the bottom is preserved for desktop where
             * the lists are already above the fold.
             */}
            <div className="cta-row cta-row--hoisted">
                <button className="btn btn--accent" onClick={onBrowse} type="button">
                    {t("landing.cta")}
                </button>
            </div>

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
