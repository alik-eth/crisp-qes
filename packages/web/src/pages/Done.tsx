import { useTranslation } from "react-i18next";
import { basescanTxUrl } from "../lib/relayer";

interface Props {
    petitionId: bigint;
    txHash: `0x${string}`;
    vote: number;
    onReturn: () => void;
}

export function Done({ petitionId, txHash, onReturn }: Props) {
    const { t } = useTranslation();
    return (
        <section className="section">
            <p className="section__label">§ 06</p>
            <h2 className="section__title">{t("done.heading")}</h2>
            <p className="lede">
                {t("done.lede", { id: petitionId.toString() })}
            </p>
            <dl>
                <div className="field-row">
                    <dt>{t("done.tx")}</dt>
                    <dd className="mono">{txHash}</dd>
                </div>
            </dl>
            <div className="actions">
                <a
                    className="btn btn--ghost"
                    href={basescanTxUrl(txHash)}
                    target="_blank"
                    rel="noreferrer"
                >
                    {t("done.viewOnExplorer")}
                </a>
                <button className="btn btn--accent" type="button" onClick={onReturn}>
                    {t("done.signAnother")}
                </button>
            </div>
        </section>
    );
}
