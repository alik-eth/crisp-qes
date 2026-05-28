import { useTranslation } from "react-i18next";
import { basescanTxUrl } from "../lib/relayer";

interface Props {
    petitionId: bigint;
    txHash: `0x${string}`;
    newCount: number;
    onReturn: () => void;
}

export function Done({ petitionId, txHash, newCount, onReturn }: Props) {
    const { t } = useTranslation();
    const url = basescanTxUrl(txHash);
    return (
        <section className="section">
            <p className="section__label">§ 06</p>
            <h2 className="section__title">{t("done.heading")}</h2>
            <p className="lede">{t("done.lede", { id: petitionId.toString() })}</p>
            <p>
                <span className="done-stat">{newCount}</span>
            </p>
            <dl style={{ marginTop: 28 }}>
                <div className="field-row">
                    <dt>{t("done.tx")}</dt>
                    <dd className="mono">
                        {url ? (
                            <a href={url} target="_blank" rel="noopener noreferrer">
                                {txHash}
                            </a>
                        ) : (
                            txHash
                        )}
                    </dd>
                </div>
            </dl>
            <div className="actions">
                <button className="btn" type="button" onClick={onReturn}>
                    {t("done.signAnother")}
                </button>
                {url ? (
                    <a className="btn btn--ghost" href={url} target="_blank" rel="noopener noreferrer">
                        {t("done.viewOnExplorer")}
                    </a>
                ) : null}
            </div>
        </section>
    );
}
