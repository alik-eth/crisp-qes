// v2 has exactly one recovery primitive: Passkey cloud sync.
// v3 introduces yearly re-enrollment via Diia as the universal
// recovery primitive (see v2 spec §3.4 / §3.5 patched at d4bb63d
// and the recovery design memo at /tmp/recovery-design.md).
//
// Earlier drafts of this page implemented a BIP-39 mnemonic import
// flow. It was structurally broken in v2 (HKDF(N) is one-way relative
// to `s = pedersen([N_hi, N_lo], 0)`) and was removed in #51.
//
// This page now serves as an informational placeholder: it explains the
// two-phase recovery model so a citizen who reaches "/recover" gets a
// straight answer instead of a non-functional form. When v3 ships,
// this page will gain the "renew for the new epoch" prompt described
// in v3 §6.5.

import { useTranslation } from "react-i18next";

interface Props {
    onBack: () => void;
}

export function Recover({ onBack }: Props) {
    const { t } = useTranslation();

    return (
        <section className="section">
            <button className="btn--link" onClick={onBack} type="button">
                ← {t("recover.back")}
            </button>
            <h2 className="section__title" style={{ marginTop: 8 }}>
                {t("recover.heading")}
            </h2>

            <div className="panel">
                <p className="panel__title">{t("recover.v2.title")}</p>
                <p className="note">{t("recover.v2.intro")}</p>
                <ul className="bullets">
                    <li>{t("recover.v2.point1")}</li>
                    <li>{t("recover.v2.point2")}</li>
                </ul>
            </div>

            <div className="panel">
                <p className="panel__title">{t("recover.v3.title")}</p>
                <p className="note">{t("recover.v3.intro")}</p>
            </div>

            <div className="actions">
                <button
                    className="btn btn--accent"
                    type="button"
                    onClick={onBack}
                >
                    {t("recover.backCta")}
                </button>
            </div>
        </section>
    );
}
