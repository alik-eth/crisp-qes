import { useTranslation } from "react-i18next";

const COUNTRIES = [
    { code: "UA", live: true },
    { code: "AT" }, { code: "BE" }, { code: "BG" }, { code: "CY" },
    { code: "CZ" }, { code: "DE" }, { code: "DK" }, { code: "EE" },
    { code: "ES" }, { code: "FI" }, { code: "FR" }, { code: "GR" },
    { code: "HR" }, { code: "HU" }, { code: "IE" }, { code: "IT" },
    { code: "LT" }, { code: "LU" }, { code: "LV" }, { code: "MT" },
    { code: "NL" }, { code: "PL" }, { code: "PT" }, { code: "RO" },
    { code: "SE" }, { code: "SI" }, { code: "SK" },
] as const;

const NAMES: Record<string, { uk: string; en: string }> = {
    UA: { uk: "Україна", en: "Ukraine" },
    AT: { uk: "Австрія", en: "Austria" },
    BE: { uk: "Бельгія", en: "Belgium" },
    BG: { uk: "Болгарія", en: "Bulgaria" },
    CY: { uk: "Кіпр", en: "Cyprus" },
    CZ: { uk: "Чехія", en: "Czechia" },
    DE: { uk: "Німеччина", en: "Germany" },
    DK: { uk: "Данія", en: "Denmark" },
    EE: { uk: "Естонія", en: "Estonia" },
    ES: { uk: "Іспанія", en: "Spain" },
    FI: { uk: "Фінляндія", en: "Finland" },
    FR: { uk: "Франція", en: "France" },
    GR: { uk: "Греція", en: "Greece" },
    HR: { uk: "Хорватія", en: "Croatia" },
    HU: { uk: "Угорщина", en: "Hungary" },
    IE: { uk: "Ірландія", en: "Ireland" },
    IT: { uk: "Італія", en: "Italy" },
    LT: { uk: "Литва", en: "Lithuania" },
    LU: { uk: "Люксембург", en: "Luxembourg" },
    LV: { uk: "Латвія", en: "Latvia" },
    MT: { uk: "Мальта", en: "Malta" },
    NL: { uk: "Нідерланди", en: "Netherlands" },
    PL: { uk: "Польща", en: "Poland" },
    PT: { uk: "Португалія", en: "Portugal" },
    RO: { uk: "Румунія", en: "Romania" },
    SE: { uk: "Швеція", en: "Sweden" },
    SI: { uk: "Словенія", en: "Slovenia" },
    SK: { uk: "Словаччина", en: "Slovakia" },
};

export function CoverageGrid() {
    const { i18n } = useTranslation();
    const lang = i18n.language === "uk" ? "uk" : "en";

    return (
        <div className="coverage-grid">
            {COUNTRIES.map(({ code, ...rest }) => {
                const live = "live" in rest;
                return (
                    <div
                        key={code}
                        className={`coverage-tile${live ? " coverage-tile--live" : ""}`}
                    >
                        <span className="coverage-tile__code">{code}</span>
                        <span className="coverage-tile__name">
                            {NAMES[code]?.[lang] ?? code}
                        </span>
                        {live ? (
                            <span className="coverage-tile__badge">LIVE</span>
                        ) : null}
                    </div>
                );
            })}
        </div>
    );
}
