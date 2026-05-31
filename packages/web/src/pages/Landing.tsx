import { useEffect, useState } from "react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import type { AccountState } from "../lib/account.js";
import { readLeafCount, readAllPetitions } from "../lib/registry.js";

interface Props {
    state: AccountState;
    onSignIn: () => void;
}

interface Stats {
    citizens: number;
    petitions: number;
    signatures: number;
}

export function Landing({ state, onSignIn }: Props) {
    const { t, i18n } = useTranslation();
    const [stats, setStats] = useState<Stats | null>(null);
    const [statsErr, setStatsErr] = useState(false);

    useEffect(() => {
        let alive = true;
        void (async () => {
            try {
                const [leafCount, petitions] = await Promise.all([
                    readLeafCount(),
                    readAllPetitions(),
                ]);
                if (!alive) return;
                setStats({
                    citizens: Number(leafCount),
                    petitions: petitions.length,
                    signatures: petitions.reduce(
                        (acc, p) => acc + p.signatureCount,
                        0,
                    ),
                });
            } catch {
                if (alive) setStatsErr(true);
            }
        })();
        return () => {
            alive = false;
        };
    }, []);

    return (
        <section>
            <div className="hero">
                <h1
                    className="hero__title"
                    dangerouslySetInnerHTML={{ __html: t("landing.hero") }}
                />
                <p className="hero__sub">
                    {t("landing.sub")}
                    {" "}{t("landing.subAvail")}
                    <Link href="/about" style={{ color: "var(--ink)", fontWeight: 500 }}>
                        {t("landing.subAvailLink")}
                    </Link>
                    {t("landing.subAvailAfter")}
                </p>
                <div className="hero__cta">
                    <Link href="/petitions" className="btn btn--primary">
                        {t("landing.cta")}
                    </Link>
                    {state.kind === "guest" ? (
                        <button
                            type="button"
                            className="btn btn--ghost"
                            onClick={onSignIn}
                        >
                            {t("landing.signInOrRegister")}
                        </button>
                    ) : state.kind === "account" ? (
                        <Link href="/verify" className="btn btn--ghost">
                            {t("me.verifyNow")}
                        </Link>
                    ) : null}
                </div>
                <p className="hero__eidas muted small" style={{ marginTop: 20 }}>
                    {t("landing.eidasNote")}
                </p>
            </div>

            <div className="statbar">
                <div className="statbar__group">
                    {stats ? (
                        <>
                            <span className="statbar__item">
                                <span className="statbar__num">{stats.citizens}</span>
                                <span className="statbar__label">{t("landing.statCitizens")}</span>
                            </span>
                            <span className="statbar__sep" aria-hidden="true">·</span>
                            <span className="statbar__item">
                                <span className="statbar__num">{stats.petitions}</span>
                                <span className="statbar__label">{t("landing.statPolls")}</span>
                            </span>
                            <span className="statbar__sep" aria-hidden="true">·</span>
                            <span className="statbar__item">
                                <span className="statbar__num">{stats.signatures}</span>
                                <span className="statbar__label">{t("landing.statSignatures")}</span>
                            </span>
                        </>
                    ) : statsErr ? (
                        <span className="muted small">Chain data unavailable.</span>
                    ) : (
                        <span className="muted small">Loading on-chain stats…</span>
                    )}
                </div>
                <span className="statbar__live">LIVE · SEPOLIA</span>
            </div>

            {/* How it works */}
            <div className="how-section">
                <p className="how-section__label">— {t("landing.howLabel")} —</p>
                <h2 className="how-section__title">{t("landing.howTitle")}</h2>
                <div className="how-grid">
                    {([1, 2, 3, 4] as const).map((n) => (
                        <div key={n} className="how-card">
                            <span className="how-card__n">{t(`landing.step${n}n`)}</span>
                            <h3 className="how-card__title">{t(`landing.step${n}title`)}</h3>
                            <p className="how-card__body">{t(`landing.step${n}body`)}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* Чим ми відрізняємось */}
            <div className="about-section-block">
                <span className="eyebrow">{t("landing.techLabel") === "Технологія · Простими словами" ? (i18n.language === "uk" ? "Чим ми відрізняємось" : "How we're different") : (i18n.language === "uk" ? "Чим ми відрізняємось" : "How we're different")}</span>
                <div className="split-cols" style={{ marginTop: 24 }}>
                    <div className="split-col">
                        <span className="split-tag"><span className="split-dot" />{i18n.language === "uk" ? "Криптографічні рішення" : "Cryptographic solutions"}</span>
                        <p>{i18n.language === "uk"
                            ? "Існуючі рішення для приватного голосування з верифікацією особи спираються на паспорт як якір ідентичності (Rarimo Freedom Tool, zkPassport). Однак паспорт перевипускується, а значить людина може отримати новий номер документа, згенерувати новий nullifier і проголосувати повторно. Це фундаментальна вразливість, яку неможливо закрити на рівні протоколу. zkID (OpenAC) фокусується на unlinkability через anonymous credentials, але не гарантує унікальність."
                            : "Existing private-voting solutions with identity verification rely on the passport as an identity anchor (Rarimo Freedom Tool, zkPassport). However, a passport gets reissued — meaning a person can get a new document number, generate a new nullifier and vote again. This is a fundamental vulnerability that cannot be closed at the protocol level. zkID (OpenAC) focuses on unlinkability via anonymous credentials, but does not guarantee uniqueness."}</p>
                        <span className="split-ref">Rarimo Freedom Tool · zkPassport · zkID (OpenAC)</span>
                    </div>
                    <div className="split-col">
                        <span className="split-tag"><span className="split-dot" />{i18n.language === "uk" ? "Соцмережі та месенджери" : "Social media & messengers"}</span>
                        <p>{i18n.language === "uk"
                            ? "Опитування в соціальних мережах та месенджерах (Telegram, Instagram, X/Twitter) не забезпечують жодної верифікації учасників. Захист від ботів ненадійний — масові накрутки залишаються нормою. Неможливо достовірно встановити, що в голосуванні беруть участь саме повнолітні громадяни певної країни, а не боти, іноземці чи діти. Результати зберігаються на серверах платформи — їх можна змінити, видалити або сфальсифікувати без будь-якого сліду. Таким результатам можна лише довіряти, але неможливо їх перевірити."
                            : "Polls on social media and messengers (Telegram, Instagram, X/Twitter) provide no verification of participants. Bot protection is unreliable — mass manipulation remains the norm. There is no way to reliably establish that voters are actually adult citizens of a given country, rather than bots, foreigners or children. Results are stored on the platform's servers — they can be changed, deleted or falsified without any trace. Such results can only be trusted, but never verified."}</p>
                        <span className="split-ref">Telegram · Instagram · X / Twitter</span>
                    </div>
                </div>
                <div className="sol-block">
                    <div className="accent-rule"><span className="accent-rule__b" /><span className="accent-rule__y" /></div>
                    <div className="sol-inner">
                        <span className="split-tag"><span className="split-dot" />{i18n.language === "uk" ? "Як це вирішує Civic Voice" : "How Civic Voice solves it"}</span>
                        <p>{i18n.language === "uk"
                            ? "Civic Voice вирішує ці проблеми, використовуючи податковий номер (ІПН) як якір ідентичності. ІПН присвоюється один раз і не змінюється протягом життя — незалежно від перевипуску паспорта чи КЕП, nullifier залишається тим самим."
                            : "Civic Voice solves these problems by using the tax ID as an identity anchor. The tax ID is assigned once and never changes for life — regardless of passport or QES reissue, the nullifier stays the same."}</p>
                        <p>{i18n.language === "uk"
                            ? "Оскільки ІПН має низьку ентропію (10 цифр — можна перебрати за секунди), для безпечного використання в публічному блокчейні застосовується OPRF — протокол, що додає криптографічну сіль до ІПН без розкриття його серверу. Це робить nullifier стійким до перебору й безпечним для реєстру. OPRF також забезпечує unlinkability: ні платформа, ні блокчейн не можуть пов'язати голос з конкретною особою. FHE (CRISP) шифрує самі голоси, розкриваючи лише загальний результат."
                            : "Because the tax ID has low entropy (10 digits — brute-forceable in seconds), it is protected with OPRF — a protocol that adds a cryptographic salt to the tax ID without revealing it to the server. This makes the nullifier brute-force-resistant and safe for the registry. OPRF also provides unlinkability: neither the platform nor the blockchain can link a vote to a specific person. FHE (CRISP) encrypts the votes themselves, revealing only the aggregate result."}</p>
                    </div>
                </div>
                <div style={{ marginTop: 56 }}>
                    <span className="eyebrow">{i18n.language === "uk" ? "Порівняння" : "Comparison"}</span>
                </div>
                <table className="cmp-table">
                    <thead>
                        <tr>
                            <th />
                            <th>{i18n.language === "uk" ? "Соцмережі · опитування" : "Social polls"}</th>
                            <th>{i18n.language === "uk" ? "Крипто-рішення" : "Crypto solutions"}</th>
                            <th className="cmp-cv">CIVIC VOICE</th>
                        </tr>
                    </thead>
                    <tbody>
                        {[
                            { label: i18n.language === "uk" ? "Верифікація особи" : "Identity verification", vals: ["✕", "✓", "✓"] },
                            { label: i18n.language === "uk" ? "Унікальність · 1 особа — 1 голос" : "Uniqueness · 1 person — 1 vote", vals: ["✕", "✕", "✓"] },
                            { label: "Unlinkability", vals: ["✕", "✓", "✓"] },
                            { label: i18n.language === "uk" ? "Приватність голосу" : "Vote privacy", vals: ["✕", "✕", "✓"] },
                            { label: i18n.language === "uk" ? "Перевірюваний результат" : "Verifiable result", vals: ["✕", "✓", "✓"] },
                        ].map((row, ri) => (
                            <tr key={ri}>
                                <td className="cmp-label">{row.label}</td>
                                {row.vals.map((v, j) => (
                                    <td key={j} className={j === 2 ? "cmp-cv" : ""}>
                                        <span className={`cmp-tick${v === "✓" ? " cmp-tick--yes" : ""}`}>{v}</span>
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
                <div className="mech-grid-3" style={{ marginTop: 56 }}>
                    <div className="how-card">
                        <span className="how-card__n mono">{i18n.language === "uk" ? "ІПН" : "TAX ID"}</span>
                        <h3 className="how-card__title">{i18n.language === "uk" ? "Незмінний якір" : "An immutable anchor"}</h3>
                        <p className="how-card__body">{i18n.language === "uk" ? "Податковий номер не змінюється все життя. Один громадянин — один nullifier, який не обнулити перевипуском документів." : "A tax ID doesn't change for a lifetime. One citizen — one nullifier that can't be reset by reissuing documents."}</p>
                    </div>
                    <div className="how-card">
                        <span className="how-card__n mono">OPRF</span>
                        <h3 className="how-card__title">{i18n.language === "uk" ? "Сіль без розкриття" : "Salt without disclosure"}</h3>
                        <p className="how-card__body">{i18n.language === "uk" ? "Oblivious PRF додає криптографічну сіль до ІПН, не показуючи його ані платформі, ані блокчейну. Перебрати 10 цифр стає неможливо, а голос — не пов'язати з особою." : "An Oblivious PRF adds a cryptographic salt to the tax ID without showing it to the platform or the blockchain. Brute-forcing 10 digits becomes impossible, and a vote can't be linked to a person."}</p>
                    </div>
                    <div className="how-card">
                        <span className="how-card__n mono">FHE</span>
                        <h3 className="how-card__title">{i18n.language === "uk" ? "Зашифрований підрахунок" : "Encrypted tally"}</h3>
                        <p className="how-card__body">{i18n.language === "uk" ? "Гомоморфне шифрування (CRISP) шифрує самі голоси й розкриває лише загальний результат — окремий голос не побачить ніхто." : "Homomorphic encryption (CRISP) encrypts the votes themselves and reveals only the aggregate result — no one sees an individual vote."}</p>
                    </div>
                </div>
            </div>

            {/* Transparency */}
            <div className="transparency-section">
                <p className="transparency-section__label">— {t("landing.transparencyLabel")} —</p>
                <h2 className="transparency-section__title">{t("landing.transparencyTitle")}</h2>
                <div className="transparency-grid">
                    <div className="transparency-col">
                        <h3 className="transparency-col__head">
                            <span className="transparency-icon transparency-icon--check">✓</span>
                            {t("landing.registryCol")}
                        </h3>
                        {(t("landing.registryItems", { returnObjects: true }) as string[]).map((item, i) => (
                            <div key={i} className="transparency-row">
                                <span className="transparency-icon transparency-icon--check">✓</span>
                                {item}
                            </div>
                        ))}
                    </div>
                    <div className="transparency-col">
                        <h3 className="transparency-col__head">
                            <span className="transparency-icon transparency-icon--cross">✕</span>
                            {t("landing.deviceCol")}
                        </h3>
                        {(t("landing.deviceItems", { returnObjects: true }) as string[]).map((item, i) => (
                            <div key={i} className="transparency-row">
                                <span className="transparency-icon transparency-icon--cross">✕</span>
                                {item}
                            </div>
                        ))}
                    </div>
                </div>
            </div>

        </section>
    );
}
