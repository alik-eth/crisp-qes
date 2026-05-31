import { useTranslation } from "react-i18next";
import { CoverageGrid } from "../components/CoverageGrid.js";

export function About() {
    const { t, i18n } = useTranslation();
    const uk = i18n.language === "uk";

    return (
        <section className="about-page">

            {/* ── Про проєкт ── */}
            <div className="about-hero">
                <span className="eyebrow">{uk ? "Про проєкт · як це працює" : "About · how it works"}</span>
                <p className="about-hero__lede">
                    {uk
                        ? "Civic Voice — відкритий сервіс, створений для того, щоб дізнатись приватну, анонімну громадську думку з будь-якого питання і бути впевненим, що в голосуванні брали участь повнолітні громадяни, а результати є публічними і їх неможливо змінити. Ми поєднуємо ідентифікацію за допомогою КЕП з криптографією нульового розголошення, щоб ніхто — ні організатор, ні платформа, ні будь-яка третя сторона — не міг дізнатись, хто і як проголосував. Результати доступні кожному в публічному розподіленому реєстрі (блокчейн), де їх неможливо змінити, видалити чи сфальсифікувати. Код проєкту відкритий, щоб кожен міг перевірити, що система працює саме так, як заявлено. Результати голосувань не мають юридичних наслідків і є інструментом для проведення громадських опитувань."
                        : "Civic Voice is an open service built to learn private, anonymous public opinion on any question — and to be sure that the participants were adult citizens, while the results are public and impossible to alter. We combine QES identification with zero-knowledge cryptography so that no one — neither the organiser, nor the platform, nor any third party — can learn who voted or how. Results are available to everyone in a public distributed ledger (blockchain), where they cannot be changed, deleted or forged. The project's code is open so anyone can verify the system works exactly as claimed. Voting results have no legal consequences and are a tool for conducting public polls."}
                </p>
            </div>

            {/* ── Хто може голосувати ── */}
            <div className="about-section-block">
                <span className="eyebrow">{uk ? "Хто може голосувати" : "Who can vote"}</span>
                <h2 className="about-h2">{uk ? "Громадяни України та 27 країн ЄС." : "Citizens of Ukraine and 27 EU countries."}</h2>
                <div className="cov-layout">
                    <div className="cov-aside">
                        <span className="micro">
                            {uk ? "Покриття eIDAS" : "eIDAS coverage"}
                        </span>
                        <p className="cov-body">
                            {uk
                                ? "Платформа доступна кожному, хто має кваліфікований електронний підпис (КЕП / QES) — це громадяни України та 27 країн Європейського Союзу відповідно до регламенту eIDAS."
                                : "The platform is open to anyone holding a qualified electronic signature (QES) — citizens of Ukraine and the 27 European Union countries under the eIDAS regulation."}
                        </p>
                        <div className="cov-legend">
                            <div className="cov-legend__item">
                                <span className="cov-swatch cov-swatch--hatch" />
                                <span>{uk ? "Підтримка ECDSA P-256" : "ECDSA P-256 support"}</span>
                            </div>
                            <div className="cov-legend__item">
                                <span className="cov-swatch cov-swatch--base" />
                                <span>{uk ? "Інші країни eIDAS" : "Other eIDAS countries"}</span>
                            </div>
                        </div>
                        <p className="muted small" style={{ marginTop: 16 }}>
                            {t("about.mapCaption")}
                        </p>
                    </div>
                    <div className="cov-map-frame">
                        <CoverageGrid />
                        <span className="cov-map-stamp mono">eIDAS · EUROPE · 2026</span>
                    </div>
                </div>
            </div>

            {/* ── Чим ми відрізняємось ── */}
            <div className="about-section-block about-section-block--paper">
                <span className="eyebrow">{uk ? "Чим ми відрізняємось" : "How we're different"}</span>
                <h2 className="about-h2">{uk ? "Не таке, як інші рішення для голосувань." : "Unlike any existing voting tool."}</h2>
                <p className="about-lede">
                    {uk
                        ? "Громадську думку сьогодні збирають двома шляхами — опитування в соцмережах та криптографічні рішення для голосувань. Обидва ламаються там, де треба одночасно довести унікальність голосу, зберегти приватність і дати змогу перевірити результат. Ось чим відрізняється Civic Voice."
                        : "Public opinion is gathered in two ways today — social-media polls and cryptographic voting tools. Both break exactly where you must simultaneously prove a vote's uniqueness, preserve privacy, and let anyone verify the result. Here is how Civic Voice differs."}
                </p>

                <div className="split-cols">
                    <div className="split-col">
                        <span className="split-tag">
                            <span className="split-dot" />
                            {uk ? "Криптографічні рішення" : "Cryptographic solutions"}
                        </span>
                        <p>
                            {uk
                                ? "Існуючі рішення для приватного голосування спираються на паспорт як якір ідентичності. Але паспорт перевипускується — отримавши новий номер документа, людина генерує новий nullifier і голосує повторно. Це фундаментальна вразливість, яку неможливо закрити на рівні протоколу."
                                : "Existing private-voting solutions rely on the passport as an identity anchor. But a passport gets reissued — with a new document number, a person generates a new nullifier and votes again. It is a fundamental vulnerability that cannot be closed at the protocol level."}
                        </p>
                        <span className="split-ref">Rarimo Freedom Tool · zkPassport · PSE zkID</span>
                    </div>
                    <div className="split-col">
                        <span className="split-tag">
                            <span className="split-dot" />
                            {uk ? "Соцмережі та месенджери" : "Social media & messengers"}
                        </span>
                        <p>
                            {uk
                                ? "Опитування в соцмережах і месенджерах (Telegram-боти, Instagram Stories, X / Twitter polls) не забезпечують жодної верифікації учасників. Захист від ботів ненадійний — масові накрутки залишаються нормою. Результати зберігаються на серверах платформи — їх можна змінити, видалити чи сфальсифікувати без сліду."
                                : "Polls on social media and messengers (Telegram bots, Instagram Stories, X / Twitter polls) provide no verification of participants. Bot protection is unreliable — mass manipulation remains the norm. Results live on the platform's servers — they can be changed, deleted or forged without a trace."}
                        </p>
                        <span className="split-ref">Telegram · Instagram · X / Twitter</span>
                    </div>
                </div>

                <div className="sol-block">
                    <div className="accent-rule"><span className="accent-rule__b" /><span className="accent-rule__y" /></div>
                    <div className="sol-inner">
                        <span className="split-tag">
                            <span className="split-dot" />
                            {uk ? "Як це вирішує Civic Voice" : "How Civic Voice solves it"}
                        </span>
                        <p>
                            {uk
                                ? "Civic Voice вирішує ці проблеми, використовуючи податковий номер (ІПН) як якір ідентичності. ІПН присвоюється один раз і не змінюється протягом життя — незалежно від перевипуску паспорта чи КЕП, nullifier залишається тим самим."
                                : "Civic Voice solves these problems by using the tax ID as an identity anchor. The tax ID is assigned once and never changes for life — regardless of passport or QES reissue, the nullifier stays the same."}
                        </p>
                        <p>
                            {uk
                                ? "Оскільки ІПН має низьку ентропію (10 цифр — можна перебрати за секунди), для безпечного використання в публічному блокчейні застосовується OPRF — протокол, що додає криптографічну сіль до ІПН без розкриття його серверу. Це робить nullifier стійким до перебору й безпечним для реєстру. OPRF також забезпечує unlinkability: ні платформа, ні блокчейн не можуть пов'язати голос з конкретною особою. FHE (CRISP) шифрує самі голоси, розкриваючи лише загальний результат."
                                : "Because the tax ID has low entropy (10 digits — brute-forceable in seconds), it is protected with OPRF — a protocol that adds a cryptographic salt to the tax ID without revealing it to the server. This makes the nullifier brute-force-resistant and safe for the registry. OPRF also provides unlinkability: neither the platform nor the blockchain can link a vote to a specific person. FHE (CRISP) encrypts the votes themselves, revealing only the aggregate result."}
                        </p>
                    </div>
                </div>

                {/* Механізми */}
                <div className="how-grid" style={{ marginTop: 56 }}>
                    <div className="how-card">
                        <span className="how-card__n mono">{uk ? "ІПН" : "TAX ID"}</span>
                        <h3 className="how-card__title">{uk ? "Незмінний якір" : "An immutable anchor"}</h3>
                        <p className="how-card__body">{uk ? "Податковий номер не змінюється все життя. Один громадянин — один nullifier, який не обнулити перевипуском документів." : "A tax ID doesn't change for a lifetime. One citizen — one nullifier that can't be reset by reissuing documents."}</p>
                    </div>
                    <div className="how-card">
                        <span className="how-card__n mono">OPRF</span>
                        <h3 className="how-card__title">{uk ? "Сіль без розкриття" : "Salt without disclosure"}</h3>
                        <p className="how-card__body">{uk ? "Oblivious PRF додає криптографічну сіль до ІПН, не показуючи його ані платформі, ані блокчейну. Перебрати 10 цифр стає неможливо, а голос — не пов'язати з особою." : "An Oblivious PRF adds a cryptographic salt to the tax ID without showing it to the platform or the blockchain. Brute-forcing 10 digits becomes impossible, and a vote can't be linked to a person."}</p>
                    </div>
                    <div className="how-card">
                        <span className="how-card__n mono">FHE</span>
                        <h3 className="how-card__title">{uk ? "Зашифрований підрахунок" : "Encrypted tally"}</h3>
                        <p className="how-card__body">{uk ? "Гомоморфне шифрування (CRISP) шифрує самі голоси й розкриває лише загальний результат — окремий голос не побачить ніхто." : "Homomorphic encryption (CRISP) encrypts the votes themselves and reveals only the aggregate result — no one sees an individual vote."}</p>
                    </div>
                </div>

                {/* Порівняння */}
                <div style={{ marginTop: 56 }}>
                    <span className="eyebrow">{uk ? "Порівняння" : "Comparison"}</span>
                    <p className="about-lede" style={{ marginTop: 16 }}>
                        {uk
                            ? "Civic Voice — єдине рішення, яке одночасно гарантує верифікацію особи, унікальність, приватність голосу та перевірюваний результат."
                            : "Civic Voice is the only solution that simultaneously guarantees identity verification, uniqueness, vote privacy and a verifiable result."}
                    </p>
                </div>
                <table className="cmp-table">
                    <thead>
                        <tr>
                            <th />
                            <th>{uk ? "Соцмережі · опитування" : "Social polls"}</th>
                            <th>{uk ? "Крипто-рішення" : "Crypto solutions"}</th>
                            <th className="cmp-cv">Civic Voice</th>
                        </tr>
                    </thead>
                    <tbody>
                        {[
                            { label: uk ? "Верифікація особи" : "Identity verification", vals: ["✕", "✓", "✓"] },
                            { label: uk ? "Унікальність · 1 особа — 1 голос" : "Uniqueness · 1 person — 1 vote", vals: ["✕", "✕", "✓"] },
                            { label: "Unlinkability", vals: ["✕", "✓", "✓"] },
                            { label: uk ? "Приватність голосу" : "Vote privacy", vals: ["✕", "✕", "✓"] },
                            { label: uk ? "Перевірюваний результат" : "Verifiable result", vals: ["✕", "✓", "✓"] },
                        ].map((row, i) => (
                            <tr key={i}>
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
            </div>

            {/* ── Команда ── */}
            <div className="about-section-block">
                <span className="eyebrow">{uk ? "Команда" : "Team"}</span>
                <div className="team-grid" style={{ marginTop: 32 }}>
                    {([1, 2] as const).map((n) => (
                        <div key={n} className="team-card">
                            <div>
                                <h3 className="team-card__name">{t(`about.team${n}name`)}</h3>
                                <p className="team-card__role">{t(`about.team${n}role`)}</p>
                            </div>
                            <p className="team-card__desc">{t(`about.team${n}desc`)}</p>
                        </div>
                    ))}
                </div>
            </div>

        </section>
    );
}
