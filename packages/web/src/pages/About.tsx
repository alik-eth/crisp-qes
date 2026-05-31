import { useTranslation } from "react-i18next";
import { CoverageGrid } from "../components/CoverageGrid.js";

export function About() {
    const { t, i18n } = useTranslation();
    const uk = i18n.language === "uk";

    return (
        <section className="about-page">

            {/* ── Про проєкт ── */}
            <div className="about-hero">
                <span className="eyebrow">{uk ? "Про проєкт" : "About"}</span>
                <p className="about-hero__lede">
                    {uk
                        ? "Civic Voice — відкритий сервіс, створений для того, щоб дізнатись приватну, анонімну громадську думку з будь-якого питання і бути впевненим, що в голосуванні брали участь повнолітні громадяни, а результати є публічними і їх неможливо змінити."
                        : "Civic Voice is an open service built to learn private, anonymous public opinion on any question — and to be sure that the participants were adult citizens, while the results are public and impossible to alter."}
                </p>
                <p className="about-hero__lede" style={{ marginTop: 16 }}>
                    {uk
                        ? "Ми поєднуємо ідентифікацію за допомогою КЕП з криптографією нульового розголошення, щоб ніхто — ні організатор, ні платформа, ні будь-яка третя сторона — не міг дізнатись, хто і як проголосував. Результати доступні кожному в публічному розподіленому реєстрі (блокчейн), де їх неможливо змінити, видалити чи сфальсифікувати. Код проєкту відкритий, щоб кожен міг перевірити, що система працює саме так, як заявлено. Результати голосувань не мають юридичних наслідків і є інструментом для проведення громадських опитувань."
                        : "We combine QES identification with zero-knowledge cryptography so that no one — neither the organiser, nor the platform, nor any third party — can learn who voted or how. Results are available to everyone in a public distributed ledger (blockchain), where they cannot be changed, deleted or forged. The project's code is open so anyone can verify the system works exactly as claimed. Voting results have no legal consequences and are a tool for conducting public polls."}
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
                                ? "Платформа доступна кожному, хто має кваліфікований електронний підпис (КЕП) — це громадяни України та 27 країн Європейського Союзу відповідно до регламенту eIDAS."
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

            {/* ── Технологія ── */}
            <div className="about-section-block">
                <span className="eyebrow">{uk ? "Технологія · Простими словами" : "Technology · In simple terms"}</span>
                <h2 className="about-h2">{uk ? "Справжня приватність — це математика." : "Real privacy is mathematics."}</h2>
                <div className="how-grid" style={{ marginTop: 40 }}>
                    {([1, 2, 3, 4] as const).map((n) => (
                        <div key={n} className="how-card">
                            <h3 className="how-card__title">{t(`landing.tech${n}title`)}</h3>
                            <p className="how-card__body">{t(`landing.tech${n}body`)}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* ── Дорожня карта ── */}
            <div className="about-section-block">
                <span className="eyebrow">{uk ? "Дорожня карта" : "Roadmap"}</span>
                <h2 className="about-h2">{uk ? "Найризикованіше ми вже зробили." : "The riskiest part is already done."}</h2>
                <div className="roadmap">
                    <div className="roadmap__phase roadmap__phase--done">
                        <div className="roadmap__head">
                            <span className="micro">{uk ? "v2 · готово" : "v2 · done"}</span>
                            <span className="roadmap__status">{uk ? "Працює сьогодні" : "Works today"}</span>
                        </div>
                        <h3 className="how-card__title">{uk ? "Анонімний голос на блокчейні" : "Anonymous vote on-chain"}</h3>
                        <ul className="roadmap__list">
                            <li>{uk ? "Ідентифікація через КЕП → ZK-доказ → запис у відкритий реєстр" : "QES identification → ZK proof → record in open registry"}</li>
                            <li>{uk ? "Без MetaMask, без розкриття особи" : "No MetaMask, no identity disclosure"}</li>
                            <li>{uk ? "Перша демо-петиція підписана on-chain" : "First demo petition signed on-chain"}</li>
                        </ul>
                    </div>
                    <div className="roadmap__phase">
                        <div className="roadmap__head">
                            <span className="micro">{uk ? "v3 · в роботі" : "v3 · in progress"}</span>
                            <span className="roadmap__status">{uk ? "У роботі" : "In progress"}</span>
                        </div>
                        <h3 className="how-card__title">{uk ? "Стійкість до примусу та покращення" : "Coercion resistance & improvements"}</h3>
                        <ul className="roadmap__list">
                            <li>{uk ? "FHE (CRISP) — зашифрований підрахунок голосів" : "FHE (CRISP) — encrypted vote tally"}</li>
                            <li>{uk ? "Захист від примусу за схемою JCJ" : "Coercion protection via JCJ scheme"}</li>
                            <li>{uk ? "Допрацювання дизайну сайту" : "Site design improvements"}</li>
                            <li>{uk ? "Тестування та виправлення помилок" : "Testing and bug fixes"}</li>
                        </ul>
                    </div>
                    <div className="roadmap__phase">
                        <div className="roadmap__head">
                            <span className="micro">{uk ? "Далі" : "Next"}</span>
                            <span className="roadmap__status">{uk ? "Заплановано" : "Planned"}</span>
                        </div>
                        <h3 className="how-card__title">{uk ? "Масштаб і незалежність" : "Scale and independence"}</h3>
                        <ul className="roadmap__list">
                            <li>{uk ? "Аудит криптографії" : "Cryptography audit"}</li>
                            <li>{uk ? "Додатковий аналіз і можливий перехід на zkID" : "Additional analysis and possible transition to zkID"}</li>
                            <li>{uk ? "Аналіз і можлива імплементація більш user-friendly вимог до створення голосувань (альтернатива депозиту 0.001 ETH)" : "Analysis and possible implementation of more user-friendly poll creation requirements (alternative to 0.001 ETH deposit)"}</li>
                            <li>{uk ? "Підтримка інших надавачів КЕП та європейських eIDAS-провайдерів" : "Support for other QES providers and European eIDAS providers"}</li>
                        </ul>
                    </div>
                </div>
            </div>

            {/* ── Команда ── */}
            <div className="about-section-block">
                <span className="eyebrow">{uk ? "Команда" : "Team"}</span>
                <div className="team-grid" style={{ marginTop: 32 }}>
                    {([
                        { n: 1, x: "https://x.com/alik_eth_" },
                        { n: 2, x: "https://x.com/dorgo_eth" },
                    ] as const).map(({ n, x }) => (
                        <div key={n} className="team-card">
                            <div>
                                <h3 className="team-card__name">{t(`about.team${n}name`)}</h3>
                                <p className="team-card__role">{t(`about.team${n}role`)}</p>
                                <a href={x} target="_blank" rel="noreferrer" className="team-card__x">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
                                    <span>@{t(`about.team${n}name`).replace(".eth", "_eth")}</span>
                                </a>
                            </div>
                            <p className="team-card__desc">{t(`about.team${n}desc`)}</p>
                        </div>
                    ))}
                </div>
            </div>

        </section>
    );
}
