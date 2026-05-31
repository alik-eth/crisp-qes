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

            {/* ── Наш стек ── */}
            <div className="about-section-block">
                <span className="micro" style={{ marginBottom: 12, display: "block" }}>{uk ? "Наш стек" : "Our stack"}</span>
                <div className="sol-stack-grid">
                    <div>
                        <span className="sol-stack-label">{uk ? "Авторизація" : "Authorization"}</span>
                        <p className="sol-stack mono">КЕП (eIDAS) · CAdES-BES .p7s · ECDSA P-256 · Longfellow (ZK, Sumcheck+Ligero, WASM)</p>
                    </div>
                    <div>
                        <span className="sol-stack-label">{uk ? "Голосування" : "Voting"}</span>
                        <p className="sol-stack mono">Interfold (CRISP) · FHE · Noirlang (Aztec) · Barretenberg UltraHonk · Solidity</p>
                    </div>
                </div>
            </div>

            {/* ── Дорожня карта ── */}
            <div className="about-section-block">
                <span className="eyebrow">{uk ? "Дорожня карта" : "Roadmap"}</span>
                <div className="roadmap">
                    <div className="roadmap__phase roadmap__phase--done">
                        <div className="roadmap__head">
                            <span className="micro">{uk ? "v2 · готово" : "v2 · done"}</span>
                            <span className="roadmap__status">{uk ? "Працює сьогодні" : "Works today"}</span>
                        </div>
                        <ul className="roadmap__list">
                            <li>{uk ? "Ідентифікація через КЕП — розбір .p7s, перевірка ECDSA P-256 над signedAttrs, кореневий ZK-доказ (поточно на бекенді, cert→signedAttrs)" : "QES identification — .p7s parsing, ECDSA P-256 over signedAttrs verification, root ZK proof (currently on backend)"}</li>
                            <li>{uk ? "ZK-доказ у браузері (Noir + Barretenberg UltraHonk) — Merkle-доказ + nullifier" : "ZK proof in browser (Noir + Barretenberg UltraHonk) — Merkle proof + nullifier"}</li>
                            <li>{uk ? "OPRF (Blindswap) для захисту РНОКПП — M = HKDF(РНОКПП), операція blind, детермінований протидублікат через Sybil" : "OPRF (Blindswap) for tax ID protection — M = HKDF(RNOKPP), blind operation, deterministic anti-Sybil"}</li>
                            <li>{uk ? "Bound-challenge enrollment — UX «РНОКПП → чекбокс + підпис у ДІ + upload»" : "Bound-challenge enrollment — UX flow"}</li>
                            <li>{uk ? "Вікова верифікація 18+ in-circuit (DOB із SubjectDirectoryAttributes)" : "Age verification 18+ in-circuit (DOB from SubjectDirectoryAttributes)"}</li>
                            <li>{uk ? "Смарт-контракти PetitionRegistryV2, міграція на Base Sepolia (gas ~>1000 газоміни)" : "PetitionRegistryV2 smart contracts, migration to Base Sepolia"}</li>
                            <li>{uk ? "Walletless (relayer без криптогаманців), локалізація UK / EN" : "Walletless (relayer, no crypto wallets), UK/EN localization"}</li>
                            <li>{uk ? "Демо: crisp-qes-web.fly.dev" : "Demo: crisp-qes-web.fly.dev"}</li>
                        </ul>
                    </div>
                    <div className="roadmap__phase">
                        <div className="roadmap__head">
                            <span className="micro">{uk ? "v3 · в роботі" : "v3 · in progress"}</span>
                            <span className="roadmap__status">{uk ? "У роботі" : "In progress"}</span>
                        </div>
                        <ul className="roadmap__list">
                            <li>{uk ? "Перехід enrollment на Longfellow — один доказ: cert → шлях до Diia CA → РНОКПП → 18+ → M → DLEQ → unblind → s" : "Enrollment transition to Longfellow — single proof: cert → path to CA → tax ID → 18+ → M → DLEQ → unblind → s"}</li>
                            <li>{uk ? "Перевірка ланцюга сертифіката до кореня (Diia QTSP CA в системних cross-trust anchors)" : "Certificate chain verification to root (QTSP CA in system cross-trust anchors)"}</li>
                            <li>{uk ? "P-256 OPRF in-circuit (RFC 9393: SSW) — expand_message_xmd + новий hash_to_curve + variable-base scalar-mul P + DLEQ (Chaum-Pedersen) + unblind" : "P-256 OPRF in-circuit (RFC 9393: SSW)"}</li>
                            <li>{uk ? "FHE (CRISP / Interfold) — шифрування голосів, тільки підрахунок" : "FHE (CRISP / Interfold) — vote encryption, tally only"}</li>
                            <li>{uk ? "Реєстр K_pub (поки OPRF) on-chain" : "K_pub registry (OPRF for now) on-chain"}</li>
                            <li>{uk ? "Допрацювання дизайну сайту" : "Site design improvements"}</li>
                            <li>{uk ? "Тестування та виправлення помилок" : "Testing and bug fixes"}</li>
                        </ul>
                    </div>
                    <div className="roadmap__phase">
                        <div className="roadmap__head">
                            <span className="micro">{uk ? "Далі" : "Next"}</span>
                            <span className="roadmap__status">{uk ? "Заплановано" : "Planned"}</span>
                        </div>
                        <ul className="roadmap__list">
                            <li>{uk ? "UI / UX: фільтри по країнах, категоріях, статусу" : "UI/UX: filters by country, category, status"}</li>
                            <li>{uk ? "КЕП інших країн EC (eIDAS) — єдина схема на кралну (pan-eIDAS, variable-length serialNumber), кожна перевірка свій trust-list" : "QES from other EU countries (eIDAS) — unified per-country scheme, each with own trust-list"}</li>
                            <li>{uk ? "Вікова верифікація (18+) для окремих країн" : "Age verification (18+) for individual countries"}</li>
                            <li>{uk ? "Мобільний додаток (наразі iOS — Rust-prover через uniffi, поки натівний WASM-out на Safari)" : "Mobile app (iOS — Rust-prover via uniffi, native WASM-out on Safari)"}</li>
                            <li>{uk ? "Офлайн-голосування" : "Offline voting"}</li>
                            <li>{uk ? "SDK для інтеграції з сторонніми сервісами" : "SDK for integration with third-party services"}</li>
                            <li>{uk ? "Аудит криптографії" : "Cryptography audit"}</li>
                            <li>{uk ? "Додатковий аналіз і можливий перехід на zkID" : "Additional analysis and possible transition to zkID"}</li>
                            <li>{uk ? "Аналіз і можлива імплементація більш user-friendly вимог до створення голосувань (альтернатива депозиту 0.001 ETH)" : "Analysis and possible implementation of more user-friendly poll creation requirements (alternative to 0.001 ETH deposit)"}</li>
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
