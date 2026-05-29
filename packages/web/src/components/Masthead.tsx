import { Link, useLocation } from "wouter";
import { useTranslation } from "react-i18next";
import type { AccountState } from "../lib/account.js";
import { shortId } from "../lib/account.js";

interface Props {
    state: AccountState;
    onSignInRequest: () => void;
    onChipClick: () => void;
}

export function Masthead({ state, onSignInRequest, onChipClick }: Props) {
    const [location] = useLocation();
    const { t, i18n } = useTranslation();

    const navItem = (path: string, label: string) => {
        const active =
            path === "/petitions"
                ? location === "/petitions" || location.startsWith("/p/")
                : location === path;
        return (
            <Link
                href={path}
                className={active ? "is-active" : undefined}
                aria-current={active ? "page" : undefined}
            >
                {label}
            </Link>
        );
    };

    const currentLang = i18n.language;

    return (
        <header className="masthead--bar">
            <Link href="/" className="brandbox">
                <span className="brandbox__mark" aria-hidden="true" />
                CRISP-QES
            </Link>
            <nav className="topnav" aria-label="Primary">
                {navItem("/petitions", t("nav.petitions"))}
            </nav>
            <div className="topnav__right">
                <div className="langseg" role="radiogroup" aria-label="Language">
                    <button
                        type="button"
                        className={`langseg__opt${currentLang === "uk" ? " is-active" : ""}`}
                        aria-checked={currentLang === "uk"}
                        onClick={() => void i18n.changeLanguage("uk")}
                    >
                        UA
                    </button>
                    <button
                        type="button"
                        className={`langseg__opt${currentLang === "en" ? " is-active" : ""}`}
                        aria-checked={currentLang === "en"}
                        onClick={() => void i18n.changeLanguage("en")}
                    >
                        EN
                    </button>
                </div>
                {state.kind === "guest" ? (
                    <button
                        type="button"
                        className="btn btn--sm"
                        onClick={onSignInRequest}
                    >
                        Sign in
                    </button>
                ) : (
                    <AccountChip state={state} onClick={onChipClick} />
                )}
            </div>
        </header>
    );
}

function AccountChip({
    state,
    onClick,
}: {
    state: AccountState;
    onClick: () => void;
}) {
    const dotClass =
        state.kind === "verified"
            ? "chip__dot chip__dot--verified"
            : "chip__dot chip__dot--account";
    const label = state.kind === "verified" ? "Verified" : "Not verified";
    const id = state.commitment ?? state.credentialId;
    return (
        <button type="button" className="chip" onClick={onClick}>
            <span className={dotClass} aria-hidden="true" />
            <span>{label}</span>
            {id ? <span className="chip__id">{shortId(id)}</span> : null}
        </button>
    );
}
