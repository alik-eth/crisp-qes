import { useState, useEffect, useRef } from "react";
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
    const [menuOpen, setMenuOpen] = useState(false);
    const toggleRef = useRef<HTMLButtonElement>(null);
    const closeRef = useRef<HTMLButtonElement>(null);

    // Close on navigation.
    useEffect(() => {
        setMenuOpen(false);
    }, [location]);

    // Esc to close; lock body scroll; focus handling while open.
    useEffect(() => {
        if (!menuOpen) return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") setMenuOpen(false);
        };
        document.addEventListener("keydown", onKey);
        const prevOverflow = document.body.style.overflow;
        document.body.style.overflow = "hidden";
        closeRef.current?.focus();
        return () => {
            document.removeEventListener("keydown", onKey);
            document.body.style.overflow = prevOverflow;
            toggleRef.current?.focus();
        };
    }, [menuOpen]);

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

    const langSwitch = (
        <div className="langseg" role="radiogroup" aria-label={t("nav.language")}>
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
    );

    const account =
        state.kind === "guest" ? (
            <button
                type="button"
                className="btn btn--sm"
                onClick={onSignInRequest}
            >
                {t("nav.signIn")}
            </button>
        ) : (
            <AccountChip state={state} onClick={onChipClick} />
        );

    return (
        <header className="masthead--bar">
            <Link href="/" className="brandbox">
                <span className="brandbox__mark" aria-hidden="true" />
                CIVIC VOICE
            </Link>

            {/* Desktop / wide: inline nav + controls */}
            <div className="topnav__right">
                <nav className="topnav" aria-label="Primary">
                    {navItem("/petitions", t("nav.petitions"))}
                    {navItem("/about", t("footer.about"))}
                </nav>
                {langSwitch}
                {account}
            </div>

            {/* Mobile: hamburger toggle */}
            <button
                type="button"
                ref={toggleRef}
                className="navtoggle"
                aria-label={t("nav.menu")}
                aria-expanded={menuOpen}
                aria-controls="mobile-nav"
                onClick={() => setMenuOpen((v) => !v)}
            >
                <span className="navtoggle__bars" aria-hidden="true">
                    <span />
                    <span />
                    <span />
                </span>
            </button>

            {/* Mobile: overlay + slide-in drawer */}
            <div
                className={`navscrim${menuOpen ? " is-open" : ""}`}
                hidden={!menuOpen}
                onClick={() => setMenuOpen(false)}
            />
            {/* When closed on mobile the drawer is visibility:hidden (see
                styles.css), which removes its controls from the tab order and
                the a11y tree — so no aria-hidden (which would otherwise wrap
                focusable descendants) is needed. */}
            <nav
                id="mobile-nav"
                className={`navdrawer${menuOpen ? " is-open" : ""}`}
                aria-label={t("nav.menu")}
            >
                <div className="navdrawer__head">
                    <span className="navdrawer__title">{t("nav.menu")}</span>
                    <button
                        type="button"
                        ref={closeRef}
                        className="navdrawer__close"
                        aria-label={t("register.close")}
                        onClick={() => setMenuOpen(false)}
                    >
                        ×
                    </button>
                </div>
                <div className="navdrawer__links">
                    {navItem("/petitions", t("nav.petitions"))}
                    {navItem("/about", t("footer.about"))}
                </div>
                <div className="navdrawer__foot">
                    {langSwitch}
                    {account}
                </div>
            </nav>
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
    const { t } = useTranslation();
    const label = state.kind === "verified" ? t("nav.verified") : t("nav.notVerified");
    const id = state.commitment ?? state.credentialId;
    return (
        <button type="button" className="chip" onClick={onClick}>
            <span className={dotClass} aria-hidden="true" />
            <span>{label}</span>
            {id ? <span className="chip__id">{shortId(id)}</span> : null}
        </button>
    );
}
