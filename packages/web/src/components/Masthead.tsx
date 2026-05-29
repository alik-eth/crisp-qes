import { Link, useLocation } from "wouter";
import type { AccountState } from "../lib/account.js";
import { shortId } from "../lib/account.js";

interface Props {
    state: AccountState;
    onSignInRequest: () => void;
    onChipClick: () => void;
}

export function Masthead({ state, onSignInRequest, onChipClick }: Props) {
    const [location] = useLocation();
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

    return (
        <header className="masthead">
            <div className="masthead__inner">
                <div className="masthead__brand">
                    <Link href="/" className="masthead__logo">
                        CRISP-QES
                    </Link>
                    <nav className="masthead__nav" aria-label="Primary">
                        {navItem("/petitions", "Petitions")}
                    </nav>
                </div>
                <div className="masthead__right">
                    {state.kind === "guest" ? (
                        <button
                            type="button"
                            className="btn btn--primary btn--sm"
                            onClick={onSignInRequest}
                        >
                            Sign in
                        </button>
                    ) : (
                        <AccountChip state={state} onClick={onChipClick} />
                    )}
                </div>
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
