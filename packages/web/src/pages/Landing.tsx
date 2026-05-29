import { useEffect, useState } from "react";
import { Link } from "wouter";
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
                <h1 className="hero__title">
                    Anonymous citizen petitions, verified by Diia.
                </h1>
                <p className="hero__sub">
                    Sign Ukrainian petitions without revealing who you are.
                    The chain cannot link your signature to your identity.
                </p>
                <div className="hero__cta">
                    <Link href="/petitions" className="btn btn--primary">
                        Browse petitions
                    </Link>
                    {state.kind === "guest" ? (
                        <button
                            type="button"
                            className="btn btn--ghost"
                            onClick={onSignIn}
                        >
                            Sign in or register
                        </button>
                    ) : state.kind === "account" ? (
                        <Link href="/verify" className="btn btn--ghost">
                            Verify with QES
                        </Link>
                    ) : null}
                </div>
            </div>

            <div className="stats" role="status" aria-live="polite">
                {stats ? (
                    <>
                        <Stat n={stats.citizens} label="citizens verified" />
                        <span className="stats__sep" aria-hidden="true">·</span>
                        <Stat n={stats.petitions} label="petitions" />
                        <span className="stats__sep" aria-hidden="true">·</span>
                        <Stat n={stats.signatures} label="signatures" />
                        <span className="stats__live">live · Sepolia</span>
                    </>
                ) : statsErr ? (
                    <span className="muted small">Chain data unavailable.</span>
                ) : (
                    <span className="muted small">Loading on-chain stats…</span>
                )}
            </div>

            <div className="how">
                <h2>How it works</h2>
                <ol className="how__list">
                    <li>
                        <span className="how__n">1</span>
                        <div>
                            <strong>Verify with Diia QES, once.</strong>{" "}
                            Your qualified electronic signature proves
                            you're a real Ukrainian adult. The verifier
                            never learns who you are on the chain.
                        </div>
                    </li>
                    <li>
                        <span className="how__n">2</span>
                        <div>
                            <strong>A Passkey on this device locks your private key.</strong>{" "}
                            Nothing sensitive leaves the browser. No password,
                            no seed phrase to lose.
                        </div>
                    </li>
                    <li>
                        <span className="how__n">3</span>
                        <div>
                            <strong>Sign petitions anonymously.</strong>{" "}
                            Only a nullifier reaches the chain — enough to
                            prevent double-signing, not enough to identify you.
                        </div>
                    </li>
                </ol>
            </div>
        </section>
    );
}

function Stat({ n, label }: { n: number; label: string }) {
    return (
        <span className="stat">
            <span className="stat__n">{n.toLocaleString("en-US")}</span>
            <span className="stat__label">{label}</span>
        </span>
    );
}
