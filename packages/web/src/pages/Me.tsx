import { useEffect, useState, useCallback } from "react";
import { Link, useLocation } from "wouter";
import type { AccountState } from "../lib/account.js";
import { clearAccount, shortId } from "../lib/account.js";
import { listEnrollments, clearAll as clearEnrollments } from "../lib/encryptedStore.js";
import { clearSessionPrf, getSessionVault } from "../lib/passkeySession.js";
import { unlockVault } from "../lib/unlock.js";
import {
    readAllPetitions,
    readHasNullifier,
    type PetitionView,
} from "../lib/registry.js";
import { pedersenNullifier } from "../lib/pedersen.js";

interface Props {
    state: AccountState;
    refresh: () => Promise<void>;
}

interface DeviceFacts {
    credentialId: `0x${string}`;
    commitment: `0x${string}` | null;
    leafIndex: number | null;
    enrolledAt: number | null;
}

export function Me({ state, refresh }: Props) {
    const [, navigate] = useLocation();
    const [facts, setFacts] = useState<DeviceFacts | null>(null);
    const [signingOut, setSigningOut] = useState(false);
    const [confirmOut, setConfirmOut] = useState(false);

    useEffect(() => {
        let alive = true;
        void (async () => {
            if (!state.credentialId) return;
            const enrollments = await listEnrollments();
            if (!alive) return;
            const latest = enrollments[enrollments.length - 1];
            setFacts({
                credentialId: state.credentialId,
                commitment: latest?.commitment ?? null,
                leafIndex: latest?.leafIndex ?? null,
                enrolledAt: null,
            });
        })();
        return () => {
            alive = false;
        };
    }, [state.credentialId]);

    const [sigStage, setSigStage] = useState<
        "idle" | "unlocking" | "scanning" | "loaded" | "error"
    >("idle");
    const [signed, setSigned] = useState<PetitionView[]>([]);
    const [sigErr, setSigErr] = useState<string | null>(null);

    const scanSignatures = useCallback(async () => {
        if (state.kind !== "verified") return;
        setSigErr(null);
        try {
            setSigStage("unlocking");
            const v = getSessionVault() ?? (await unlockVault());
            setSigStage("scanning");
            const petitions = await readAllPetitions();
            const flags = await Promise.all(
                petitions.map(async (p) => {
                    const n = await pedersenNullifier(
                        v.enrollmentSecret,
                        p.id,
                    );
                    return readHasNullifier(p.id, n).catch(() => false);
                }),
            );
            const mine = petitions.filter((_, i) => flags[i]);
            setSigned(mine);
            setSigStage("loaded");
        } catch (e) {
            setSigErr(e instanceof Error ? e.message : String(e));
            setSigStage("error");
        }
    }, [state.kind]);

    const signOut = async () => {
        setSigningOut(true);
        try {
            clearSessionPrf();
            await clearEnrollments();
            await clearAccount();
            await refresh();
            navigate("/");
        } finally {
            setSigningOut(false);
        }
    };

    return (
        <section className="me">
            <h1>Account</h1>
            <p className="muted" style={{ marginTop: 8, marginBottom: 24 }}>
                Local-only. This page lives entirely on this device.
            </p>

            {state.kind === "account" ? (
                <div className="notice notice--info" style={{ marginBottom: 20 }}>
                    <div>
                        Your Passkey is set up, but you haven't verified with
                        Diia QES yet. You can browse petitions, but signing
                        and creating require verification.{" "}
                        <Link href="/verify">Verify now →</Link>
                    </div>
                </div>
            ) : null}

            <dl className="detail__facts">
                <div className="fact">
                    <dt>Status</dt>
                    <dd>
                        <span
                            className={
                                state.kind === "verified"
                                    ? "badge badge--ok"
                                    : "badge"
                            }
                            style={{ marginRight: 8 }}
                        >
                            {state.kind === "verified"
                                ? "Verified"
                                : "Registered"}
                        </span>
                    </dd>
                </div>
                {state.commitment ? (
                    <div className="fact">
                        <dt>Anonymous identity</dt>
                        <dd className="mono">{shortId(state.commitment)}</dd>
                    </div>
                ) : null}
                {facts?.leafIndex !== null && facts?.leafIndex !== undefined ? (
                    <div className="fact">
                        <dt>Enrollment leaf</dt>
                        <dd className="mono">#{facts.leafIndex}</dd>
                    </div>
                ) : null}
                {facts?.credentialId ? (
                    <div className="fact">
                        <dt>Passkey credential</dt>
                        <dd className="mono">{shortId(facts.credentialId)}</dd>
                    </div>
                ) : null}
            </dl>

            {facts?.commitment ? (
                <div style={{ marginTop: 24 }}>
                    <div className="muted small" style={{ marginBottom: 4 }}>
                        Full commitment
                    </div>
                    <div
                        className="mono"
                        style={{
                            wordBreak: "break-all",
                            padding: "12px 14px",
                            background: "var(--bg-elevated)",
                            border: "1px solid var(--rule)",
                            borderRadius: "var(--r-md)",
                            fontSize: 13,
                        }}
                    >
                        {facts.commitment}
                    </div>
                </div>
            ) : null}

            {state.kind === "verified" ? (
                <>
                    <hr className="hairline" />
                    <h2>Petitions you signed</h2>
                    <p className="muted small" style={{ marginTop: 8 }}>
                        Only you can compute this list. Nobody else — not
                        even us — can link your nullifiers to your identity.
                    </p>

                    {sigStage === "idle" ? (
                        <button
                            type="button"
                            className="btn btn--primary"
                            style={{ marginTop: 16 }}
                            onClick={() => void scanSignatures()}
                        >
                            {getSessionVault()
                                ? "Show my signatures"
                                : "Unlock and show my signatures"}
                        </button>
                    ) : sigStage === "unlocking" ? (
                        <div
                            className="progress-band"
                            style={{ marginTop: 16 }}
                        >
                            <span className="spinner" aria-hidden="true" />
                            <span className="small">
                                Waiting for your Passkey…
                            </span>
                        </div>
                    ) : sigStage === "scanning" ? (
                        <div
                            className="progress-band"
                            style={{ marginTop: 16 }}
                        >
                            <span className="spinner" aria-hidden="true" />
                            <span className="small">
                                Checking each petition on chain…
                            </span>
                        </div>
                    ) : sigStage === "error" ? (
                        <div
                            className="notice notice--bad"
                            style={{ marginTop: 16 }}
                        >
                            <div>
                                <strong>Couldn't load signatures.</strong>
                                <br />
                                <span className="small mono">{sigErr}</span>
                            </div>
                        </div>
                    ) : signed.length === 0 ? (
                        <p
                            className="muted"
                            style={{ marginTop: 16 }}
                        >
                            You haven't signed any petition yet.
                        </p>
                    ) : (
                        <ul
                            className="petitions"
                            style={{ marginTop: 16 }}
                        >
                            {signed.map((p) => (
                                <li key={p.id.toString()}>
                                    <Link
                                        href={`/p/${p.id.toString()}`}
                                        className="petitions__row"
                                    >
                                        <div className="petitions__main">
                                            <div className="petitions__title">
                                                #{p.id.toString()} ·{" "}
                                                {p.fullText
                                                    .split(/\r?\n/)[0]
                                                    ?.slice(0, 100) ||
                                                    "(untitled)"}
                                            </div>
                                            <div className="petitions__meta">
                                                <span className="muted">
                                                    {p.modeLabel ===
                                                    "Signature"
                                                        ? "Signature"
                                                        : "Vote"}
                                                </span>
                                                <span className="muted">·</span>
                                                <span className="muted">
                                                    {p.status}
                                                </span>
                                            </div>
                                        </div>
                                    </Link>
                                </li>
                            ))}
                        </ul>
                    )}
                </>
            ) : null}

            <hr className="hairline" />

            <h2>Recovery</h2>
            <p className="muted small" style={{ marginTop: 8 }}>
                The only v2 recovery is Passkey cloud sync (iCloud Keychain,
                1Password, Bitwarden, Google Password Manager). If your
                Passkey is in one of those, it will reappear on a new device
                when you sign in. We do NOT offer a "recover with Diia QES"
                flow — re-running OPRF would let anyone with a stolen QES
                sign as you. See{" "}
                <Link href="/recover">why &amp; what to do if you're stuck →</Link>
            </p>

            <hr className="hairline" />

            <h2 style={{ color: "var(--bad)" }}>Sign out</h2>
            <p className="muted small" style={{ marginTop: 8, marginBottom: 16 }}>
                Wipes your local vault and Passkey reference on this device.
                Your on-chain enrollment stays — you can recover with your
                Diia QES.
            </p>
            {!confirmOut ? (
                <button
                    type="button"
                    className="btn btn--ghost"
                    onClick={() => setConfirmOut(true)}
                >
                    Sign out of this device
                </button>
            ) : (
                <div className="row">
                    <button
                        type="button"
                        className="btn btn--primary"
                        style={{
                            background: "var(--bad)",
                        }}
                        onClick={() => void signOut()}
                        disabled={signingOut}
                    >
                        {signingOut ? "Signing out…" : "Yes, wipe local data"}
                    </button>
                    <button
                        type="button"
                        className="btn btn--ghost"
                        onClick={() => setConfirmOut(false)}
                        disabled={signingOut}
                    >
                        Cancel
                    </button>
                </div>
            )}
        </section>
    );
}
