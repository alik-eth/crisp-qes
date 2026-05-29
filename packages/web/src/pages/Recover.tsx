import { Link } from "wouter";

interface Props {
    onDone: () => Promise<void>;
}

// v2 has no within-protocol recovery. Re-running OPRF on a re-presented
// Diia QES would give the same anonymous identity (the math allows it),
// but that means anyone with a stolen QES can sign as the citizen — OPRF
// can't distinguish them. We refuse to advertise that path.
//
// The only v2 recovery is Passkey cloud sync (iCloud Keychain, 1Password,
// Bitwarden Premium, etc) — handled transparently by the OS/extension
// without any UI from us. v3 introduces yearly epoch rotation as the
// universal recovery primitive.
//
// See [[project-recovery-design]] and docs/specs/2026-05-29-crisp-qes-v2-
// refined.md §3.4 / §3.5.

export function Recover({ onDone: _onDone }: Props) {
    return (
        <section className="verify">
            <div className="detail__crumbs">
                <Link href="/petitions">← All petitions</Link>
            </div>

            <h1>Lost your device?</h1>
            <p className="muted" style={{ marginTop: 8, maxWidth: 560 }}>
                Honest answer: there's no recovery button here, and that's
                by design.
            </p>

            <div className="card" style={{ marginTop: 24 }}>
                <h3>Use Passkey cloud sync</h3>
                <p style={{ marginTop: 12 }}>
                    Your Passkey is the only way back into your account. If
                    you created it inside a password manager that syncs
                    Passkeys — iCloud Keychain, 1Password, Bitwarden, Google
                    Password Manager — log into that manager on the new
                    device and your Passkey will reappear there. Then come
                    back here and sign in normally.
                </p>
                <p className="muted small" style={{ marginTop: 12 }}>
                    Hardware-key Passkeys (YubiKey and similar) only live on
                    that one key. If you lost the key itself, see the next
                    section.
                </p>
            </div>

            <div className="card" style={{ marginTop: 16 }}>
                <h3>Why we don't offer a "recover with Diia" button</h3>
                <p style={{ marginTop: 12 }}>
                    Re-running OPRF on the same Diia QES would deterministically
                    yield the same anonymous identity — that's how the math
                    works. But it would also let anyone holding a stolen Diia
                    signature recover the same identity and sign as you.
                    OPRF can't tell the two cases apart.
                </p>
                <p style={{ marginTop: 12 }}>
                    Advertising "recovery via Diia" is the same as advertising
                    "lose your QES to anyone and they become you." So we
                    don't. The state's Diia recovery process is the floor:
                    anyone who can re-issue Diia through state channels gets
                    a fresh identity at the next yearly epoch rotation
                    (shipping in v3).
                </p>
            </div>

            <div className="card" style={{ marginTop: 16 }}>
                <h3>If you have neither</h3>
                <p style={{ marginTop: 12 }}>
                    No Passkey cloud sync, no hardware key, no fresh Diia
                    QES on a new device — you wait for the next epoch.
                    During v2 you're locked out; from v3, you re-enroll with
                    a fresh Diia QES in <span className="mono">epoch_2026</span>{" "}
                    and your old anonymous identity simply retires.
                </p>
                <p className="muted small" style={{ marginTop: 12 }}>
                    Yes — this is honestly worse than a typical app, and
                    honestly better than the alternative (a recovery button
                    that doubles as a takeover button for anyone with your
                    QES).
                </p>
            </div>

            <hr className="hairline" />

            <p className="muted small">
                References: <span className="mono">docs/specs/2026-05-29-crisp-qes-v2-refined.md</span>{" "}
                §3.4 / §3.5, and{" "}
                <span className="mono">docs/specs/2026-05-29-crisp-qes-v3-funded-scope.md</span>{" "}
                §6.
            </p>
        </section>
    );
}
