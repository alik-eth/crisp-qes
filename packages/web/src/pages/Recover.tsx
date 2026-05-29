import { Link } from "wouter";

interface Props {
    onDone: () => Promise<void>;
}

// v2 recovery, two paths:
//
//   1. Passkey re-unlock — if the encrypted vault is still on this device
//      (you only locked / signed out, didn't wipe), a Passkey assertion
//      decrypts it. No Diia needed.
//   2. Diia recovery — on a wiped device or a new one, re-present your Diia
//      QES. The OPRF is deterministic on your RNOKPP, so it re-derives the
//      SAME anonymous commitment you enrolled with; we fetch the existing
//      Merkle leaf's path and rebuild the local vault under a fresh Passkey.
//      No new on-chain leaf is created.
//
// Honest tradeoff (surfaced in the copy below): because recovery needs only
// a fresh Diia signature, anyone who can make your Diia sign can restore —
// and sign — as you. That capability is inherent to "Diia QES = eligibility
// anchor" (control of the QES already lets someone derive your secret and
// sign at the protocol level); the recovery flow just makes it convenient.
// v3 yearly epoch rotation bounds the blast radius (a fresh epoch retires
// the old identity).
//
// See [[project-recovery-design]] and docs/specs/2026-05-29-crisp-qes-v2-
// refined.md §3.4 / §3.5.

export function Recover({ onDone: _onDone }: Props) {
    return (
        <section className="verify">
            <div className="detail__crumbs">
                <Link href="/petitions">← All petitions</Link>
            </div>

            <h1>Lost access?</h1>
            <p className="muted" style={{ marginTop: 8, maxWidth: 560 }}>
                There are two ways back, depending on what you still have.
            </p>

            <div className="card" style={{ marginTop: 24 }}>
                <h3>1 · Same device — just unlock with your Passkey</h3>
                <p style={{ marginTop: 12 }}>
                    If you only signed out (and didn't wipe), your encrypted
                    vault is still on this device. Sign in with your Passkey
                    and it unlocks instantly — no Diia step needed.
                </p>
                <p className="muted small" style={{ marginTop: 12 }}>
                    If your Passkey lives in a cloud-synced manager (iCloud
                    Keychain, 1Password, Bitwarden, Google Password Manager),
                    it follows you to a new device too — but the vault itself
                    doesn't sync, so on a fresh device use option 2.
                </p>
            </div>

            <div className="card" style={{ marginTop: 16 }}>
                <h3>2 · New or wiped device — recover with Diia</h3>
                <p style={{ marginTop: 12 }}>
                    Set up a Passkey, then run{" "}
                    <Link href="/verify">Verify with Diia</Link> again. The OPRF
                    re-derives the same anonymous identity you enrolled with, we
                    pull your existing on-chain leaf, and your account is
                    restored on this device. No new enrollment, no duplicate
                    identity, no extra transaction.
                </p>
                <Link
                    href="/verify"
                    className="btn btn--primary"
                    style={{ marginTop: 16 }}
                >
                    Recover with Diia
                </Link>
            </div>

            <div className="card" style={{ marginTop: 16 }}>
                <h3>The honest tradeoff</h3>
                <p style={{ marginTop: 12 }}>
                    Diia recovery needs only a fresh Diia signature — so anyone
                    who can make your Diia sign can restore, and sign, as you.
                    That isn't new: your Diia QES is the eligibility anchor, and
                    whoever controls it can already derive your signing secret.
                    Recovery just makes that convenient instead of manual.
                </p>
                <p className="muted small" style={{ marginTop: 12 }}>
                    Guard your Diia the way you guard your passport. v3's yearly
                    epoch rotation bounds the blast radius: a fresh{" "}
                    <span className="mono">epoch_2027</span> retires the old
                    identity, so a compromise can't follow you across years.
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
