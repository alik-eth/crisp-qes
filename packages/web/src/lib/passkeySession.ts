// In-memory cache of the WebAuthn PRF output for the lifetime of this tab.
//
// We never persist the PRF output anywhere. After the user gestures once,
// we keep it in a module-level variable so subsequent encrypted-vault
// reads don't re-prompt the Passkey. Closing the tab wipes it.
//
// This module also offers a tiny pub/sub so components can re-render when
// the session unlocks/locks.

let prfOutput: Uint8Array | null = null;
let vault: SessionVault | null = null;
const listeners = new Set<() => void>();

function emit() {
    for (const fn of listeners) fn();
}

export interface SessionVault {
    /** The Pedersen-derived secret (also the on-chain commitment = leaf). */
    enrollmentSecret: `0x${string}`;
    /** Merkle path siblings from leaf to root. */
    merklePath: `0x${string}`[];
    /** Per-level direction bits (0/1). */
    merklePathIndices: number[];
    /** Leaf index inside the EnrollmentRegistry tree. */
    leafIndex: number;
    /** Passkey credentialId the vault row was wrapped with. */
    credentialId: `0x${string}`;
}

export function setSessionVault(v: SessionVault): void {
    vault = v;
    emit();
}

export function getSessionVault(): SessionVault | null {
    return vault;
}

export function clearSessionVault(): void {
    vault = null;
    emit();
}

export function setSessionPrf(output: Uint8Array): void {
    prfOutput = output;
    emit();
}

export function clearSessionPrf(): void {
    if (prfOutput) prfOutput.fill(0);
    prfOutput = null;
    vault = null;
    emit();
}

export function getSessionPrf(): Uint8Array | null {
    return prfOutput;
}

export function isSessionUnlocked(): boolean {
    return prfOutput !== null;
}

export function subscribePrfSession(fn: () => void): () => void {
    listeners.add(fn);
    return () => {
        listeners.delete(fn);
    };
}
