// Account state machine + IndexedDB-backed credential persistence.
//
// State derives from two stores:
//   accounts     — { credentialId, supportsPRF, createdAt }
//   enrollments  — encryptedStore.ts vault rows (Verified-state material)
//
// Guest     : no `accounts` row
// Account   : `accounts` row, no `enrollments` row
// Verified  : `accounts` row AND at least one `enrollments` row
//
// The `accounts` row carries only the credentialId (so we can target the
// right Passkey on assertion) plus a boolean recording that the
// authenticator surfaced a PRF output at registration time. Nothing
// sensitive lives here.

import { useEffect, useState, useCallback } from "react";
import { listEnrollments } from "./encryptedStore.js";

const DB_NAME = "crisp_qes_v2";
const DB_VERSION = 2; // bumped from 1 to add `accounts` store
const STORE_ACCOUNTS = "accounts";
const STORE_ENROLLMENTS = "enrollments";

export interface AccountRow {
    credentialId: `0x${string}`;
    supportsPRF: boolean;
    createdAt: number;
}

function openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE_ENROLLMENTS)) {
                db.createObjectStore(STORE_ENROLLMENTS, {
                    keyPath: "id",
                    autoIncrement: true,
                });
            }
            if (!db.objectStoreNames.contains(STORE_ACCOUNTS)) {
                db.createObjectStore(STORE_ACCOUNTS, {
                    keyPath: "credentialId",
                });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export async function putAccount(row: AccountRow): Promise<void> {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_ACCOUNTS, "readwrite");
        const req = tx.objectStore(STORE_ACCOUNTS).put(row);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

export async function getAccount(): Promise<AccountRow | null> {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_ACCOUNTS, "readonly");
        const req = tx.objectStore(STORE_ACCOUNTS).getAll();
        req.onsuccess = () => {
            const rows = req.result as AccountRow[];
            resolve(rows[0] ?? null);
        };
        req.onerror = () => reject(req.error);
    });
}

export async function clearAccount(): Promise<void> {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE_ACCOUNTS, "readwrite");
        const req = tx.objectStore(STORE_ACCOUNTS).clear();
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

export type AccountKind = "guest" | "account" | "verified";

export interface AccountState {
    kind: AccountKind;
    credentialId: `0x${string}` | null;
    commitment: `0x${string}` | null;
}

export async function readAccountState(): Promise<AccountState> {
    let account = await getAccount();
    const enrollments = await listEnrollments();

    // Legacy users (enrolled before the 4-action rewrite) have an
    // `enrollments` row but no `accounts` row. The credentialId we'd
    // store in `accounts` is recorded on the enrollment row already,
    // so lift it across once and treat them as Verified.
    if (!account && enrollments.length > 0) {
        const latest = enrollments[enrollments.length - 1]!;
        const row: AccountRow = {
            credentialId: latest.credentialId,
            supportsPRF: true,
            createdAt: Date.now(),
        };
        try {
            await putAccount(row);
            account = row;
        } catch {
            // If the write fails, fall through to the Guest branch —
            // worst case the user re-registers.
        }
    }

    if (!account) return { kind: "guest", credentialId: null, commitment: null };
    if (enrollments.length === 0) {
        return { kind: "account", credentialId: account.credentialId, commitment: null };
    }
    return {
        kind: "verified",
        credentialId: account.credentialId,
        commitment: enrollments[0]!.commitment,
    };
}

export function useAccountState(): {
    state: AccountState;
    loading: boolean;
    refresh: () => Promise<void>;
} {
    const [state, setState] = useState<AccountState>({
        kind: "guest",
        credentialId: null,
        commitment: null,
    });
    const [loading, setLoading] = useState(true);

    const refresh = useCallback(async () => {
        const next = await readAccountState();
        setState(next);
        setLoading(false);
    }, []);

    useEffect(() => {
        void refresh();
    }, [refresh]);

    return { state, loading, refresh };
}

// Short-id rendering for the masthead chip: `0x1b49…cd84`.
export function shortId(hex: `0x${string}` | null): string {
    if (!hex) return "";
    if (hex.length <= 12) return hex;
    return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
}
