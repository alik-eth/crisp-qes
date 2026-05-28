// SQLite-backed enrolled-commitment store.
//
// Schema is intentionally tiny: one row per (commitment, leafIndex) plus a
// generic key-value table so the boot path can stamp the current root and
// the OPRF public key. The Merkle tree is *not* persisted as a structure —
// we rebuild it from the ordered commitment list on boot. At 2^20 leaves
// that rebuild costs O(N) Pedersen hashes on bb.js wasm (~hundreds of µs
// each), which is well within a one-shot boot budget. v2.1-prod will swap
// this for an incremental subtree-cache.

import Database, { type Database as DB } from "better-sqlite3";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS enrolled (
    commitment   TEXT PRIMARY KEY NOT NULL,   -- 0x-prefixed 32-byte hex
    leaf_index   INTEGER NOT NULL UNIQUE,
    enrolled_at  INTEGER NOT NULL,            -- unix seconds (UTC)
    blinded_in   TEXT NOT NULL                -- 0x-prefixed 32-byte hex
);

CREATE INDEX IF NOT EXISTS enrolled_by_leaf_index
    ON enrolled (leaf_index);

CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY NOT NULL,
    v TEXT NOT NULL
);
`;

export interface EnrolledRow {
    commitment: `0x${string}`;
    leafIndex: number;
    enrolledAt: number;
    blindedInput: `0x${string}`;
}

export class EnrollmentStore {
    private readonly db: DB;

    constructor(path: string) {
        this.db = new Database(path);
        this.db.pragma("journal_mode = WAL");
        this.db.pragma("synchronous = NORMAL");
        this.db.exec(SCHEMA);
    }

    /** Append a new commitment in a single transaction. Throws on collision. */
    insert(row: EnrolledRow): void {
        const stmt = this.db.prepare(
            `INSERT INTO enrolled (commitment, leaf_index, enrolled_at, blinded_in)
             VALUES (?, ?, ?, ?)`,
        );
        stmt.run(row.commitment, row.leafIndex, row.enrolledAt, row.blindedInput);
    }

    has(commitment: `0x${string}`): boolean {
        const row = this.db
            .prepare(`SELECT 1 AS one FROM enrolled WHERE commitment = ? LIMIT 1`)
            .get(commitment) as { one: number } | undefined;
        return row !== undefined;
    }

    leafIndexFor(commitment: `0x${string}`): number | null {
        const row = this.db
            .prepare(`SELECT leaf_index AS i FROM enrolled WHERE commitment = ?`)
            .get(commitment) as { i: number } | undefined;
        return row?.i ?? null;
    }

    /** All commitments in insertion order (leaf_index ASC). */
    allInOrder(): `0x${string}`[] {
        const rows = this.db
            .prepare(
                `SELECT commitment FROM enrolled ORDER BY leaf_index ASC`,
            )
            .all() as { commitment: `0x${string}` }[];
        return rows.map((r) => r.commitment);
    }

    count(): number {
        const row = this.db
            .prepare(`SELECT COUNT(*) AS n FROM enrolled`)
            .get() as { n: number };
        return row.n;
    }

    /** Next leaf_index = current count (slots are 0-indexed and dense). */
    nextLeafIndex(): number {
        return this.count();
    }

    kvGet(key: string): string | null {
        const row = this.db
            .prepare(`SELECT v FROM kv WHERE k = ?`)
            .get(key) as { v: string } | undefined;
        return row?.v ?? null;
    }

    kvSet(key: string, value: string): void {
        this.db
            .prepare(
                `INSERT INTO kv (k, v) VALUES (?, ?)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
            )
            .run(key, value);
    }

    close(): void {
        this.db.close();
    }
}
