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

-- Per-epoch p7s replay cache (task #31). One row per distinct .p7s
-- envelope observed at /oprf/blind-eval. PRIMARY KEY on the SHA-256
-- gives us atomic INSERT-OR-IGNORE semantics for TOCTOU-free dedupe.
CREATE TABLE IF NOT EXISTS p7s_replay_cache (
    p_hash    BLOB PRIMARY KEY NOT NULL,   -- 32 bytes, sha256(p7sBytes)
    seen_at   INTEGER NOT NULL             -- unix seconds (UTC)
);

CREATE INDEX IF NOT EXISTS p7s_replay_cache_by_seen_at
    ON p7s_replay_cache (seen_at);

-- Per-RNOKPP blind-eval counter (task #32). subject_hash is
-- sha256(subjectSerial) — we never store the plaintext RNOKPP.
CREATE TABLE IF NOT EXISTS blind_eval_counts (
    subject_hash  BLOB PRIMARY KEY NOT NULL,
    count         INTEGER NOT NULL,
    first_seen    INTEGER NOT NULL          -- unix seconds (UTC)
);

CREATE INDEX IF NOT EXISTS blind_eval_counts_by_first_seen
    ON blind_eval_counts (first_seen);
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

    /**
     * Atomically record a p7s hash in the per-epoch replay cache.
     *
     * Returns `true` if this hash had not been seen yet (the insert won),
     * `false` if it was already present (replay — caller must reject).
     *
     * Atomicity: INSERT OR IGNORE collapses check + insert into a single
     * SQL statement; `stmt.run().changes` is 1 on a fresh insert and 0
     * when the PRIMARY KEY on `p_hash` blocked it. No TOCTOU window.
     */
    recordP7sHashIfFresh(pHash: Uint8Array, seenAt: number): boolean {
        const stmt = this.db.prepare(
            `INSERT OR IGNORE INTO p7s_replay_cache (p_hash, seen_at)
             VALUES (?, ?)`,
        );
        const info = stmt.run(Buffer.from(pHash), seenAt);
        return info.changes === 1;
    }

    /** Drop p7s replay rows older than `olderThan` (unix seconds). */
    prunePAhsReplayCache(olderThan: number): number {
        const info = this.db
            .prepare(`DELETE FROM p7s_replay_cache WHERE seen_at < ?`)
            .run(olderThan);
        return Number(info.changes);
    }

    /**
     * Increment the per-RNOKPP blind-eval counter and return the new value.
     *
     * Uses ON CONFLICT to keep the increment + insert atomic. `first_seen`
     * is set on initial insert and not touched on subsequent updates;
     * cleanup uses `first_seen` so a single sliding-TTL eviction works.
     */
    incrementBlindEvalCount(
        subjectHash: Uint8Array,
        now: number,
    ): { count: number; firstSeen: number } {
        const sh = Buffer.from(subjectHash);
        // We do this in a transaction so the increment and the SELECT-back
        // happen against the same DB snapshot. better-sqlite3 transactions
        // are synchronous, which matches our handler shape.
        const txn = this.db.transaction(() => {
            this.db
                .prepare(
                    `INSERT INTO blind_eval_counts (subject_hash, count, first_seen)
                     VALUES (?, 1, ?)
                     ON CONFLICT(subject_hash) DO UPDATE SET count = count + 1`,
                )
                .run(sh, now);
            const row = this.db
                .prepare(
                    `SELECT count AS c, first_seen AS f
                     FROM blind_eval_counts WHERE subject_hash = ?`,
                )
                .get(sh) as { c: number; f: number };
            return { count: row.c, firstSeen: row.f };
        });
        return txn();
    }

    /** Drop blind-eval counter rows older than `olderThan` (unix seconds). */
    pruneBlindEvalCounts(olderThan: number): number {
        const info = this.db
            .prepare(`DELETE FROM blind_eval_counts WHERE first_seen < ?`)
            .run(olderThan);
        return Number(info.changes);
    }

    close(): void {
        this.db.close();
    }
}
