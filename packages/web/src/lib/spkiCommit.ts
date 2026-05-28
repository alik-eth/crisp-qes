// Mirror of packages/lotl-flattener/src/ca/spkiCommit.ts.
//
// We need to recompute the leaf SPKI commit on the client to match the
// uploaded certificate against the LOTL manifest's leaves. Constants MUST
// match the flattener — see comments in that file.

import { BarretenbergSync, Fr } from "@aztec/bb.js";

const SPKI_COMMIT_DOMAIN = 1;
const MAX_SPKI_BYTES = 1024;
const SPKI_CHUNK_BYTES = 31;
const SPKI_FULL_CHUNKS = 33;
const SPKI_NUM_CHUNKS = 34;

function packBE(chunk: Uint8Array): bigint {
    let acc = 0n;
    for (let i = 0; i < chunk.length; i++) acc = (acc << 8n) | BigInt(chunk[i]!);
    return acc;
}

export async function spkiCommit(spkiDer: Uint8Array): Promise<bigint> {
    if (spkiDer.length === 0) throw new Error("spkiCommit: empty SPKI");
    if (spkiDer.length > MAX_SPKI_BYTES) {
        throw new Error(
            `spkiCommit: SPKI length ${spkiDer.length} exceeds ${MAX_SPKI_BYTES}`,
        );
    }
    const padded = new Uint8Array(MAX_SPKI_BYTES);
    padded.set(spkiDer, 0);

    const fields = new Array<Fr>(SPKI_NUM_CHUNKS);
    for (let c = 0; c < SPKI_FULL_CHUNKS; c++) {
        const start = c * SPKI_CHUNK_BYTES;
        fields[c] = new Fr(packBE(padded.subarray(start, start + SPKI_CHUNK_BYTES)));
    }
    fields[SPKI_FULL_CHUNKS] = new Fr(BigInt(padded[MAX_SPKI_BYTES - 1]!));

    const api = await BarretenbergSync.initSingleton();
    const out = api.pedersenHash(fields, SPKI_COMMIT_DOMAIN);
    const hex = out.toString();
    return BigInt(hex);
}
