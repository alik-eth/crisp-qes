// Browser shim for the small surface of `node:crypto` the SDK touches.
//
// The SDK was originally Node-targeted and uses `createHash("sha256")` for
// the in-browser p7s parser. We map that to @noble/hashes/sha256 which is
// already in viem's transitive closure and works in workers without any
// global Buffer requirement.

import { sha256 } from "@noble/hashes/sha256";

type Bufferish = Uint8Array | ArrayBuffer | string;

function toBytes(data: Bufferish): Uint8Array {
    if (typeof data === "string") return new TextEncoder().encode(data);
    if (data instanceof Uint8Array) return data;
    return new Uint8Array(data);
}

class HashAdapter {
    #chunks: Uint8Array[] = [];

    update(data: Bufferish): this {
        this.#chunks.push(toBytes(data));
        return this;
    }

    digest(): Uint8Array {
        const total = this.#chunks.reduce((n, c) => n + c.byteLength, 0);
        const all = new Uint8Array(total);
        let off = 0;
        for (const c of this.#chunks) {
            all.set(c, off);
            off += c.byteLength;
        }
        // Node's `Buffer` extends Uint8Array; the SDK only ever wraps the
        // digest in `new Uint8Array(...)` so a plain Uint8Array satisfies it.
        return sha256(all);
    }
}

export function createHash(algorithm: string): HashAdapter {
    if (algorithm !== "sha256") {
        throw new Error(`node-crypto shim: unsupported hash algorithm ${algorithm}`);
    }
    return new HashAdapter();
}

export default { createHash };
