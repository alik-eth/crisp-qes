// Small byte-level DER helpers used by the .p7s parser.
//
// We use these to walk leaf-cert internals (find SPKI bytes, find subject
// serialNumber RDN VALUE bytes, find SKI extension contents) without paying
// the pkijs object-graph cost for those targeted lookups, and to keep the
// behaviour deterministic across pkijs minor versions.

/** Read an ASN.1 length encoding starting at `der[off]`. */
export function readDerLength(
    der: Uint8Array,
    off: number,
): { headerLen: number; contentLen: number } {
    const b0 = der[off];
    if (b0 === undefined) {
        throw new Error(`asn1: out-of-bounds length read at offset ${off}`);
    }
    if (b0 < 0x80) return { headerLen: 1, contentLen: b0 };
    const n = b0 & 0x7f;
    if (n === 0 || n > 4) {
        throw new Error(
            `asn1: unsupported DER length form 0x${b0.toString(16)} at offset ${off}`,
        );
    }
    let len = 0;
    for (let k = 1; k <= n; k++) {
        const byte = der[off + k];
        if (byte === undefined) {
            throw new Error(`asn1: truncated length bytes at offset ${off}`);
        }
        len = (len << 8) | byte;
    }
    return { headerLen: 1 + n, contentLen: len };
}

/** Equality check on `n` bytes of `a` starting at `aOff` against `b`. */
export function bytesEqAt(a: Uint8Array, aOff: number, b: Uint8Array): boolean {
    if (aOff + b.length > a.length) return false;
    for (let i = 0; i < b.length; i++) {
        if (a[aOff + i] !== b[i]) return false;
    }
    return true;
}

/** Find first occurrence of `needle` in `hay`. -1 if not found. */
export function indexOf(hay: Uint8Array, needle: Uint8Array): number {
    if (needle.length === 0) return 0;
    const last = hay.length - needle.length;
    outer: for (let i = 0; i <= last; i++) {
        for (let k = 0; k < needle.length; k++) {
            if (hay[i + k] !== needle[k]) continue outer;
        }
        return i;
    }
    return -1;
}
