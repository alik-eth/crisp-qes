// CAdES (.p7s) parsing surface — to port from identityescroworg.
// See docs/specs/2026-05-19-crisp-qes-pivot-design.md §3 (reused components).

export interface ParsedP7s {
    /** Raw signedAttrs bytes — input to ECDSA verify. */
    signedAttrs: Uint8Array;
    /** SHA-256(messageDigest) attribute from signedAttrs. */
    messageDigest: Uint8Array;
    /** Signer cert subject serial bytes (must start with "TINUA-"). */
    subjectSerial: Uint8Array;
    /** Leaf cert DER bytes. */
    leafCertDer: Uint8Array;
    /** Intermediate cert DER bytes (if present in the SignedData). */
    intermediateCertDer: Uint8Array | null;
    /** P-256 pubkey affine coordinates from the leaf cert. */
    pubkey: { x: bigint; y: bigint };
    /** ECDSA signature on signedAttrs. */
    signature: { r: bigint; s: bigint };
}

export function parseP7s(_bytes: Uint8Array): ParsedP7s {
    throw new Error("parseP7s: not implemented — port from identityescroworg");
}
