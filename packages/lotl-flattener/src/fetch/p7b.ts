// CMS-SignedData (PKCS#7 `.p7b`) cert-bundle parser.
//
// `.p7b` is the wire format Diia publishes its trusted-CA bundle in
// (ca.diia.gov.ua/uploads/certificates/diia_ecdsa.p7b). It's a
// CMS-SignedData ContentInfo whose `certificates [0] IMPLICIT` field carries
// the certs we care about — `signerInfos` is empty (`.p7b` is the
// "cert-only" variant of PKCS#7 SignedData per RFC 5652 §10.2.2).
//
// We walk the DER by hand because the rest of `lotl-flattener` already
// avoids pulling in `asn1js` / `pkijs`; one self-contained walker keeps the
// dependency footprint minimal and the parse rules auditable.
//
// Structure walked (RFC 5652 §5.1, §10.2.2):
//
//   ContentInfo ::= SEQUENCE {
//     contentType OBJECT IDENTIFIER,    -- 1.2.840.113549.1.7.2 (signedData)
//     content     [0] EXPLICIT ANY
//   }
//   SignedData ::= SEQUENCE {
//     version          INTEGER,
//     digestAlgorithms SET,
//     encapContentInfo SEQUENCE,
//     certificates     [0] IMPLICIT SET OF Certificate OPTIONAL,
//     crls             [1] IMPLICIT ... OPTIONAL,
//     signerInfos      SET OF SignerInfo
//   }
//
// Each Certificate inside `certificates [0]` is itself a `SEQUENCE` (tag
// 0x30); we slice and return its DER bytes verbatim.

const OID_SIGNED_DATA: Uint8Array = new Uint8Array([
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
]);

interface TLV {
  /** ASN.1 tag byte. */
  tag: number;
  /** Byte offset of the start of the value (after tag + length header). */
  contentStart: number;
  /** Byte offset one past the end of the value. */
  contentEnd: number;
}

function readTLV(der: Uint8Array, off: number): TLV {
  if (off >= der.length) {
    throw new Error(`p7b: read past EOF at offset ${off}`);
  }
  const tag = der[off]!;
  const lenOff = off + 1;
  const b0 = der[lenOff];
  if (b0 === undefined) {
    throw new Error(`p7b: truncated length at offset ${off}`);
  }
  let headerLen: number;
  let contentLen: number;
  if (b0 < 0x80) {
    headerLen = 1;
    contentLen = b0;
  } else {
    const n = b0 & 0x7f;
    if (n === 0 || n > 4) {
      throw new Error(
        `p7b: unsupported DER length form 0x${b0.toString(16)} at offset ${lenOff}`,
      );
    }
    headerLen = 1 + n;
    let len = 0;
    for (let k = 1; k <= n; k++) {
      const by = der[lenOff + k];
      if (by === undefined) {
        throw new Error(`p7b: truncated multi-byte length at offset ${lenOff}`);
      }
      len = (len << 8) | by;
    }
    contentLen = len;
  }
  const contentStart = lenOff + headerLen;
  const contentEnd = contentStart + contentLen;
  if (contentEnd > der.length) {
    throw new Error(`p7b: TLV at offset ${off} extends past EOF`);
  }
  return { tag, contentStart, contentEnd };
}

function bytesEqAt(a: Uint8Array, off: number, b: Uint8Array): boolean {
  if (off + b.length > a.length) return false;
  for (let i = 0; i < b.length; i++) if (a[off + i] !== b[i]) return false;
  return true;
}

/**
 * Parse a binary CMS-SignedData `.p7b` blob and return the DER bytes of
 * every Certificate carried in the `certificates [0] IMPLICIT` field.
 *
 * Returns certs in the exact order they appear in the bundle (DER order).
 * Order matters: downstream Merkle leaf-index is the array index, so any
 * shuffling changes the trust root.
 */
export function parseP7b(der: Uint8Array): Uint8Array[] {
  // ContentInfo SEQUENCE
  const ci = readTLV(der, 0);
  if (ci.tag !== 0x30) {
    throw new Error(`p7b: outer is not SEQUENCE (got tag 0x${ci.tag.toString(16)})`);
  }
  // contentType OID — must be signedData
  if (!bytesEqAt(der, ci.contentStart, OID_SIGNED_DATA)) {
    throw new Error("p7b: contentType is not signedData (1.2.840.113549.1.7.2)");
  }
  let cur = ci.contentStart + OID_SIGNED_DATA.length;

  // content [0] EXPLICIT
  const exp = readTLV(der, cur);
  if (exp.tag !== 0xa0) {
    throw new Error(
      `p7b: expected [0] EXPLICIT content after contentType (got tag 0x${exp.tag.toString(16)})`,
    );
  }
  cur = exp.contentStart;

  // SignedData SEQUENCE
  const sd = readTLV(der, cur);
  if (sd.tag !== 0x30) {
    throw new Error("p7b: SignedData payload is not SEQUENCE");
  }
  cur = sd.contentStart;

  // version INTEGER
  const ver = readTLV(der, cur);
  if (ver.tag !== 0x02) {
    throw new Error("p7b: SignedData.version is not INTEGER");
  }
  cur = ver.contentEnd;

  // digestAlgorithms SET
  const da = readTLV(der, cur);
  if (da.tag !== 0x31) {
    throw new Error("p7b: SignedData.digestAlgorithms is not SET");
  }
  cur = da.contentEnd;

  // encapContentInfo SEQUENCE
  const eci = readTLV(der, cur);
  if (eci.tag !== 0x30) {
    throw new Error("p7b: encapContentInfo is not SEQUENCE");
  }
  cur = eci.contentEnd;

  // certificates [0] IMPLICIT (optional). If absent, return empty.
  if (cur >= sd.contentEnd) return [];
  const next = readTLV(der, cur);
  if (next.tag !== 0xa0) return [];

  const certs: Uint8Array[] = [];
  let ptr = next.contentStart;
  while (ptr < next.contentEnd) {
    const cert = readTLV(der, ptr);
    // RFC 5652 §10.2.2 also allows ExtendedCertificate / AttributeCertificate
    // tags in this SET; for `.p7b` cert bundles we only care about plain
    // X.509 Certificates (tag 0x30). Skip anything else silently.
    if (cert.tag === 0x30) {
      certs.push(der.slice(ptr, cert.contentEnd));
    }
    ptr = cert.contentEnd;
  }
  return certs;
}
