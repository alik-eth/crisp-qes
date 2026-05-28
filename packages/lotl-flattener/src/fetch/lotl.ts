// LOTL pointer parser, ported from identityescroworg.
//
// In the CRISP-QES MVP we only support local-file inputs to the flattener:
// the live LOTL fetch / XMLDSig path is intentionally out of scope here. The
// expected workflow is to snapshot a known LOTL bundle offline, sign-check
// it out-of-band, and feed the .xml into this flattener.

import { XMLParser } from "fast-xml-parser";

export interface LotlPointer {
  territory: string;
  location: string;
  mimeType: string;
  x509CertificateList: Uint8Array[];
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  removeNSPrefix: true,
});

const asArray = <T>(v: T | T[] | undefined): T[] =>
  v === undefined ? [] : Array.isArray(v) ? v : [v];

const decodeB64 = (b64: string): Uint8Array => {
  const clean = b64.replace(/\s+/g, "");
  return Uint8Array.from(Buffer.from(clean, "base64"));
};

const parsePointerCerts = (p: Record<string, unknown>): Uint8Array[] => {
  const identities = asArray<Record<string, unknown>>(
    (p.ServiceDigitalIdentities as Record<string, unknown> | undefined)?.ServiceDigitalIdentity as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  const out: Uint8Array[] = [];
  for (const identity of identities) {
    const digitalIds = asArray<Record<string, unknown>>(
      identity.DigitalId as Record<string, unknown> | Record<string, unknown>[] | undefined,
    );
    for (const did of digitalIds) {
      const cert = did.X509Certificate;
      if (typeof cert === "string") out.push(decodeB64(cert));
    }
  }
  return out;
};

const parsePointerInfo = (
  p: Record<string, unknown>,
): Pick<LotlPointer, "territory" | "mimeType"> => {
  const otherInfo = asArray<Record<string, unknown>>(
    (p.AdditionalInformation as Record<string, unknown> | undefined)?.OtherInformation as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  const findString = (key: string): string => {
    for (const info of otherInfo) {
      const value = info[key];
      if (typeof value === "string") return value;
    }
    return "";
  };
  return {
    territory: findString("SchemeTerritory"),
    mimeType: findString("MimeType"),
  };
};

const isTrustedListPointer = (p: LotlPointer): boolean =>
  Boolean(p.territory) &&
  p.territory !== "EU" &&
  Boolean(p.location) &&
  (!p.mimeType || p.mimeType === "application/vnd.etsi.tsl+xml");

export function parseLotl(xml: string): LotlPointer[] {
  const doc = parser.parse(xml);
  const tsl = doc?.TrustServiceStatusList;
  if (!tsl) throw new Error("not a LOTL: missing TrustServiceStatusList");
  const raw = tsl?.SchemeInformation?.PointersToOtherTSL?.OtherTSLPointer ?? [];
  const arr = Array.isArray(raw) ? raw : [raw];
  return arr
    .map((p: Record<string, unknown>) => {
      const info = parsePointerInfo(p);
      return {
        territory: info.territory,
        location: String(p?.TSLLocation ?? ""),
        mimeType: info.mimeType,
        x509CertificateList: parsePointerCerts(p),
      };
    })
    .filter(isTrustedListPointer);
}
