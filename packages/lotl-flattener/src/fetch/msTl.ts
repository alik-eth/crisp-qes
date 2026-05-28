import { XMLParser } from 'fast-xml-parser';

export interface QualificationCriteria {
  assert?: string;
  keyUsageBits: string[];
  policyIdentifiers: string[];
}

export interface QualificationElement {
  qualifiers: string[];
  criteria: QualificationCriteria;
}

export interface RawService {
  territory: string;
  tspName?: string;
  serviceName?: string;
  serviceTypeIdentifier: string;
  status: string;
  statusStartingTime: number;
  statusEndingTime?: number;
  x509CertificateList: Uint8Array[];
  qualifiers: string[];
  qualificationElements: QualificationElement[];
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
});

const asArray = <T>(v: T | T[] | undefined): T[] =>
  v === undefined ? [] : Array.isArray(v) ? v : [v];

const decodeB64 = (b64: string): Uint8Array => {
  const clean = b64.replace(/\s+/g, '');
  return Uint8Array.from(Buffer.from(clean, 'base64'));
};

const toEpochSeconds = (iso: string): number => {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.floor(t / 1000) : 0;
};

const readLocalizedName = (v: unknown): string | undefined => {
  const names = asArray<Record<string, unknown>>(
    (v as Record<string, unknown> | undefined)?.Name as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  const en = names.find((n) => n['@_lang'] === 'en' || n['@_xml:lang'] === 'en');
  const picked = en ?? names[0];
  if (!picked) return undefined;
  const text = picked['#text'];
  return typeof text === 'string' ? text : String(picked);
};

const parseCerts = (state: Record<string, unknown>): Uint8Array[] => {
  const digitalIds = asArray<Record<string, unknown>>(
    (state.ServiceDigitalIdentity as Record<string, unknown> | undefined)?.DigitalId as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  const certs: Uint8Array[] = [];
  for (const did of digitalIds) {
    const x509 = did.X509Certificate;
    if (typeof x509 === 'string') certs.push(decodeB64(x509));
    else if (Array.isArray(x509)) {
      for (const c of x509) if (typeof c === 'string') certs.push(decodeB64(c));
    }
  }
  return certs;
};

const readText = (v: unknown): string | undefined => {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (v && typeof v === 'object') {
    const text = (v as Record<string, unknown>)['#text'];
    if (text !== undefined) return readText(text);
  }
  return undefined;
};

const parseKeyUsageBits = (criteria: Record<string, unknown> | undefined): string[] => {
  const bits = asArray<Record<string, unknown>>(
    (criteria?.KeyUsage as Record<string, unknown> | undefined)?.KeyUsageBit as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  return bits
    .filter((bit) => readText(bit) === 'true')
    .map((bit) => String(bit['@_name'] ?? ''))
    .filter(Boolean)
    .sort();
};

const parsePolicyIdentifiers = (criteria: Record<string, unknown> | undefined): string[] => {
  const policySets = asArray<Record<string, unknown>>(
    criteria?.PolicySet as Record<string, unknown> | Record<string, unknown>[] | undefined,
  );
  const out: string[] = [];
  for (const policySet of policySets) {
    const identifiers = asArray<Record<string, unknown>>(
      policySet.PolicyIdentifier as Record<string, unknown> | Record<string, unknown>[] | undefined,
    );
    for (const policyIdentifier of identifiers) {
      const value = readText((policyIdentifier.Identifier as unknown) ?? policyIdentifier);
      if (value) out.push(value);
    }
  }
  return [...new Set(out)].sort();
};

const parseQualificationElements = (state: Record<string, unknown>): QualificationElement[] => {
  const extensions = asArray<Record<string, unknown>>(
    (state.ServiceInformationExtensions as Record<string, unknown> | undefined)?.Extension as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  const out: QualificationElement[] = [];
  for (const ext of extensions) {
    const elements = asArray<Record<string, unknown>>(
      (ext.Qualifications as Record<string, unknown> | undefined)?.QualificationElement as
        | Record<string, unknown>
        | Record<string, unknown>[]
        | undefined,
    );
    for (const el of elements) {
      const qualifiers = asArray<Record<string, unknown>>(
        (el.Qualifiers as Record<string, unknown> | undefined)?.Qualifier as
          | Record<string, unknown>
          | Record<string, unknown>[]
          | undefined,
      );
      const qualifierUris: string[] = [];
      for (const q of qualifiers) {
        const uri = readText(q.QualifierUri) ?? readText(q['@_uri']);
        if (uri) qualifierUris.push(uri);
      }
      const criteria = el.CriteriaList as Record<string, unknown> | undefined;
      out.push({
        qualifiers: [...new Set(qualifierUris)].sort(),
        criteria: {
          ...(typeof criteria?.['@_assert'] === 'string' ? { assert: criteria['@_assert'] } : {}),
          keyUsageBits: parseKeyUsageBits(criteria),
          policyIdentifiers: parsePolicyIdentifiers(criteria),
        },
      });
    }
  }
  return out;
};

const parseAdditionalServiceInformationUris = (state: Record<string, unknown>): string[] => {
  const extensions = asArray<Record<string, unknown>>(
    (state.ServiceInformationExtensions as Record<string, unknown> | undefined)?.Extension as
      | Record<string, unknown>
      | Record<string, unknown>[]
      | undefined,
  );
  const out: string[] = [];
  for (const ext of extensions) {
    const uris = asArray<unknown>(
      (ext.AdditionalServiceInformation as Record<string, unknown> | undefined)?.URI as
        | unknown
        | unknown[]
        | undefined,
    );
    for (const uri of uris) {
      const value = readText(uri);
      if (value) out.push(value);
    }
  }
  return [...new Set(out)].sort();
};

const flattenQualifiers = (
  elements: QualificationElement[],
  additionalUris: string[],
): string[] => {
  const out = new Set<string>();
  for (const el of elements) for (const q of el.qualifiers) out.add(q);
  for (const q of additionalUris) out.add(q);
  return [...out].sort();
};

const toServiceState = (
  info: Record<string, unknown>,
  context: { territory: string; tspName?: string },
): Omit<RawService, 'statusEndingTime'> => {
  const serviceName = readLocalizedName(info.ServiceName);
  const qualificationElements = parseQualificationElements(info);
  const additionalUris = parseAdditionalServiceInformationUris(info);
  return {
    territory: context.territory,
    ...(context.tspName ? { tspName: context.tspName } : {}),
    ...(serviceName ? { serviceName } : {}),
    serviceTypeIdentifier: String(info.ServiceTypeIdentifier ?? ''),
    status: String(info.ServiceStatus ?? ''),
    statusStartingTime: toEpochSeconds(String(info.StatusStartingTime ?? '')),
    x509CertificateList: parseCerts(info),
    qualifiers: flattenQualifiers(qualificationElements, additionalUris),
    qualificationElements,
  };
};

export function parseMsTl(xml: string): RawService[] {
  const doc = parser.parse(xml);
  const tsl = doc?.TrustServiceStatusList;
  if (!tsl?.TrustServiceProviderList) {
    throw new Error('not a Member State trusted list: missing TrustServiceProviderList');
  }
  const territory = String(tsl?.SchemeInformation?.SchemeTerritory ?? '');
  const tsps = asArray<Record<string, unknown>>(tsl.TrustServiceProviderList.TrustServiceProvider);
  const out: RawService[] = [];
  for (const tsp of tsps) {
    const tspName = readLocalizedName(
      (tsp.TSPInformation as Record<string, unknown> | undefined)?.TSPName,
    );
    const context = {
      territory,
      ...(tspName ? { tspName } : {}),
    };
    const services = asArray<Record<string, unknown>>(
      (tsp.TSPServices as Record<string, unknown> | undefined)?.TSPService as
        | Record<string, unknown>
        | Record<string, unknown>[]
        | undefined,
    );
    for (const svc of services) {
      const info = svc.ServiceInformation as Record<string, unknown> | undefined;
      if (!info) continue;

      const states = [
        toServiceState(info, context),
        ...asArray<Record<string, unknown>>(
          (svc.ServiceHistory as Record<string, unknown> | undefined)?.ServiceHistoryInstance as
            | Record<string, unknown>
            | Record<string, unknown>[]
            | undefined,
        ).map((h) => toServiceState(h, context)),
      ].sort((a, b) => a.statusStartingTime - b.statusStartingTime);

      for (const [i, state] of states.entries()) {
        const next = states[i + 1];
        out.push({
          ...state,
          ...(next?.statusStartingTime
            ? { statusEndingTime: Math.max(0, next.statusStartingTime - 1) }
            : {}),
        });
      }
    }
  }
  return out;
}
