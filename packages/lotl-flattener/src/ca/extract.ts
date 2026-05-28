import { X509Certificate } from "node:crypto";
import type { RawService } from "../filter/qesServices.js";
import type { ExtractedCA } from "../types.js";

export function extractCAs(services: RawService[]): ExtractedCA[] {
  const out: ExtractedCA[] = [];
  for (const svc of services) {
    for (const der of svc.x509CertificateList) {
      const parsed = new X509Certificate(Buffer.from(der));
      out.push({
        certDer: der,
        subjectDN: parsed.subject,
        issuerDN: parsed.issuer,
        validFrom: Math.floor(Date.parse(parsed.validFrom) / 1000),
        validTo: Math.floor(Date.parse(parsed.validTo) / 1000),
        territory: svc.territory,
        ...(svc.tspName ? { tspName: svc.tspName } : {}),
        ...(svc.serviceName ? { serviceName: svc.serviceName } : {}),
        serviceStatus: svc.status,
        serviceValidFrom: svc.statusStartingTime,
        ...(svc.statusEndingTime ? { serviceValidTo: svc.statusEndingTime } : {}),
        qualifiers: svc.qualifiers,
        qualificationElements: svc.qualificationElements,
      });
    }
  }
  return out;
}
