// Ported verbatim from identityescroworg/packages/lotl-flattener — the
// ETSI/Diia service taxonomy doesn't change between the two projects, only
// the downstream hash family does.

import type { RawService } from "../fetch/msTl.js";

export type { RawService };

const SVC_CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
const UA_SVC_CA_QC = "http://czo.gov.ua/TrstSvc/Svctype/CA/QC";
const UA_SVC_MR_CA_QC = "http://czo.gov.ua/TrstSvc/Svctype/MR-CA/QC";
const STATUS_GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
const UA_STATUS_GRANTED = "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted";
const QC_FOR_ESIG = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig";
const QC_FOR_ESEAL = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal";
const QC_FOR_LEGAL_PERSON =
  "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson";
const FORE_SIGNATURES = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures";
const FORE_SEALS = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals";

const isSignatureQualified = (s: RawService): boolean => {
  const explicitEsig =
    s.qualifiers.includes(QC_FOR_ESIG) || s.qualifiers.includes(FORE_SIGNATURES);
  if (explicitEsig) return true;
  if (
    s.qualifiers.includes(QC_FOR_ESEAL) ||
    s.qualifiers.includes(QC_FOR_LEGAL_PERSON) ||
    s.qualifiers.includes(FORE_SEALS)
  ) {
    return false;
  }
  return (
    s.qualificationElements.length === 0 ||
    s.qualificationElements.some((el) => el.criteria.keyUsageBits.includes("nonRepudiation"))
  );
};

const isCaQcService = (s: RawService): boolean =>
  s.serviceTypeIdentifier === SVC_CA_QC ||
  s.serviceTypeIdentifier === UA_SVC_CA_QC ||
  s.serviceTypeIdentifier === UA_SVC_MR_CA_QC;

const isGranted = (s: RawService): boolean =>
  s.status === STATUS_GRANTED || s.status === UA_STATUS_GRANTED;

export function filterQes(services: RawService[]): RawService[] {
  return services.filter(
    (s) =>
      isCaQcService(s) &&
      isGranted(s) &&
      s.x509CertificateList.length > 0 &&
      isSignatureQualified(s),
  );
}
