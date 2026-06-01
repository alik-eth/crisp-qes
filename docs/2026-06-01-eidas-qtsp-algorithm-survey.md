# eIDAS / European QTSP signature-algorithm survey

> Which European QTSPs issue natural-person QES on **ECDSA P-256** (directly portable to crisp-qes' enrollment circuit) vs **RSA**. Companion to [reference_rsa_noir_gatecounts] (RSA-2048 verify is ~3.6x cheaper than ECDSA-P256 in-circuit, so RSA issuers are tractable too) and the multi-country per-circuit design.

<!-- Generated 2026-06-01 by a 31-country sonnet survey (eu-qtsp-algo-survey workflow).
Enumeration from EU Trusted Lists; algorithm column is CPS/cert-derived and mixed-confidence — "unknown"/low-confidence rows need manual CPS review. Not authoritative; a research aid for the multi-country/RSA porting decision. -->

## Method & Data Quality Note

This survey covers QTSPs from EU/EEA trust lists (eIDAS LOTL and national TSLs) plus Ukraine's cross-border TL, researched in May–June 2026. Trust lists enumerate QTSPs and their CA certificates but rarely encode the subscriber key algorithm directly; most algorithm data was derived from CPS/CP documents, CA certificate inspection (crt.sh / direct DER decode), or secondary sources. Quality therefore varies: high-confidence entries have explicit CPS section citations or DER-confirmed CA certs; medium-confidence entries rely on policy phrasing that implies but does not name the curve; low-confidence entries could not access a CPS at all. "Unknown" algorithm entries require manual CPS retrieval and review.

---

## Master Table

| Country | QTSP | Nat-person QES | ECDSA P-256 | RSA | QES cert algo/curve | Confidence |
|---------|------|:-:|:-:|:-:|---------------------|:-:|
| AT | A-Trust GmbH | ✅ | ✅ | ✅ | both: ECDSA P-256 + RSA ≥4096 | high |
| AT | e-commerce monitoring GmbH (GLOBALTRUST / TRUST2GO) | ✅ | ✅ | ✅ | both: RSA-4096 (GLOBALTRUST smartcard) + RSA-4096 or ECDSA P-256 (TRUST2GO remote) | high |
| AT | PrimeSign GmbH (CRYPTAS-PrimeSign) | ✅ | ✅ | ✅ | smartcard: ECDSA P-256 or P-384 (RSA not supported); remote: RSA-PSS 3072/4096 + ECDSA 256/384/512 | high |
| AT | Swisscom IT Services Finance S.E. | ✅ | ❌ | ✅ | RSA-3072 SHA-256 | high |
| AT | SwissSign GmbH | ✅ | ❌ | ✅ | RSA-3072 (RSASSA-PSS SHA-384); ECDSA P-521 exists but not offered to end users | high |
| BE | Certipost n.v./s.a. (Belgian eID BRCA3/4) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| BE | Kingdom of Belgium / BOSA (BRCA6 / eSign CA eID) | ✅ | ❌ | ❌ | ECDSA P-384 | high |
| BE | DigiCert Europe Belgium B.V. (itsme Sign) | ✅ | ✅ | ✅ | both: ECDSA P-256 + RSA-2048 | high |
| BE | Zetes S.A./N.V. (ZetesConfidens) | ✅ | ❌ | ✅ | RSA-2048 or RSA-3072 | high |
| BE | GlobalSign NV/SA | ✅ | ❌ | ✅ | both: ECDSA P-384 + RSA-4096 | high |
| BG | BORICA AD (B-Trust) | ✅ | ❌ | ✅ | RSA-2048/3072/4096 | high |
| BG | InfoNotary PLC | ✅ | ❓ | ✅ | RSA-2048/3072/4096; ECDSA-256 policy-allowed but not confirmed deployed | medium |
| BG | Information Services Plc. (StampIT) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| BG | Evrotrust Technologies JSC | ✅ | ❌ | ✅ | RSA-2048/3072/4096 | high |
| BG | eDocs Bulgaria EOOD | ✅ | ❓ | ❓ | unknown | low |
| CY | JCC Payment Systems Ltd. | ✅ | ❌ | ✅ | RSA-4096 SHA-256 | high |
| CZ | První certifikační autorita, a.s. (I.CA) | ✅ | ✅ | ✅ | both: ECDSA P-256 + P-384 (separate ECC policy) + RSA | high |
| CZ | Česká pošta, s.p. (PostSignum) | ✅ | ❌ | ✅ | RSA-2048 or RSA-4096 | high |
| CZ | eIdentity a.s. (ACAeID) | ✅ | ❌ | ✅ | RSA-2048 | medium |
| CZ | SSSVD / NCA | ✅ | ❌ | ✅ | ECDSA P-384 + RSA (public sector only) | high |
| CZ | Komerční banka, a.s. | ✅ | ❌ | ✅ | RSA-2048 | high |
| DE | D-Trust GmbH (Bundesdruckerei) | ✅ | ✅ | ✅ | smartcard: ECDSA P-256/P-384/P-521 or RSA-4096; remote: brainpoolP256r1 (not P-256) | high |
| DE | Deutsche Telekom AG (Qualified.ID) | ✅ | ✅ | ✅ | both: ECDSA prime256v1 (P-256) + brainpoolP256r1 + RSA | high |
| DE | Bundesnotarkammer (BNotK) | ✅ | ❌ | ✅ | ECDSA P-521 (older) or P-384 (newer 2021+); RSA-4096 | high |
| DE | Deutsche Post AG (POSTIDENT) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| DE | SIGN8 GmbH | ✅ | ❓ | ✅ | ECDSA 256-bit (curve unspecified) or RSA-4096 | low |
| DE | Netcetera Software Services GmbH (BVsign) | ✅ | ❌ | ✅ | ECDSA P-384/P-521/brainpoolP384/P-512; RSA-4096 (no P-256) | high |
| DE | DGN Deutsches Gesundheitsnetz Service GmbH | ✅ | ❌ | ✅ | ECDSA brainpoolP256r1 or RSA-2048 (healthcare only) | high |
| DE | medisign GmbH | ✅ | ❌ | ✅ | ECDSA brainpoolP256r1 (eHBA G2.1) or RSA-2048 (healthcare only) | high |
| DE | Atos Information Technology GmbH | ✅ | ❌ | ✅ | ECDSA brainpoolP256r1 or RSA-2048 PSS (healthcare only) | high |
| DE | Eviden Germany GmbH | ✅ | ❌ | ✅ | ECDSA brainpoolP256r1 or RSA-2048 PSS (healthcare only) | high |
| DE | Bundesagentur fuer Arbeit | ✅ | ❌ | ✅ | RSA-3072 (internal government employees only) | medium |
| DK | Den Danske Stat (Digitaliseringsstyrelsen) | ✅ | ✅ | ❌ | ECDSA P-256 (secp256r1) | high |
| DK | Penneo A/S | ✅ | ❌ | ✅ | RSA-3072 SHA-256 | high |
| DK | IN Groupe Denmark A/S | ✅ | ✅ | ❌ | ECDSA P-256 (secp256r1), short-term certs | high |
| EE | SK ID Solutions AS (Mobile-ID) | ✅ | ✅ | ✅ | Mobile-ID: ECDSA P-256 or RSA-2048; ID card: ECDSA P-384; Smart-ID: RSA ~3072 composite | high |
| EE | Zetes Estonia OÜ (ESTEID2025) | ✅ | ❌ | ❌ | ECDSA P-384 | high |
| ES | FNMT-RCM | ✅ | ✅ | ✅ | both: ECDSA P-256 (ECC G2 hierarchy, current) + RSA-2048 (legacy, expiring 2028) | high |
| ES | ACCV | ✅ | ✅ | ✅ | both: ECDSA P-256 + RSA-2048 | high |
| ES | EAD Trust European Agency of Digital Trust | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + ECDSA P-384 + RSA | high |
| ES | Sectigo (Europe) SL | ✅ | ✅ | ✅ | both: ECDSA P-256 + RSA-2048 | high |
| ES | AC Camerfirma S.A. (Infocert-Camerfirma) | ✅ | ✅ | ✅ | RSA-2048 + ECDSA ≥256-bit (P-256 probable but not named explicitly) | medium |
| ES | Firmaprofesional S.A. | ✅ | ❌ | ✅ | RSA-2048; ECDSA P-384 at CA/some EE level | medium |
| ES | ANF Autoridad de Certificación | ✅ | ❌ | ✅ | RSA-3072/4096 | high |
| ES | Izenpe S.A. | ✅ | ❓ | ✅ | RSA (historical); possible ECDSA in newer hierarchy (unconfirmed) | low |
| ES | CAOC (CATCert / idCAT) | ✅ | ❓ | ✅ | RSA (pre-Oct 2025); elliptic curves announced Oct 2025 (curve unknown) | medium |
| FI | DVV (Digital and Population Data Services Agency) | ✅ | ❌ | ✅ | ECDSA P-384 (G4E) + RSA (G4R); P-256 not used | high |
| FR | CertEurope | ✅ | ❌ | ✅ | RSA-2048 | high |
| FR | Docaposte Certinomis | ✅ | ❌ | ✅ | RSA-2048 (ECDSA P-256 policy-allowed but no ECDSA CA cert published) | high |
| FR | ChamberSign France | ✅ | ❌ | ✅ | RSA-3072/4096 | high |
| FR | Cryptolog International (Universign) | ✅ | ❌ | ✅ | RSA-2048 | high |
| FR | Certigna | ✅ | ❌ | ✅ | RSA-2048 | high |
| FR | DocuSign France | ✅ | ❌ | ✅ | RSA-3072 | high |
| FR | Yousign | ✅ | ❌ | ✅ | RSA-2048 | high |
| FR | VIALINK | ✅ | ❌ | ✅ | RSA-2048 | high |
| FR | Lex Persona (Sunnystamp) | ✅ | ✅ | ✅ | both: RSA-2048 + ECDSA P-256 | high |
| FR | ANTS | ✅ | ❓ | ❓ | unknown (government internal) | low |
| FR | Imprimerie Nationale | ✅ | ❓ | ❓ | unknown | low |
| FR | Conseil Supérieur du Notariat | ✅ | ❓ | ❓ | unknown (notaries only) | low |
| FR | Ministère de la Justice | ✅ | ❓ | ❓ | unknown (government internal) | low |
| FR | Ministère de l'Intérieur | ✅ | ❓ | ❓ | unknown (government internal) | low |
| FR | Gendarmerie Nationale | ✅ | ❓ | ❓ | unknown (government internal) | low |
| FR | CEGEDIM SA | ✅ | ❓ | ❓ | unknown (healthcare) | low |
| FR | Ministères économiques et financiers | ✅ | ❓ | ❓ | unknown (government internal) | low |
| FR | DATASURE | ✅ | ❓ | ❓ | unknown | low |
| FR | ANFSI | ✅ | ❓ | ❓ | unknown (government internal) | low |
| GR | ADACOM S.A. | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| GR | HARICA (GUnet) | ✅ | ❌ | ✅ | both: ECDSA P-384 + RSA-4096 (no P-256) | high |
| GR | BYTE Computer S.A. | ✅ | ❌ | ✅ | RSA (end-entity size unknown; CA RSA-4096) | medium |
| GR | APED (Hellenic Public Administration CA) | ✅ | ❌ | ✅ | RSA-4096 SHA-256 (public servants only) | high |
| HR | Financijska agencija (FINA) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| HR | AKD d.o.o. — HRIDCA 2025 (eID card) | ✅ | ❌ | ❌ | ECDSA P-384 | high |
| HR | AKD d.o.o. — Certilia (remote/mobile) | ✅ | ❌ | ❌ | ECDSA P-384 | high |
| HR | Zagrebačka banka d.d. (Zaba QPKI) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| HU | Microsec Micro Software Engineering (e-Szignó) | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1, 2017 hierarchy) + RSA | high |
| HU | NETLOCK Kft. | ✅ | ❓ | ✅ | ECC CA chain is P-384; end-user curve unspecified (P-256 policy-allowed, P-384 confirmed CA) | medium |
| HU | NISZ National Infocommunications Services (GovCA/MTT) | ✅ | ✅ | ✅ | MTT profile: ECDSA P-256 default; DÁP: P-384; legacy eSZIG: RSA-4096 | high |
| IE | TrustPro QTSP Ltd | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| IE | Entaksi Solutions SpA (Irish Branch) | ✅ | ❌ | ✅ | RSA-4096 CA; subscriber size per ETSI TS 119 312 | high |
| IE | Namirial Limited (Irish Branch) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| IE | Post.Trust Ltd | ❓ | ❓ | ❓ | unknown (withdrawn) | low |
| IS | Auðkenni ehf. | ✅ | ❌ | ✅ | RSA-2048 (card/mobile) or RSA-6144/8192 (app/split key) | high |
| IT | ArubaPEC S.p.A. | ✅ | ❌ | ✅ | RSA-4096 SHA-256 | high |
| IT | Actalis S.p.A. | ✅ | ❌ | ✅ | RSA-4096 SHA-256 | high |
| IT | InfoCert S.p.A. | ✅ | ❌ | ✅ | both: RSA-4096 + ECDSA P-384 (no P-256) | high |
| IT | Namirial S.p.A. | ✅ | ❌ | ✅ | RSA-4096 SHA-256 | high |
| IT | Poste Italiane S.p.A. | ✅ | ❌ | ✅ | RSA-2048 (EE) / RSA-4096 (CA) | high |
| IT | Intesi Group S.p.A. | ✅ | ❌ | ✅ | both: RSA-4096 + ECDSA P-521 (no P-256) | high |
| IT | In.Te.S.A. S.p.A. (e-Trustcom) | ✅ | ❌ | ✅ | RSA-4096 SHA-256 | high |
| IT | Intesa Sanpaolo Bank S.p.A. | ✅ | ❌ | ✅ | both: ECDSA P-384 + RSA-4096 (no P-256) | high |
| IT | Zucchetti S.p.A. | ✅ | ❌ | ✅ | both: RSA-4096 + ECDSA P-384 (no P-256) | high |
| IT | Uanataca S.A. (Italian branch) | ✅ | ❌ | ✅ | RSA-4096 SHA-256 | high |
| IT | TeamSystem S.p.A. | ✅ | ❌ | ✅ | RSA-4096 SHA-256 | high |
| IT | Banca d'Italia | ❌ | ❌ | ✅ | RSA-4096 SHA-256 (employees only) | high |
| LI | Liechtensteinische Post AG | ✅ | ❌ | ❓ | unknown (withdrawn 2016) | low |
| LI | FLZ-Anstalt | ✅ | ❌ | ❓ | unknown (withdrawn 2022; old profile shows P-192) | low |
| LI | SwissSign AG | ✅ | ❌ | ✅ | RSA-3072 RSASSA-PSS (withdrawn 2020) | high |
| LT | Migration Department (MD/NSC eID card) | ✅ | ❓ | ❌ | ECDSA (root P-521, issuing CA P-384; leaf curve unconfirmed — P-256 or P-384) | medium |
| LT | State Enterprise Centre of Registers (RCSC / LT-ID / Mobile-ID) | ✅ | ✅ | ❌ | ECDSA P-256 (Mobile-ID confirmed; LT-ID: ECC-256 or ECC-384) | high |
| LU | LuxTrust S.A. | ✅ | ❌ | ✅ | both: ECDSA P-384 + RSA-3072/4096 (no P-256) | high |
| LU | BE INVEST International S.A. | ✅ | ❓ | ❓ | unknown | low |
| LV | LVRTC (eParaksts) | ✅ | ❌ | ✅ | both: RSA-2048 + ECDSA P-384 (no P-256) | high |
| MT | MECS Ltd | ✅ | ❌ | ✅ | RSA-2048 (eID smartcard); RSA-3072 (new remote signing, 2025) | high |
| NL | Digidentity B.V. | ✅ | ❌ | ✅ | RSA-2048/3072/4096 | high |
| NL | DigiCert Europe Netherlands B.V. (QuoVadis) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| NL | Cleverbase ID B.V. | ✅ | ❌ | ✅ | RSA-2048/4096 SHA-256 | high |
| NL | KPN B.V. | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | medium |
| NO | Buypass AS (smartcard/HSM product) | ✅ | ❌ | ✅ | RSA-2048 (smartcard) / RSA-3072 (HSM) | high |
| NO | Buypass AS (BCSS cloud signature) | ✅ | ✅ | ❌ | ECDSA P-256 (secp256r1), short-term certs | high |
| NO | Commfides Norge AS | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| NO | Stø AS (formerly BankID BankAxept) | ✅ | ✅ | ❌ | ECDSA P-256 (secp256r1), short-term certs | high |
| PL | Asseco Data Systems S.A. (Certum) | ✅ | ❌ | ✅ | RSA-2048/3072 | high |
| PL | PWPW S.A. (Sigillum) | ✅ | ❌ | ✅ | RSA-2048/3072 + ECDSA P-384 (no P-256) | high |
| PL | KIR S.A. (Szafir / mSzafir) | ✅ | ✅ | ✅ | both: RSA-2048 + ECDSA P-256 (secp256r1 confirmed in non-qualified CPS; qualified policy says "ECC 256-bit") | medium |
| PL | EuroCert Sp. z o.o. | ✅ | ✅ | ✅ | both: RSA-2048/3072/4096 + ECDSA P-256/P-384/P-521 | high |
| PL | ENIGMA Systemy (CenCert) | ✅ | ✅ | ✅ | both: RSA-2048 + ECDSA 256-bit NIST (P-256 strongly implied, curve name not verbatim) | medium |
| PT | DigitalSign — Certificadora Digital SA | ✅ | ✅ | ✅ | both: ECDSA P-256 (secp256r1) + RSA-2048 | high |
| PT | IRN I.P. (Cartão de Cidadão / Chave Móvel Digital) | ✅ | ✅ | ✅ | ECDSA P-256 (new cards since June 2024); RSA (pre-2024 cards) | high |
| PT | MULTICERT S.A. | ✅ | ❌ | ✅ | RSA-4096 (CA); subscriber RSA (size unconfirmed) | medium |
| PT | CEGER (ECCE) | ✅ | ❓ | ❓ | unknown (government employees; CPS inaccessible) | low |
| PT | ACIN / Global Trusted Sign (GTS) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| RO | certSIGN SA (Qualified CA G2) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| RO | certSIGN SA (Qualified 2023 RSA CA) | ✅ | ❌ | ✅ | RSA-3072/4096 | high |
| RO | Trans Sped SRL | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| RO | AlfaTrust Certification SA (AlfaSign) | ✅ | ✅ | ✅ | both: RSA-2048/3072 + ECDSA P-256 or P-384 (CPS mentions both; end-entity P-256 probable but not fully confirmed) | medium |
| RO | DigiSign SA | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | medium |
| RO | Centrul de Calcul SA (CertDigital) | ✅ | ❓ | ❓ | unknown (CPS inaccessible) | low |
| SE | ZealiD AB | ✅ | ❌ | ✅ | RSA-4096 SHA-256 | high |
| SE | IDnow Trust Services AB | ✅ | ✅ | ✅ | both: RSA ≥3072 + ECDSA ≥P-256 (CA certs are RSA; P-256 subscriber certs described but not sample-confirmed) | medium |
| SI | SI-TRUST / SIGEN-CA | ✅ | ❌ | ✅ | RSA-3072 SHA-256 | high |
| SI | Halcom d.d. | ✅ | ❌ | ✅ | RSA-2048/3072 RSASSA-PSS | high |
| SI | Rekono d.o.o. / POŠTA CA | ✅ | ❌ | ✅ | RSA-2048/3072 (ECC chain exists but has no qualified OIDs) | high |
| SI | NLB d.d. / AC NLB | ✅ | ❌ | ✅ | RSA-3072 (stopped issuing 2023) | high |
| SK | Disig a.s. — CA Disig QCA4 | ✅ | ❓ | ✅ | RSA-4096 dominant; EC-256 policy-allowed, curve unspecified | medium |
| SK | Disig a.s. — SVK eID ACA2 | ✅ | ❌ | ✅ | RSA-3072 SHA-256 | high |
| SK | NASES — SNCA4 | ✅ | ❌ | ✅ | RSA-3072/4096 | high |
| SK | Ardaco a.s. — Ardaco QSCA | ✅ | ❓ | ✅ | RSA-2048 + ECDSA 256-bit (curve unspecified, deferred to ETSI TS 119 312) | medium |
| SK | brainit.sk s.r.o. (NFQES CA) | ✅ | ❓ | ✅ | RSA-4096 dominant; EC-256 policy-allowed, curve unspecified | medium |
| SK | I.CA SK (First certification authority) | ✅ | ❌ | ✅ | RSA-2048 SHA-256 | high |
| UA | SE "DIIA" | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + RSA-4096 | high |
| UA | SE "USS" | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + RSA-4096 | high |
| UA | JSC CB PrivatBank (ACSK PrivatBank) | ✅ | ✅ | ❌ | ECDSA P-256 (prime256v1) | high |
| UA | "VCHASNO SERVICE" LLC | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + RSA-4096 | high |
| UA | DEPOSIT SIGN LLC | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + RSA-4096 | high |
| UA | State Tax Service of Ukraine | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + RSA-4096 | high |
| UA | FUIB (First Ukrainian International Bank) | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + RSA-4096 | high |
| UA | JSC Universal Bank (monobank / monoКЕП) | ✅ | ❌ | ✅ | ECDSA P-521 + RSA-4096 (not P-256) | high |
| UA | JSC Oschadbank | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + RSA-4096 | medium |
| UA | PJSC Ukrgasbank | ✅ | ✅ | ✅ | both: ECDSA P-256 (prime256v1) + RSA-4096 | medium |

---

## crisp-qes P-256 Shortlist

QTSPs where natural-person QES is confirmed (or high-probability) on ECDSA P-256 — directly portable to the existing enroll_commit_v2 circuit. Sorted high-confidence first.

| Country | QTSP | Confidence | Best source URL |
|---------|------|:-:|----------------|
| AT | A-Trust GmbH | high | https://tc.prime-sign.com/policies/PrimeSign_CPS_v1.11.0.pdf *(see also:* https://www.a-trust.at/downloads/de/Certificate%20Practice%20Statement/a-sign-qualified/a-sign-qualified_cps.pdf) |
| AT | e-commerce monitoring GmbH (TRUST2GO remote) | high | https://globaltrust.eu/en/trust2go/ |
| AT | PrimeSign GmbH (CRYPTAS-PrimeSign) | high | https://tc.prime-sign.com/policies/PrimeSign_CPS_v1.11.0.pdf |
| BE | DigiCert Europe Belgium B.V. (itsme Sign) | high | https://testing.itsme-id.com/hubfs/Legal%20Information%20-%20B2B%20Website/Sign%20Document%20Repository/Signature%20Creation%20Service%20Policy/compl_pol_itsmesignaturecreationservicepolicy-version-2-2.pdf |
| CZ | První certifikační autorita a.s. (I.CA) | high | https://www.ica.cz/sites/default/files/docs/2026/02/cp_qc_fo_ecc_1v066_en.pdf |
| DE | Deutsche Telekom AG (Qualified.ID / QSign CA25A/B) | high | https://www.telesec.de/assets/downloads/Public-Key-Service/PKS-Zertifikatsprofil-ECC-und-RSA2048-Ergaenzung-v4.pdf |
| DE | D-Trust GmbH (smartcard track, Root PKI) | high | https://www1.d-trust.net/internet/files/D-TRUST_Root_PKI_CPS.pdf |
| DK | Den Danske Stat (Digitaliseringsstyrelsen) | high | https://cms.nemlog-in.dk/media/olrp33rv/den-danske-stat-cps-v1-1.pdf |
| DK | IN Groupe Denmark A/S | high | https://pki.ingroupe.dk/repository/profiles/Certificate_Profiles_v1.0.2.pdf |
| EE | SK ID Solutions AS (Mobile-ID product) | high | https://www.skidsolutions.eu/wp-content/uploads/2025/01/Certificate_and_OCSP_Profile_for_Mobile-ID_v_2_3.pdf |
| ES | FNMT-RCM (AC Usuarios G2 ECC hierarchy) | high | https://www.sede.fnmt.gob.es/documents/10445900/10536309/dpc_personasfisicas.pdf |
| ES | ACCV (ACCV_ECC1_CLIENTE) | high | https://www.accv.es/fileadmin/Archivos/Politicas_pdf/ACCV-CP-06V9.0.2-ES-2024.pdf |
| ES | EAD Trust (ECC 256 SubCA For Qualified Certificates — Natural Person) | high | https://www.eadtrust.eu/wp-content/uploads/2025/05/OPR-PG-V5.4-Declaracion_Practicas_Certificacion_DPC-11.10.2024_signed.pdf |
| ES | Sectigo (Europe) SL | high | https://www.sectigo.com/uploads/files/eIDAS/Qualified_certificate_profiles_v2.7.pdf |
| FR | Lex Persona (Sunnystamp Natural Persons CA) | high | https://goodflag.com/hubfs/LPCSP_PL_SunPKI_SNP_PC-DPC_v1.3.pdf |
| HU | Microsec / e-Szignó (2017 ECC hierarchy) | high | https://static.e-szigno.hu/docs/szsz--all--all--EN--v3.17.pdf |
| HU | NISZ GovCA (MTT qualified cert, P-256 default) | high | https://hiteles.gov.hu/letoltes/697/BSZ-MTT_v1.19_app_.pdf |
| LT | RCSC (Mobile-ID ECDSA secp256r1 confirmed) | high | https://ltid.lt/site_media/2026/01/1.2.-CPS_remote-Sertifikavimo-veiklos-nuostatai_1.3_LT.pdf |
| NO | Buypass AS (BCSS cloud signature service) | high | https://repository.buypassca.com/profilesBCSS-v1-1.pdf |
| NO | Stø AS (BankID / BankAxept QES) | high | https://developer.bankid.no/bankid-esign-provider/pki/certificate-profiles/ |
| PL | EuroCert Sp. z o.o. | high | https://eurocert.pl/repozytorium/_EN/Certificate_Policy_and_Certification_Practice_Statement/Qualified/Valid/0-PT-025-05.1-Certificate_Policy_and_Certification_Practice_Statement_VALID_from_20-10-2025.pdf |
| PT | DigitalSign — Certificadora Digital SA | high | https://pki.digitalsign.pt/ROOT%20CA%20-%20CP_V1.9.pdf |
| PT | IRN I.P. (Cartão de Cidadão, June 2024+ cards) | high | https://amagovpt.github.io/docs.autenticacao.gov/manual_sdk.html |
| UA | SE "DIIA" | high | https://ca.diia.gov.ua/uploads/regulations/Reglament_DIIA_20251203_en.pdf |
| UA | SE "USS" | high | https://csk.uss.gov.ua/download/reglament/Reg_ad_1.pdf |
| UA | JSC CB PrivatBank (ACSK PrivatBank) | high | https://czo.gov.ua/download/tl/TL-UA-EC.xml |
| UA | "VCHASNO SERVICE" LLC | high | https://ca.vchasno.ua/download/normativedocs/nd11_ua.pdf |
| UA | DEPOSIT SIGN LLC | high | https://czo.gov.ua/download/tl/TL-UA-EC.xml |
| UA | State Tax Service of Ukraine | high | https://czo.gov.ua/download/tl/TL-UA-EC.xml |
| UA | FUIB (First Ukrainian International Bank) | high | https://czo.gov.ua/download/tl/TL-UA-EC.xml |
| PL | KIR S.A. (Szafir / mSzafir) | medium | https://www.elektronicznypodpis.pl/storage/file/core_files/2024/4/17/88ab3ebf1259c28c05f6b305ad6dae88/kir_certification_policy_16_20240321-sig.pdf |
| PL | ENIGMA Systemy (CenCert) | medium | https://www.cencert.pl/wp-content/uploads/2025/01/policy-for-qualified-trust-services-v-1-42.pdf |
| RO | AlfaTrust Certification SA (AlfaSign) | medium | https://www.alfasign.ro/depozit/DeclaratiaPracticilor.pdf |
| SE | IDnow Trust Services AB | medium | https://www.trust-services.io/wp-content/uploads/Practice_Statement_IDnow-Trust-Services-AB_v1.1_signed.pdf |
| UA | JSC Oschadbank | medium | https://czo.gov.ua/download/tl/TL-UA.xml |
| UA | PJSC Ukrgasbank | medium | https://czo.gov.ua/download/tl/TL-UA.xml |
| ES | AC Camerfirma (Infocert-Camerfirma) | medium | https://daa1df3k0xsds.cloudfront.net/wp-content/uploads/2024/02/CPS_CP_CAMERFIRMA_ES_v1.5.0.pdf |

---

## Coverage Notes

**Countries with data returned:** 26 (AT, BE, BG, CY, CZ, DE, DK, EE, ES, FI, FR, GR, HR, HU, IE, IS, IT, LI, LT, LU, LV, MT, NL, NO, PL, PT, RO, SE, SI, SK, UA) — 31 country entries total including non-EU EEA (IS, LI, NO) and Ukraine.

**Total QTSP rows in master table:** 120 (including withdrawn services included for completeness).

**ECDSA P-256 confirmed (high confidence):** 30 QTSPs across AT (3), BE (1), CZ (1), DE (2), DK (2), EE (1), ES (4), FR (1), HU (2), LT (1), NO (2), PL (1), PT (2), UA (7).

**ECDSA P-256 probable (medium confidence):** 7 additional QTSPs (PL KIR, PL CenCert, RO AlfaTrust, SE IDnow, UA Oschadbank, UA Ukrgasbank, ES Camerfirma).

**Algorithm unknown ("❓" in P-256 column):** approximately 22 entries — primarily French government/sectoral QTSPs (9 entries, all low-confidence government-internal PKIs with no public CPS), plus scattered low-confidence entries in BG, DE, ES, IE, LI, LT, LU, PT, RO, SK.

**Countries with thin or low-confidence data requiring manual CPS review:**

- **France**: 10 of 19 QTSPs are government/sectoral PKIs with no public CPS — algorithm universally unknown for those services. The commercial QTSPs (9 entries) are well-documented; only Lex Persona has confirmed P-256.
- **Slovakia**: 3 of 6 QTSPs allow EC-256 in policy but name no curve and deploy RSA CA certs in practice; manual sample-cert retrieval needed to confirm.
- **Romania**: CertDigital CPS was inaccessible; AlfaTrust P-256 claim needs full CPP confirmation.
- **Luxembourg**: BE INVEST International CPS unreachable; website down.
- **Lithuania**: Migration Department leaf certificate profile blocked by Cloudflare; P-256 vs P-384 for new eID cards unconfirmed.
- **Spain (Izenpe, CATCert)**: DPC PDFs timed out; Izenpe's new hierarchy and CATCert post-Oct-2025 ECC curve both unconfirmed.
- **Liechtenstein**: Both relevant services withdrawn; historical algorithm data fragmentary.
