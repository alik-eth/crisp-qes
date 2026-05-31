// QTSP data per EU/EEA country + Ukraine.
// Source: EU DSS Trusted Lists — https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/tl-info
// Last updated: 2026-05-31

export interface QtspCountryData {
    code: string;
    name: string;
    totalQtsps: number;
    qtspWithP256: number;
    qtspWithRsa: number;
    services: number;
    certificates: number;
}

export const QTSP_DATA: QtspCountryData[] = [
    { code: "AT", name: "Austria",       totalQtsps:  8, qtspWithP256:  0, qtspWithRsa:  8, services: 100, certificates: 104 },
    { code: "BE", name: "Belgium",       totalQtsps: 16, qtspWithP256:  2, qtspWithRsa: 16, services: 127, certificates: 133 },
    { code: "BG", name: "Bulgaria",      totalQtsps:  8, qtspWithP256:  1, qtspWithRsa:  8, services: 113, certificates: 111 },
    { code: "CY", name: "Cyprus",        totalQtsps:  1, qtspWithP256:  1, qtspWithRsa:  1, services:   8, certificates:   8 },
    { code: "CZ", name: "Czechia",       totalQtsps: 10, qtspWithP256:  1, qtspWithRsa: 10, services: 540, certificates: 535 },
    { code: "DE", name: "Germany",       totalQtsps: 30, qtspWithP256:  2, qtspWithRsa: 30, services: 977, certificates: 977 },
    { code: "DK", name: "Denmark",       totalQtsps:  4, qtspWithP256:  0, qtspWithRsa:  4, services:  16, certificates:  16 },
    { code: "EE", name: "Estonia",       totalQtsps:  3, qtspWithP256:  0, qtspWithRsa:  3, services:  66, certificates:  67 },
    { code: "GR", name: "Greece",        totalQtsps:  5, qtspWithP256:  2, qtspWithRsa:  5, services: 133, certificates: 133 },
    { code: "ES", name: "Spain",         totalQtsps: 71, qtspWithP256:  0, qtspWithRsa: 71, services: 424, certificates: 451 },
    { code: "FI", name: "Finland",       totalQtsps:  1, qtspWithP256:  1, qtspWithRsa:  1, services:  19, certificates:  19 },
    { code: "FR", name: "France",        totalQtsps: 39, qtspWithP256:  0, qtspWithRsa: 39, services: 344, certificates: 350 },
    { code: "HR", name: "Croatia",       totalQtsps:  4, qtspWithP256:  0, qtspWithRsa:  4, services:  43, certificates:  43 },
    { code: "HU", name: "Hungary",       totalQtsps: 11, qtspWithP256:  1, qtspWithRsa: 11, services: 337, certificates: 368 },
    { code: "IE", name: "Ireland",       totalQtsps:  5, qtspWithP256:  0, qtspWithRsa:  5, services:  12, certificates:  13 },
    { code: "IS", name: "Iceland",       totalQtsps:  2, qtspWithP256:  0, qtspWithRsa:  2, services:   8, certificates:   9 },
    { code: "IT", name: "Italy",         totalQtsps: 56, qtspWithP256:  2, qtspWithRsa: 56, services: 557, certificates: 538 },
    { code: "LI", name: "Liechtenstein", totalQtsps:  4, qtspWithP256:  0, qtspWithRsa:  4, services:  10, certificates:  10 },
    { code: "LT", name: "Lithuania",     totalQtsps: 10, qtspWithP256:  2, qtspWithRsa: 10, services:  85, certificates:  85 },
    { code: "LU", name: "Luxembourg",    totalQtsps:  5, qtspWithP256:  4, qtspWithRsa:  5, services:  34, certificates:  32 },
    { code: "LV", name: "Latvia",        totalQtsps:  1, qtspWithP256:  0, qtspWithRsa:  1, services:  40, certificates:  40 },
    { code: "MT", name: "Malta",         totalQtsps:  3, qtspWithP256:  3, qtspWithRsa:  0, services:  10, certificates:  12 },
    { code: "NL", name: "Netherlands",   totalQtsps: 14, qtspWithP256:  2, qtspWithRsa: 14, services:  95, certificates: 105 },
    { code: "NO", name: "Norway",        totalQtsps: 16, qtspWithP256:  2, qtspWithRsa: 16, services:  53, certificates:  54 },
    { code: "PL", name: "Poland",        totalQtsps: 13, qtspWithP256:  0, qtspWithRsa: 13, services: 130, certificates: 135 },
    { code: "PT", name: "Portugal",      totalQtsps: 10, qtspWithP256:  3, qtspWithRsa: 10, services: 105, certificates: 107 },
    { code: "RO", name: "Romania",       totalQtsps:  8, qtspWithP256:  0, qtspWithRsa:  8, services: 167, certificates: 175 },
    { code: "SE", name: "Sweden",        totalQtsps:  4, qtspWithP256:  0, qtspWithRsa:  4, services:  14, certificates:  12 },
    { code: "SI", name: "Slovenia",      totalQtsps: 10, qtspWithP256:  4, qtspWithRsa: 10, services: 105, certificates: 100 },
    { code: "SK", name: "Slovakia",      totalQtsps: 10, qtspWithP256:  0, qtspWithRsa: 10, services: 186, certificates: 279 },
    { code: "UA", name: "Ukraine",       totalQtsps: 10, qtspWithP256:  1, qtspWithRsa: 10, services:  44, certificates:  44 },
];
