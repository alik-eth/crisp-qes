// DOB extraction + age-arithmetic unit tests.
//
// `extractDOB` walks a Diia leaf cert's SubjectDirectoryAttributes
// extension. We test it directly against the live fixture .p7s in
// `fixtures/diia/` when present, plus exercise the pure-string parser
// and age comparator with synthetic inputs.

import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { parseP7s } from "@crisp-qes/sdk";

import { ageInYears, extractDOB, parseDOBString } from "../src/dob.js";

const FIXTURE_PATH =
    "/data/Develop/crisp-qes/fixtures/diia/petition-1-binding.bin.p7s";
const hasFixture = existsSync(FIXTURE_PATH);
const maybe = hasFixture ? describe : describe.skip;

describe("parseDOBString", () => {
    it("parses YYYYMMDD-suffix into a UTC Date", () => {
        const d = parseDOBString("19990426-02970");
        expect(d).not.toBeNull();
        expect(d!.getUTCFullYear()).toBe(1999);
        expect(d!.getUTCMonth()).toBe(3); // April = 3 (0-indexed)
        expect(d!.getUTCDate()).toBe(26);
        expect(d!.getUTCHours()).toBe(0);
    });

    it("parses bare YYYYMMDD with no trailer", () => {
        const d = parseDOBString("20000115");
        expect(d).not.toBeNull();
        expect(d!.getUTCFullYear()).toBe(2000);
        expect(d!.getUTCMonth()).toBe(0);
        expect(d!.getUTCDate()).toBe(15);
    });

    it("returns null for short or non-numeric prefix", () => {
        expect(parseDOBString("")).toBeNull();
        expect(parseDOBString("199904")).toBeNull();
        expect(parseDOBString("abcd0426")).toBeNull();
    });

    it("rejects out-of-range months and days (Feb 30 etc.)", () => {
        expect(parseDOBString("19990230")).toBeNull(); // Feb 30
        expect(parseDOBString("19990431")).toBeNull(); // Apr 31
        expect(parseDOBString("19991301")).toBeNull(); // month 13
        expect(parseDOBString("19990000")).toBeNull(); // month 0
    });

    it("rejects implausible years", () => {
        expect(parseDOBString("18001231")).toBeNull();
        expect(parseDOBString("21501231")).toBeNull();
    });
});

describe("ageInYears (strict calendar)", () => {
    const dob = new Date(Date.UTC(2000, 4, 15)); // 2000-05-15

    it("returns 18 at exact 18th birthday UTC", () => {
        const now = new Date(Date.UTC(2018, 4, 15));
        expect(ageInYears(dob, now)).toBe(18);
    });

    it("returns 17 the day BEFORE the 18th birthday", () => {
        const now = new Date(Date.UTC(2018, 4, 14));
        expect(ageInYears(dob, now)).toBe(17);
    });

    it("returns 17 in a month before the 18th birthday's month", () => {
        const now = new Date(Date.UTC(2018, 3, 30)); // 2018-04-30
        expect(ageInYears(dob, now)).toBe(17);
    });

    it("returns 18 the day AFTER the 18th birthday", () => {
        const now = new Date(Date.UTC(2018, 4, 16));
        expect(ageInYears(dob, now)).toBe(18);
    });

    it("returns 0 when DOB is in the future", () => {
        const now = new Date(Date.UTC(1999, 0, 1));
        expect(ageInYears(dob, now)).toBe(0);
    });
});

maybe("extractDOB against live Diia fixture", () => {
    it("returns the citizen DOB embedded in the .p7s leaf cert", () => {
        const p7s = readFileSync(FIXTURE_PATH);
        const parsed = parseP7s(p7s);
        const dob = extractDOB(parsed.leafCertDer);
        // Fixture is alikvovk's own cert per fixtures/diia/ — DOB
        // 1999-04-26 surfaced via `openssl x509 -text` decode of the
        // Subject Directory Attributes extension (Ukrainian OID
        // 1.2.804.2.1.1.1.11.1.4.11.1, value "19990426-02970").
        expect(dob).not.toBeNull();
        expect(dob!.getUTCFullYear()).toBe(1999);
        expect(dob!.getUTCMonth()).toBe(3);
        expect(dob!.getUTCDate()).toBe(26);
    });

    it("citizen is well over 18 today (sanity check on the gate)", () => {
        const p7s = readFileSync(FIXTURE_PATH);
        const parsed = parseP7s(p7s);
        const dob = extractDOB(parsed.leafCertDer)!;
        const age = ageInYears(dob, new Date());
        expect(age).toBeGreaterThanOrEqual(18);
    });
});

describe("extractDOB on malformed input", () => {
    it("returns null on garbage bytes (not throws)", () => {
        const dob = extractDOB(new Uint8Array([0x30, 0x00]));
        expect(dob).toBeNull();
    });

    it("returns null on empty input", () => {
        const dob = extractDOB(new Uint8Array(0));
        expect(dob).toBeNull();
    });
});
