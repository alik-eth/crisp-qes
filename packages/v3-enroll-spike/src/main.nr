// Phase-0 spike D: DER field-extraction cost (risk #3).
// In-circuit we must pull the RNOKPP (subject serialNumber, OID 2.5.4.5)
// out of the leaf cert DER at a witnessed offset and bind it. The cost
// driver is DYNAMIC array access at a witnessed index (no native RAM in
// ACIR), not the byte compares -- this is the zk-email substring problem.
//
// Representative: a ~1.5 KB cert buffer; prove the 5-byte OID appears at a
// witnessed offset, then a tag+len, then read the 10 RNOKPP digit bytes,
// and fold them into a single Field (the value handed to hash-to-curve).

global CERT_LEN: u32 = 1536;
global RNOKPP_LEN: u32 = 10;

// OID 2.5.4.5 (id-at-serialNumber) DER: 06 03 55 04 05
global OID: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x05];

fn main(cert: [u8; CERT_LEN], oid_offset: u32) -> pub Field {
    // 1. Assert the OID bytes sit at the witnessed offset (dynamic reads).
    for i in 0..5 {
        assert(cert[oid_offset + i] == OID[i]);
    }
    // 2. After OID: tag (0x13 PrintableString) + length byte == RNOKPP_LEN.
    let tag = cert[oid_offset + 5];
    let len = cert[oid_offset + 6];
    assert(tag == 0x13);
    assert(len as u32 == RNOKPP_LEN);

    // 3. Read the 10 value bytes (dynamic), validate they are ASCII digits,
    //    and fold into a Field (this is the input to hash-to-curve).
    let mut acc: Field = 0;
    for i in 0..RNOKPP_LEN {
        let byte = cert[oid_offset + 7 + i];
        assert((byte >= 0x30) & (byte <= 0x39)); // '0'..'9'
        acc = acc * 256 + byte as Field;
    }
    acc
}
