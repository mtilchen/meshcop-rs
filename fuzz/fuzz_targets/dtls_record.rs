#![no_main]

use libfuzzer_sys::fuzz_target;
use meshcop_dtls::{DtlsRecord, RecordHeader};

// DTLS record framing: parsing one datagram into records must never panic, and
// any record that parses must re-encode and re-parse to an identical sequence.
fuzz_target!(|data: &[u8]| {
    let _ = RecordHeader::parse(data);

    if let Ok(records) = DtlsRecord::parse_datagram(data) {
        let mut reencoded = Vec::new();
        for record in &records {
            reencoded.extend_from_slice(&record.encode().expect("parsed record must re-encode"));
        }
        let reparsed =
            DtlsRecord::parse_datagram(&reencoded).expect("re-encoded datagram must re-parse");
        assert_eq!(records, reparsed);
    }
});
