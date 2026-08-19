#![no_main]

use libfuzzer_sys::fuzz_target;
use meshcop_dtls::{
    parse_unfragmented_handshake_messages, ContentType, DtlsRecord, HandshakeFragment,
    HandshakeHeader, HandshakeReassembler,
};

// DTLS handshake framing and reassembly: header/fragment parsing, fragment
// reassembly, and the record-level message parser must all reject malformed
// input without panicking.
fuzz_target!(|data: &[u8]| {
    let _ = HandshakeHeader::parse(data);

    if let Ok(fragment) = HandshakeFragment::parse(data) {
        let encoded = fragment.encode().expect("parsed fragment must re-encode");
        assert_eq!(&encoded[..], &data[..encoded.len()]);

        let mut reassembler = HandshakeReassembler::default();
        let _ = reassembler.push(fragment);
    }

    if let Ok(record) = DtlsRecord::new(ContentType::Handshake, 0, 0, data.to_vec()) {
        let _ = parse_unfragmented_handshake_messages(&record);
    }
});
