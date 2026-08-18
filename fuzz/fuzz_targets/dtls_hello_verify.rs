#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh50_dtls::HelloVerifyRequest;

// HelloVerifyRequest decoding: a decoded message must round-trip.
fuzz_target!(|data: &[u8]| {
    if let Ok(message) = HelloVerifyRequest::decode(data) {
        if let Ok(encoded) = message.encode() {
            let reparsed = HelloVerifyRequest::decode(&encoded)
                .expect("re-encoded HelloVerifyRequest must decode");
            assert_eq!(message, reparsed);
        }
    }
});
