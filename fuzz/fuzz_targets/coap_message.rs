#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh50::meshcop::{
    parse_notification, parse_petition_response, parse_state, parse_state_response, CoapMessage,
};

// MeshCoP CoAP decoding plus the higher-level response/notification parsers that
// run on decoded messages. None may panic on attacker-controlled bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(message) = CoapMessage::decode(data) {
        if let Ok(encoded) = message.encode() {
            let reparsed = CoapMessage::decode(&encoded).expect("re-encoded CoAP must decode");
            assert_eq!(message, reparsed);
        }

        let _ = parse_state(&message.payload);
        let _ = parse_state_response(&message, false);
        let _ = parse_petition_response(&message);
        let _ = parse_notification(&message);
    }
});
