#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh50::meshcop::{parse_udp_rx, CoapMessage};

// UDP_RX.ntf decapsulation: outer CoAP decode, IPv6 Address and UDP
// Encapsulation TLV extraction, and decode of the proxied inner datagram.
// Must never panic on attacker-controlled bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(message) = CoapMessage::decode(data) {
        if let Ok(Some(udp_rx)) = parse_udp_rx(&message) {
            let _ = CoapMessage::decode(&udp_rx.payload);
        }
    }
});
