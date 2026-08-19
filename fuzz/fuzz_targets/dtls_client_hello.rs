#![no_main]

use libfuzzer_sys::fuzz_target;
use meshcop_dtls::ClientHello;

// ClientHello decoding: a decoded hello must round-trip through encode/decode.
fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = ClientHello::decode(data) {
        if let Ok(encoded) = hello.encode() {
            let reparsed =
                ClientHello::decode(&encoded).expect("re-encoded ClientHello must decode");
            assert_eq!(hello, reparsed);
        }
    }
});
