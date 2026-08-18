#![no_main]

use libfuzzer_sys::fuzz_target;
use meshcop_dtls::ServerHello;

// ServerHello decoding: a decoded hello must round-trip through encode/decode.
fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = ServerHello::decode(data) {
        if let Ok(encoded) = hello.encode() {
            let reparsed =
                ServerHello::decode(&encoded).expect("re-encoded ServerHello must decode");
            assert_eq!(hello, reparsed);
        }
    }
});
