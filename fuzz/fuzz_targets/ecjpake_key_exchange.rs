#![no_main]

use libfuzzer_sys::fuzz_target;
use meshcop_dtls::ecjpake::{RoundTwo, THREAD_CLIENT_ID, THREAD_SERVER_ID};

// EC J-PAKE round-two key-exchange decoding. The server form carries secp256r1
// ECParameters (expect_curve_params = true); the client form does not. Both must
// reject malformed input and invalid curve points without panicking.
fuzz_target!(|data: &[u8]| {
    let _ = RoundTwo::decode_tls_key_exchange(data, THREAD_SERVER_ID, true);
    let _ = RoundTwo::decode_tls_key_exchange(data, THREAD_CLIENT_ID, false);
});
